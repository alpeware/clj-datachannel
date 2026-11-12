(ns datachannel.dtls
  "Cross-platform DTLS 1.2 engine abstraction (`IDtlsEngine`), JVM `SSLEngine` implementation,
   and pure Node.js (`node:crypto`) DTLS 1.2 record + handshake implementation."
  (:require [clojure.string :as str]
            [datachannel.buffer :as b])
  #?(:clj
     (:import [java.io ByteArrayOutputStream]
              [java.nio ByteBuffer]
              [java.security KeyStore]
              [java.security.cert X509Certificate]
              [java.util ArrayList Date]
              [javax.net.ssl KeyManagerFactory SSLContext SSLEngine SSLEngineResult$HandshakeStatus SSLEngineResult$Status TrustManagerFactory X509TrustManager]
              [sun.security.tools.keytool CertAndKeyGen]
              [sun.security.x509 X500Name])))

#?(:cljs
   (def ^:private node-crypto
     (js/require "node:crypto")))

(def DEFAULT-PACKET-SIZE
  "The default maximum expected packet size for the SSLEngine configuration."
  16384)

(def buffer-size
  "Allocation size for ByteBuffers routing unencrypted chunks into the encryption `SSLEngine` wrapper."
  65536)

;; =============================================================================
;; 1. Cross-Platform `IDtlsEngine` Protocol
;; =============================================================================

(defprotocol IDtlsEngine
  "Pure-friendly boundary protocol decoupling `datachannel.core` and `datachannel.handlers`
   from `javax.net.ssl.SSLEngine`."
  (begin-handshake! [engine]
    "Initiates the DTLS handshake on the engine.")
  (handshake-finished? [engine]
    "Returns true if the DTLS handshake is complete (`FINISHED` or `NOT_HANDSHAKING`).")
  (handshake-step [engine in-bytes]
    "Processes incoming handshake/application bytes (may be empty for flight timeout).
     Returns `{:status <status> :finished? <bool> :packets [<byte-array> ...] :app-data <byte-array>}`.")
  (wrap-app-data [engine plain-bytes]
    "Encrypts application payload bytes after handshake completion.
     Returns `{:status <status> :bytes <byte-array>}`.")
  (unwrap-packet [engine net-bytes]
    "Decrypts an incoming DTLS application data packet.
     Returns `{:status <status> :bytes <byte-array>}`.")
  (peer-fingerprint [engine]
    "Returns the peer certificate's uppercase colon-separated SHA-256 fingerprint string, or nil.")
  (handle-timeout [engine now-ms]
    "Handles flight timeout or timer tick for DTLS engine."))

(defn verify-peer-fingerprint
  "Verifies that the primary peer certificate extracted from `engine` matches `expected-fingerprint`."
  [engine expected-fingerprint]
  (try
    (let [actual (when engine (peer-fingerprint engine))]
      (boolean
       (and (string? actual)
            (string? expected-fingerprint)
            (= (str/lower-case (str/trim actual))
               (str/lower-case (str/trim expected-fingerprint))))))
    (catch #?(:clj Exception :cljs :default) _
      false)))

(defn format-sha256-fingerprint
  "Formats raw DER certificate bytes into uppercase colon-separated SHA-256 hex string."
  [der-bytes]
  (let [digest (b/sha256-bytes der-bytes)
        len (b/blength digest)]
    (loop [i 0
           parts (transient [])]
      (if (= i len)
        (str/join ":" (persistent! parts))
        (let [v (b/bget-u8 digest i)
              hex (str/upper-case #?(:clj (Integer/toHexString v) :cljs (.toString v 16)))]
          (recur (inc i)
                 (conj! parts (if (< (count hex) 2) (str "0" hex) hex))))))))

;; =============================================================================
;; 1b. Pure Persistent `SimulatedDtlsEngine` (Cross-Platform)
;; =============================================================================

(def ^:const SIM-DTLS-VERSION "DTLS 1.2 protocol version (0xFEFD)." 0xFEFD)
(def ^:const SIM-CONTENT-TYPE-CHANGE-CIPHER-SPEC "DTLS ChangeCipherSpec content type (20)." 20)
(def ^:const SIM-CONTENT-TYPE-ALERT "DTLS Alert content type (21)." 21)
(def ^:const SIM-CONTENT-TYPE-HANDSHAKE "DTLS Handshake content type (22)." 22)
(def ^:const SIM-CONTENT-TYPE-APP-DATA "DTLS Application Data content type (23)." 23)

(def ^:const SIM-HS-CLIENT-HELLO "DTLS Handshake ClientHello message type (1)." 1)
(def ^:const SIM-HS-SERVER-HELLO "DTLS Handshake ServerHello message type (2)." 2)
(def ^:const SIM-HS-HELLO-VERIFY-REQUEST "DTLS Handshake HelloVerifyRequest message type (3)." 3)
(def ^:const SIM-HS-CERTIFICATE "DTLS Handshake Certificate message type (11)." 11)
(def ^:const SIM-HS-FINISHED "DTLS Handshake Finished message type (20)." 20)

(defn- sim-make-record
  [content-type epoch seq-num fragment]
  (let [flen (b/blength fragment)
        buf (b/allocate-buffer (+ 13 flen))]
    (b/buf-put-u8! buf (long content-type))
    (b/buf-put-u16! buf SIM-DTLS-VERSION)
    (b/buf-put-u16! buf (bit-and (long epoch) 0xFFFF))
    (b/buf-put-u16! buf (bit-and (unsigned-bit-shift-right (long seq-num) 32) 0xFFFF))
    (b/buf-put-u32! buf (bit-and (long seq-num) 0xFFFFFFFF))
    (b/buf-put-u16! buf (bit-and flen 0xFFFF))
    (b/buf-put-bytes! buf fragment)
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn- sim-make-hs-msg
  [msg-type msg-seq body]
  (let [blen (b/blength body)
        buf (b/allocate-buffer (+ 12 blen))]
    (b/buf-put-u8! buf (long msg-type))
    (b/buf-put-u8! buf (bit-and (unsigned-bit-shift-right blen 16) 0xFF))
    (b/buf-put-u16! buf (bit-and blen 0xFFFF))
    (b/buf-put-u16! buf (bit-and (long msg-seq) 0xFFFF))
    (b/buf-put-u8! buf 0)
    (b/buf-put-u16! buf 0)
    (b/buf-put-u8! buf (bit-and (unsigned-bit-shift-right blen 16) 0xFF))
    (b/buf-put-u16! buf (bit-and blen 0xFFFF))
    (b/buf-put-bytes! buf body)
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn- make-client-hello-body
  [client-random cookie fingerprint]
  (let [cookie-len (b/blength cookie)
        fp-bytes (b/utf8->bytes (or fingerprint ""))
        fp-len (b/blength fp-bytes)
        exts-len (+ 4 fp-len)
        body-len (+ 2 32 1 (inc cookie-len) 4 2 2 exts-len)
        buf (b/allocate-buffer body-len)]
    (b/buf-put-u16! buf SIM-DTLS-VERSION)
    (b/buf-put-bytes! buf client-random)
    (b/buf-put-u8! buf 0)
    (b/buf-put-u8! buf cookie-len)
    (when (pos? cookie-len)
      (b/buf-put-bytes! buf cookie))
    (b/buf-put-u16! buf 2)
    (b/buf-put-u16! buf 0xC02B)
    (b/buf-put-u8! buf 1)
    (b/buf-put-u8! buf 0)
    (b/buf-put-u16! buf exts-len)
    (b/buf-put-u16! buf 0xFF01)
    (b/buf-put-u16! buf fp-len)
    (b/buf-put-bytes! buf fp-bytes)
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn- make-hello-verify-body
  [cookie]
  (let [cookie-len (b/blength cookie)
        buf (b/allocate-buffer (+ 3 cookie-len))]
    (b/buf-put-u16! buf SIM-DTLS-VERSION)
    (b/buf-put-u8! buf cookie-len)
    (when (pos? cookie-len)
      (b/buf-put-bytes! buf cookie))
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn- make-server-hello-body
  [server-random]
  (let [buf (b/allocate-buffer 38)]
    (b/buf-put-u16! buf SIM-DTLS-VERSION)
    (b/buf-put-bytes! buf server-random)
    (b/buf-put-u8! buf 0)
    (b/buf-put-u16! buf 0xC02B)
    (b/buf-put-u8! buf 0)
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn- make-certificate-body
  [fingerprint]
  (let [fp-bytes (b/utf8->bytes (or fingerprint ""))
        clen (b/blength fp-bytes)
        total-len (+ clen 3)
        buf (b/allocate-buffer (+ 6 clen))]
    (b/buf-put-u8! buf (bit-and (unsigned-bit-shift-right total-len 16) 0xFF))
    (b/buf-put-u16! buf (bit-and total-len 0xFFFF))
    (b/buf-put-u8! buf (bit-and (unsigned-bit-shift-right clen 16) 0xFF))
    (b/buf-put-u16! buf (bit-and clen 0xFFFF))
    (b/buf-put-bytes! buf fp-bytes)
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn- make-finished-body
  [verify-data]
  (b/bslice verify-data 0 (min 16 (b/blength verify-data))))

(defn- parse-dtls-record
  [bs]
  (when (and bs (>= (b/blength bs) 13))
    (let [ctype (b/bget-u8 bs 0)
          ver (bit-or (bit-shift-left (b/bget-u8 bs 1) 8) (b/bget-u8 bs 2))
          epoch (bit-or (bit-shift-left (b/bget-u8 bs 3) 8) (b/bget-u8 bs 4))
          seq-hi (bit-or (bit-shift-left (b/bget-u8 bs 5) 8) (b/bget-u8 bs 6))
          seq-lo (bit-or (bit-shift-left (b/bget-u8 bs 7) 24)
                         (bit-shift-left (b/bget-u8 bs 8) 16)
                         (bit-shift-left (b/bget-u8 bs 9) 8)
                         (b/bget-u8 bs 10))
          seq-num (+ (* (long seq-hi) 4294967296) (bit-and (long seq-lo) 0xFFFFFFFF))
          flen (bit-or (bit-shift-left (b/bget-u8 bs 11) 8) (b/bget-u8 bs 12))
          frag (when (>= (b/blength bs) (+ 13 flen))
                 (b/bslice bs 13 (+ 13 flen)))]
      {:content-type ctype
       :version ver
       :epoch epoch
       :seq-num seq-num
       :length flen
       :fragment frag})))

(defn- parse-all-hs-msgs
  [frag]
  (when (and frag (>= (b/blength frag) 12))
    (let [total (b/blength frag)]
      (loop [offset 0
             acc []]
        (if (>= (+ offset 12) total)
          acc
          (let [mtype (b/bget-u8 frag offset)
                mlen (bit-or (bit-shift-left (b/bget-u8 frag (+ offset 1)) 16)
                             (bit-shift-left (b/bget-u8 frag (+ offset 2)) 8)
                             (b/bget-u8 frag (+ offset 3)))
                mseq (bit-or (bit-shift-left (b/bget-u8 frag (+ offset 4)) 8)
                             (b/bget-u8 frag (+ offset 5)))
                body (when (<= (+ offset 12 mlen) total)
                       (b/bslice frag (+ offset 12) (+ offset 12 mlen)))]
            (if body
              (recur (+ offset 12 mlen) (conj acc {:msg-type mtype :length mlen :msg-seq mseq :body body}))
              acc)))))))

(defn- parse-client-hello-body
  [body]
  (let [blen (b/blength body)]
    (if (< blen 35)
      {:cookie b/empty-bytes :client-fp nil :client-random nil}
      (let [client-random (b/bslice body 2 34)
            sid-len (b/bget-u8 body 34)
            cookie-offset (+ 35 sid-len)]
        (if (>= cookie-offset blen)
          {:cookie b/empty-bytes :client-fp nil :client-random client-random}
          (let [cookie-len (b/bget-u8 body cookie-offset)
                cookie (if (pos? cookie-len)
                         (b/bslice body (inc cookie-offset) (+ (inc cookie-offset) cookie-len))
                         b/empty-bytes)
                after-cookie (+ (inc cookie-offset) cookie-len)
                fp (try
                     (when (< (+ after-cookie 4) blen)
                       (let [cs-len (bit-or (bit-shift-left (b/bget-u8 body after-cookie) 8)
                                            (b/bget-u8 body (inc after-cookie)))
                             after-cs (+ after-cookie 2 cs-len)
                             comp-len (b/bget-u8 body after-cs)
                             after-comp (+ after-cs 1 comp-len)
                             exts-len (bit-or (bit-shift-left (b/bget-u8 body after-comp) 8)
                                              (b/bget-u8 body (inc after-comp)))
                             exts-start (+ after-comp 2)
                             exts-end (+ exts-start exts-len)]
                         (loop [cur exts-start]
                           (when (< (+ cur 4) exts-end)
                             (let [etype (bit-or (bit-shift-left (b/bget-u8 body cur) 8)
                                                 (b/bget-u8 body (inc cur)))
                                   elen (bit-or (bit-shift-left (b/bget-u8 body (+ cur 2)) 8)
                                                (b/bget-u8 body (+ cur 3)))
                                   edata (b/bslice body (+ cur 4) (+ cur 4 elen))]
                               (if (= etype 0xFF01)
                                 (b/bytes->utf8 edata)
                                 (recur (+ cur 4 elen))))))))
                     (catch #?(:clj Exception :cljs :default) _ nil))]
            {:cookie cookie :client-fp fp :client-random client-random}))))))

(defn- parse-hello-verify-body
  [body]
  (let [blen (b/blength body)]
    (if (< blen 3)
      b/empty-bytes
      (let [cookie-len (b/bget-u8 body 2)]
        (if (and (pos? cookie-len) (<= (+ 3 cookie-len) blen))
          (b/bslice body 3 (+ 3 cookie-len))
          b/empty-bytes)))))

(defn- parse-cert-body
  [body]
  (try
    (let [blen (b/blength body)]
      (when (>= blen 6)
        (let [clen (bit-or (bit-shift-left (b/bget-u8 body 3) 16)
                           (bit-shift-left (b/bget-u8 body 4) 8)
                           (b/bget-u8 body 5))
              cert1 (b/bslice body 6 (+ 6 clen))]
          (b/bytes->utf8 cert1))))
    (catch #?(:clj Exception :cljs :default) _ nil)))

(declare map->SimulatedDtlsEngine)

(defrecord ^{:doc "Pure Sans-IO immutable record implementing IDtlsEngine for deterministic simulation."}
 SimulatedDtlsEngine [role
                      phase
                      local-fingerprint
                      remote-fingerprint
                      peer-fingerprint
                      cookie-secret
                      client-random
                      server-random
                      epoch
                      tx-seq
                      rx-seq
                      rx-window
                      finished?
                      last-flight
                      symmetric-key]
  IDtlsEngine
  (begin-handshake! [this]
    (if (:finished? this)
      {:status :ok :finished? true :packets [] :engine this}
      (if (= (:role this) :client)
        (let [client-random (or (:client-random this) (b/random-bytes 32))
              ch-body (make-client-hello-body client-random b/empty-bytes (:local-fingerprint this))
              hs-msg (sim-make-hs-msg SIM-HS-CLIENT-HELLO 0 ch-body)
              record (sim-make-record SIM-CONTENT-TYPE-HANDSHAKE 0 0 hs-msg)
              upd (assoc this
                         :phase :wait-hello-verify
                         :last-flight [record]
                         :tx-seq 1)]
          {:status :handshaking
           :finished? false
           :packets [record]
           :engine upd})
        {:status :handshaking
         :finished? false
         :packets []
         :engine (assoc this :phase :wait-client-hello)})))

  (handshake-finished? [this]
    (boolean (:finished? this)))

  (peer-fingerprint [this]
    (:peer-fingerprint this))

  (handle-timeout [this _now-ms]
    (handshake-step this b/empty-bytes))

  (handshake-step [this in-bytes]
    (cond
      ;; Retransmission / tick
      (or (nil? in-bytes) (zero? (b/blength in-bytes)))
      (if (:finished? this)
        {:status :ok :finished? true :packets [] :app-data nil :engine this}
        {:status :handshaking
         :finished? false
         :packets (vec (:last-flight this))
         :app-data nil
         :engine this})

      ;; Inbound packet
      :else
      (let [rec (parse-dtls-record in-bytes)]
        (if-not rec
          {:status :error :finished? (:finished? this) :packets [] :app-data nil :engine this}
          (let [hs-msgs (parse-all-hs-msgs (:fragment rec))]
            (if (empty? hs-msgs)
              {:status :error :finished? (:finished? this) :packets [] :app-data nil :engine this}
              (loop [[hs & more] hs-msgs
                     cur-engine this
                     acc-packets []
                     fin? (:finished? cur-engine)]
                (if-not hs
                  {:status (if fin? :ok :handshaking)
                   :finished? fin?
                   :packets acc-packets
                   :app-data nil
                   :engine cur-engine}
                  (case (:msg-type hs)
                    ;; 1: ClientHello (Server receives)
                    1
                    (let [{:keys [cookie client-fp client-random]} (parse-client-hello-body (:body hs))
                          client-fp-bytes (b/utf8->bytes (or client-fp ""))
                          expected-cookie (b/hmac-sha256 (:cookie-secret cur-engine)
                                                         (b/bconcat [client-random client-fp-bytes]))]
                      (if (and (pos? (b/blength cookie)) (b/bytes= cookie expected-cookie))
                        ;; Flight 3 -> ServerHello + Certificate + Finished (coalesced in 1 record)
                        (let [server-random (or (:server-random cur-engine) (b/random-bytes 32))
                              sh-body (make-server-hello-body server-random)
                              sh-msg (sim-make-hs-msg SIM-HS-SERVER-HELLO 1 sh-body)
                              cert-body (make-certificate-body (:local-fingerprint cur-engine))
                              cert-msg (sim-make-hs-msg SIM-HS-CERTIFICATE 2 cert-body)
                              server-fp (or (:local-fingerprint cur-engine) "")
                              sym-key (b/hmac-sha256 (b/utf8->bytes "simulated-dtls-key")
                                                     (b/utf8->bytes (str (or client-fp "") ":" server-fp)))
                              fin-body (make-finished-body (b/hmac-sha256 sym-key (b/utf8->bytes "server-finished")))
                              fin-msg (sim-make-hs-msg SIM-HS-FINISHED 3 fin-body)
                              tx-seq (:tx-seq cur-engine 0)
                              flight-fragment (b/bconcat [sh-msg cert-msg fin-msg])
                              server-rec (sim-make-record SIM-CONTENT-TYPE-HANDSHAKE 0 tx-seq flight-fragment)
                              upd (assoc cur-engine
                                         :phase :wait-client-finished
                                         :peer-fingerprint client-fp
                                         :symmetric-key sym-key
                                         :last-flight [server-rec]
                                         :tx-seq (inc tx-seq))]
                          (recur more upd (conj acc-packets server-rec) false))
                        ;; Flight 1 (or forged/corrupted cookie on Flight 3) -> HelloVerifyRequest
                        (let [hvr-body (make-hello-verify-body expected-cookie)
                              hvr-msg (sim-make-hs-msg SIM-HS-HELLO-VERIFY-REQUEST 0 hvr-body)
                              tx-seq (:tx-seq cur-engine 0)
                              hvr-rec (sim-make-record SIM-CONTENT-TYPE-HANDSHAKE 0 tx-seq hvr-msg)
                              upd (assoc cur-engine
                                         :phase :wait-client-hello-cookie
                                         :last-flight [hvr-rec]
                                         :tx-seq (inc tx-seq))]
                          (recur more upd (conj acc-packets hvr-rec) false))))

                    ;; 3: HelloVerifyRequest (Client receives)
                    3
                    (let [cookie (parse-hello-verify-body (:body hs))
                          client-random (or (:client-random cur-engine) (b/random-bytes 32))
                          ch-body (make-client-hello-body client-random cookie (:local-fingerprint cur-engine))
                          ch-msg (sim-make-hs-msg SIM-HS-CLIENT-HELLO 1 ch-body)
                          tx-seq (:tx-seq cur-engine 0)
                          ch-rec (sim-make-record SIM-CONTENT-TYPE-HANDSHAKE 0 tx-seq ch-msg)
                          upd (assoc cur-engine
                                     :phase :wait-server-flight
                                     :last-flight [ch-rec]
                                     :tx-seq (inc tx-seq))]
                      (recur more upd (conj acc-packets ch-rec) false))

                    ;; 2: ServerHello (Client receives)
                    2
                    (recur more cur-engine acc-packets fin?)

                    ;; 11: Certificate (Client receives)
                    11
                    (let [cert-fp (parse-cert-body (:body hs))
                          upd (assoc cur-engine :peer-fingerprint cert-fp)]
                      (recur more upd acc-packets fin?))

                    ;; 20: Finished
                    20
                    (if (= (:role cur-engine) :client)
                      ;; Client receives Finished -> verifies ServerFinished verify_data
                      (let [client-fp (or (:local-fingerprint cur-engine) "")
                            server-fp (or (:peer-fingerprint cur-engine) (:remote-fingerprint cur-engine) "")
                            sym-key (b/hmac-sha256 (b/utf8->bytes "simulated-dtls-key")
                                                   (b/utf8->bytes (str client-fp ":" server-fp)))
                            expected-server-fin-body (make-finished-body (b/hmac-sha256 sym-key (b/utf8->bytes "server-finished")))]
                        (if-not (b/bytes= (:body hs) expected-server-fin-body)
                          {:status :handshake-failed :finished? false :packets [] :app-data nil :engine (assoc cur-engine :phase :failed)}
                          (let [client-fin-body (make-finished-body (b/hmac-sha256 sym-key (b/utf8->bytes "client-finished")))
                                fin-msg (sim-make-hs-msg SIM-HS-FINISHED 4 client-fin-body)
                                tx-seq (:tx-seq cur-engine 0)
                                fin-rec (sim-make-record SIM-CONTENT-TYPE-HANDSHAKE 0 tx-seq fin-msg)
                                upd (assoc cur-engine
                                           :phase :established
                                           :peer-fingerprint server-fp
                                           :symmetric-key sym-key
                                           :epoch 1
                                           :finished? true
                                           :last-flight [fin-rec]
                                           :tx-seq (inc tx-seq))]
                            (recur more upd (conj acc-packets fin-rec) true))))
                      ;; Server receives ClientFinished -> verifies ClientFinished verify_data
                      (let [client-fp (or (:peer-fingerprint cur-engine) (:remote-fingerprint cur-engine) "")
                            server-fp (or (:local-fingerprint cur-engine) "")
                            sym-key (or (:symmetric-key cur-engine)
                                        (b/hmac-sha256 (b/utf8->bytes "simulated-dtls-key")
                                                       (b/utf8->bytes (str client-fp ":" server-fp))))
                            expected-client-fin-body (make-finished-body (b/hmac-sha256 sym-key (b/utf8->bytes "client-finished")))]
                        (if-not (b/bytes= (:body hs) expected-client-fin-body)
                          {:status :handshake-failed :finished? false :packets [] :app-data nil :engine (assoc cur-engine :phase :failed)}
                          (let [upd (assoc cur-engine
                                           :phase :established
                                           :epoch 1
                                           :finished? true)]
                            (recur more upd acc-packets true)))))

                    (recur more cur-engine acc-packets fin?))))))))))

  (wrap-app-data [this plain-bytes]
    (let [seq-num (:tx-seq this 0)
          epoch (:epoch this 1)
          key (:symmetric-key this (b/alloc-bytes 32))
          flen (b/blength plain-bytes)
          explicit-nonce (let [buf (b/allocate-buffer 8)]
                           (b/buf-put-u16! buf (bit-and epoch 0xFFFF))
                           (b/buf-put-u16! buf (bit-and (unsigned-bit-shift-right seq-num 32) 0xFFFF))
                           (b/buf-put-u32! buf (bit-and seq-num 0xFFFFFFFF))
                           (b/buf-flip! buf)
                           (b/buf->bytes buf))
          aad (let [buf (b/allocate-buffer 13)]
                (b/buf-put-u16! buf (bit-and epoch 0xFFFF))
                (b/buf-put-u16! buf (bit-and (unsigned-bit-shift-right seq-num 32) 0xFFFF))
                (b/buf-put-u32! buf (bit-and seq-num 0xFFFFFFFF))
                (b/buf-put-u8! buf SIM-CONTENT-TYPE-APP-DATA)
                (b/buf-put-u16! buf SIM-DTLS-VERSION)
                (b/buf-put-u16! buf (bit-and flen 0xFFFF))
                (b/buf-flip! buf)
                (b/buf->bytes buf))
          full-tag (b/hmac-sha256 key (b/bconcat [aad explicit-nonce plain-bytes]))
          tag (b/bslice full-tag 0 16)
          body (b/bconcat [explicit-nonce plain-bytes tag])
          record (sim-make-record SIM-CONTENT-TYPE-APP-DATA epoch seq-num body)]
      {:status :ok
       :bytes record
       :engine (assoc this :tx-seq (inc seq-num))}))

  (unwrap-packet [this net-bytes]
    (let [total-len (b/blength net-bytes)]
      (if (< total-len (+ 13 8 16))
        {:status :truncated :bytes nil :engine this}
        (let [ctype (b/bget-u8 net-bytes 0)
              ver (bit-or (bit-shift-left (b/bget-u8 net-bytes 1) 8) (b/bget-u8 net-bytes 2))
              epoch (bit-or (bit-shift-left (b/bget-u8 net-bytes 3) 8) (b/bget-u8 net-bytes 4))
              seq-hi (bit-or (bit-shift-left (b/bget-u8 net-bytes 5) 8) (b/bget-u8 net-bytes 6))
              seq-lo (bit-or (bit-shift-left (b/bget-u8 net-bytes 7) 24)
                             (bit-shift-left (b/bget-u8 net-bytes 8) 16)
                             (bit-shift-left (b/bget-u8 net-bytes 9) 8)
                             (b/bget-u8 net-bytes 10))
              seq-num (+ (* (long seq-hi) 4294967296) (bit-and (long seq-lo) 0xFFFFFFFF))
              flen (bit-or (bit-shift-left (b/bget-u8 net-bytes 11) 8) (b/bget-u8 net-bytes 12))]
          (cond
            (not= ctype SIM-CONTENT-TYPE-APP-DATA)
            {:status :invalid-content-type :bytes nil :engine this}

            (not= ver SIM-DTLS-VERSION)
            {:status :invalid-version :bytes nil :engine this}

            (not= epoch (:epoch this 1))
            {:status :invalid-epoch :bytes nil :engine this}

            (not= flen (- total-len 13))
            {:status :length-mismatch :bytes nil :engine this}

            :else
            (let [body (b/bslice net-bytes 13 total-len)
                  body-len (b/blength body)
                  explicit-nonce (b/bslice body 0 8)
                  plain-len (- body-len 24)
                  plain (b/bslice body 8 (+ 8 plain-len))
                  tag (b/bslice body (+ 8 plain-len) body-len)
                  key (:symmetric-key this (b/alloc-bytes 32))
                  aad (let [buf (b/allocate-buffer 13)]
                        (b/buf-put-u16! buf (bit-and epoch 0xFFFF))
                        (b/buf-put-u16! buf (bit-and (unsigned-bit-shift-right seq-num 32) 0xFFFF))
                        (b/buf-put-u32! buf (bit-and seq-num 0xFFFFFFFF))
                        (b/buf-put-u8! buf SIM-CONTENT-TYPE-APP-DATA)
                        (b/buf-put-u16! buf SIM-DTLS-VERSION)
                        (b/buf-put-u16! buf (bit-and plain-len 0xFFFF))
                        (b/buf-flip! buf)
                        (b/buf->bytes buf))
                  expected-full-tag (b/hmac-sha256 key (b/bconcat [aad explicit-nonce plain]))
                  expected-tag (b/bslice expected-full-tag 0 16)]
              (if-not (b/bytes= tag expected-tag)
                {:status :auth-tag-mismatch :bytes nil :engine this}
                (let [rx-win (get this :rx-window #{})]
                  (if (contains? rx-win seq-num)
                    {:status :replay-dropped :bytes nil :engine this}
                    {:status :ok
                     :bytes plain
                     :engine (-> this
                                 (assoc :rx-seq seq-num)
                                 (update :rx-window (fn [w] (conj (or w #{}) seq-num))))}))))))))))

(defn generate-simulated-cert
  "Generates a deterministic simulated self-signed certificate data map with SHA-256 fingerprint."
  ([]
   (generate-simulated-cert nil))
  ([rng]
   (let [raw (if rng (b/random-bytes 32 rng) (b/random-bytes 32))
         fp (format-sha256-fingerprint raw)]
     {:cert (b/alloc-bytes 64)
      :fingerprint fp
      :key (b/alloc-bytes 32)})))

(defn create-simulated-engine
  "Creates a pure persistent SimulatedDtlsEngine."
  [opts]
  (let [client-mode? (boolean (or (:client? opts) (:client-mode? opts) (= (:role opts) :client)))
        rng (:rng opts)
        cert-data (or (:cert-data opts) (generate-simulated-cert rng))
        fp (:fingerprint cert-data)
        cookie-secret (if rng (b/random-bytes 32 rng) (b/random-bytes 32))
        client-random (if rng (b/random-bytes 32 rng) (b/random-bytes 32))
        server-random (if rng (b/random-bytes 32 rng) (b/random-bytes 32))
        role (if client-mode? :client :server)
        base (map->SimulatedDtlsEngine
              {:role role
               :phase (if client-mode? :wait-hello-verify :wait-client-hello)
               :local-fingerprint fp
               :remote-fingerprint (:remote-fingerprint opts)
               :peer-fingerprint nil
               :cookie-secret cookie-secret
               :client-random client-random
               :server-random server-random
               :epoch 0
               :tx-seq 0
               :rx-seq 0
               :rx-window #{}
               :finished? false
               :last-flight []
               :symmetric-key nil})]
    (if client-mode?
      (let [ch-body (make-client-hello-body client-random b/empty-bytes fp)
            ch-msg (sim-make-hs-msg SIM-HS-CLIENT-HELLO 0 ch-body)
            ch-rec (sim-make-record SIM-CONTENT-TYPE-HANDSHAKE 0 0 ch-msg)]
        (assoc base
               :last-flight [ch-rec]
               :tx-seq 1))
      base)))

;; =============================================================================
;; 2. Node.js (`node:crypto`) DTLS 1.2 Record & Handshake Engine (`:cljs`)
;; =============================================================================

#?(:cljs
   (defn- der-len-buf
     [n]
     (cond
       (< n 128) (js/Buffer.from #js [n])
       (< n 256) (js/Buffer.from #js [0x81 n])
       :else (js/Buffer.from #js [0x82 (bit-and (unsigned-bit-shift-right n 8) 0xFF) (bit-and n 0xFF)]))))

#?(:cljs
   (defn- der-tag-buf
     [tag body]
     (js/Buffer.concat #js [(js/Buffer.from #js [tag]) (der-len-buf (.-length body)) body])))

#?(:cljs
   (defn- coerce-cert-der-buf
     ^js [cert]
     (cond
       (nil? cert) nil
       (string? cert) (.-raw (new (.-X509Certificate node-crypto) cert))
       (instance? js/Uint8Array cert) (js/Buffer.from cert)
       (.-raw cert) (js/Buffer.from (.-raw cert))
       :else (js/Buffer.from cert))))

#?(:cljs
   (defn- coerce-private-key-obj
     ^js [k]
     (cond
       (nil? k) nil
       (string? k) (.createPrivateKey node-crypto k)
       (.-asymmetricKeyType k) k
       :else (.createPrivateKey node-crypto #js {:key (js/Buffer.from k) :format "der" :type "pkcs8"}))))

#?(:cljs
   (defn- prf-sha256-buf
     ^js [secret label seed length]
     (let [label-seed (js/Buffer.concat #js [(js/Buffer.from label "ascii") seed])
           chunks #js []]
       (loop [a label-seed
              total 0]
         (if (>= total length)
           (js/Buffer.concat chunks length)
           (let [next-a (-> (.createHmac node-crypto "sha256" secret) (.update a) (.digest))
                 out (-> (.createHmac node-crypto "sha256" secret)
                         (.update (js/Buffer.concat #js [next-a label-seed]))
                         (.digest))]
             (.push chunks out)
             (recur next-a (+ total (.-length out)))))))))

#?(:cljs
   (defn- sha256-transcript-buf
     ^js [bufs-vec]
     (let [h (.createHash node-crypto "sha256")]
       (doseq [b bufs-vec]
         (.update h b))
       (.digest h))))

#?(:cljs
   (defn- wrap-dtls-record
     ^js [content-type epoch seq-num fragment]
     (let [hdr (js/Buffer.alloc 13)]
       (.writeUInt8 hdr content-type 0)
       (.writeUInt8 hdr 0xFE 1)
       (.writeUInt8 hdr 0xFD 2)
       (.writeUInt16BE hdr epoch 3)
       (.writeUIntBE hdr seq-num 5 6)
       (.writeUInt16BE hdr (.-length fragment) 11)
       (js/Uint8Array. (js/Buffer.concat #js [hdr fragment])))))

#?(:cljs
   (defn- wrap-dtls-handshake
     ^js [msg-type msg-seq body]
     (let [hdr (js/Buffer.alloc 12)
           blen (.-length body)]
       (.writeUInt8 hdr msg-type 0)
       (.writeUIntBE hdr blen 1 3)
       (.writeUInt16BE hdr msg-seq 4)
       (.writeUIntBE hdr 0 6 3)
       (.writeUIntBE hdr blen 9 3)
       (js/Buffer.concat #js [hdr body]))))

#?(:cljs
   (defn- aead-encrypt-dtls-record
     ^js [write-key implicit-iv epoch seq-num content-type plaintext]
     (let [explicit-nonce (js/Buffer.alloc 8)
           _ (.writeUInt16BE explicit-nonce epoch 0)
           _ (.writeUIntBE explicit-nonce seq-num 2 6)
           nonce (js/Buffer.concat #js [implicit-iv explicit-nonce])
           aad (js/Buffer.alloc 13)
           _ (.writeUInt16BE aad epoch 0)
           _ (.writeUIntBE aad seq-num 2 6)
           _ (.writeUInt8 aad content-type 8)
           _ (.writeUInt8 aad 0xFE 9)
           _ (.writeUInt8 aad 0xFD 10)
           _ (.writeUInt16BE aad (.-length plaintext) 11)
           cipher (.createCipheriv node-crypto "aes-128-gcm" write-key nonce)
           _ (.setAAD cipher aad)
           enc (js/Buffer.concat #js [(.update cipher plaintext) (.final cipher)])
           tag (.getAuthTag cipher)]
       (wrap-dtls-record content-type epoch seq-num (js/Buffer.concat #js [explicit-nonce enc tag])))))

#?(:cljs
   (defn- aead-decrypt-dtls-record
     ^js [read-key implicit-iv hdr frag]
     (when (< (.-length frag) 24)
       (throw (ex-info "DTLS AEAD record too short" {:length (.-length frag)})))
     (let [content-type (.readUInt8 hdr 0)
           epoch (.readUInt16BE hdr 3)
           seq-num (.readUIntBE hdr 5 6)
           explicit-nonce (.subarray frag 0 8)
           tag (.subarray frag (- (.-length frag) 16))
           ciphertext (.subarray frag 8 (- (.-length frag) 16))
           nonce (js/Buffer.concat #js [implicit-iv explicit-nonce])
           aad (js/Buffer.alloc 13)
           _ (.writeUInt16BE aad epoch 0)
           _ (.writeUIntBE aad seq-num 2 6)
           _ (.writeUInt8 aad content-type 8)
           _ (.writeUInt8 aad (.readUInt8 hdr 1) 9)
           _ (.writeUInt8 aad (.readUInt8 hdr 2) 10)
           _ (.writeUInt16BE aad (.-length ciphertext) 11)
           decipher (.createDecipheriv node-crypto "aes-128-gcm" read-key nonce)]
       (.setAAD decipher aad)
       (.setAuthTag decipher tag)
       (js/Buffer.concat #js [(.update decipher ciphertext) (.final decipher)]))))

#?(:cljs
   (defn- verify-tls12-signature
     [hash-alg sig-alg signed-buf sig-buf pub-key]
     (let [digest-name (case hash-alg
                         4 "sha256"
                         5 "sha384"
                         6 "sha512"
                         "sha256")]
       (if (and (= hash-alg 8) (= sig-alg 4))
         (.verify node-crypto "sha256" signed-buf
                  #js {:key pub-key
                       :padding (.. node-crypto -constants -RSA_PKCS1_PSS_PADDING)
                       :saltLength 32}
                  sig-buf)
         (.verify node-crypto digest-name signed-buf pub-key sig-buf)))))

#?(:cljs
   (defn- sign-tls12-bytes
     ^js [priv-key data-buf]
     (let [ktype (.-asymmetricKeyType priv-key)
           alg-bytes (if (= ktype "rsa")
                       (js/Buffer.from #js [0x04 0x01])
                       (js/Buffer.from #js [0x04 0x03]))
           sig (.sign node-crypto "sha256" data-buf priv-key)
           len-buf (js/Buffer.alloc 2)]
       (.writeUInt16BE len-buf (.-length sig) 0)
       (js/Buffer.concat #js [alg-bytes len-buf sig]))))

#?(:cljs
   (defn- build-cert-hs-body
     ^js [cert-der]
     (let [hdr (js/Buffer.alloc 6)
           clen (.-length cert-der)]
       (.writeUIntBE hdr (+ clen 3) 0 3)
       (.writeUIntBE hdr clen 3 3)
       (js/Buffer.concat #js [hdr cert-der]))))

#?(:cljs
   (deftype NodeDtlsEngine [st-atom build-client-hello! reassemble-and-enqueue-hs! process-epoch1-record!]
     IDtlsEngine
     (begin-handshake! [_]
       (swap! st-atom assoc :started? true))
     (handshake-finished? [_]
       (boolean (:finished? @st-atom)))
     (peer-fingerprint [_]
       (:peer-fingerprint @st-atom))
     (handshake-step [_ in-bytes]
       (let [raw (when in-bytes (b/to-bytes in-bytes))
             buf (if (and raw (pos? (b/blength raw)))
                   (js/Buffer.from raw)
                   (js/Buffer.alloc 0))]
         (if (and (zero? (.-length buf)) (not (:finished? @st-atom)))
           (if (:client-mode? @st-atom)
             (let [lf (:last-flight @st-atom)
                   pkts (if (seq lf) lf [(build-client-hello!)])]
               {:status :need-unwrap
                :finished? false
                :packets pkts
                :app-data b/empty-bytes})
             {:status :need-unwrap
              :finished? false
              :packets (vec (:last-flight @st-atom))
              :app-data b/empty-bytes})
           (let [out-packets-atom (atom [])
                 app-chunks-atom (atom [])]
             (loop [r-off 0]
               (when (<= (+ r-off 13) (.-length buf))
                 (let [ct (.readUInt8 buf r-off)
                       r-ver (.readUInt16BE buf (+ r-off 1))
                       _ (when-not (or (= r-ver 0xFEFD) (= r-ver 0xFEFF))
                           (throw (ex-info "Unsupported peer DTLS record version"
                                           {:type :dtls-unsupported-version :version r-ver})))
                       ep (.readUInt16BE buf (+ r-off 3))
                       r-len (.readUInt16BE buf (+ r-off 11))
                       hdr (.subarray buf r-off (+ r-off 13))
                       frag (.subarray buf (+ r-off 13) (+ r-off 13 r-len))]
                   (cond
                     (and (zero? ep) (= ct 22))
                     (reassemble-and-enqueue-hs! frag out-packets-atom app-chunks-atom)

                     (= ep 1)
                     (process-epoch1-record! hdr frag out-packets-atom app-chunks-atom))
                   (recur (+ r-off 13 r-len)))))
             (let [fin? (boolean (:finished? @st-atom))
                   app-chunks @app-chunks-atom
                   app-bytes (if (seq app-chunks)
                               (js/Uint8Array. (js/Buffer.concat (into-array app-chunks)))
                               b/empty-bytes)]
               {:status (if fin? :finished :need-unwrap)
                :finished? fin?
                :packets @out-packets-atom
                :app-data app-bytes})))))
     (wrap-app-data [_ plain-bytes]
       (let [st @st-atom
             w-key (if (:client-mode? st) (:client-write-key st) (:server-write-key st))
             w-iv (if (:client-mode? st) (:client-write-iv st) (:server-write-iv st))
             seq-n (:epoch1-seq st)
             _ (swap! st-atom update :epoch1-seq inc)
             plain-buf (js/Buffer.from (b/to-bytes plain-bytes))]
         {:status :ok
          :bytes (aead-encrypt-dtls-record w-key w-iv 1 seq-n 23 plain-buf)}))
     (unwrap-packet [_ net-bytes]
       (try
         (let [st @st-atom
               r-key (if (:client-mode? st) (:server-write-key st) (:client-write-key st))
               r-iv (if (:client-mode? st) (:server-write-iv st) (:client-write-iv st))
               buf (js/Buffer.from (b/to-bytes net-bytes))
               chunks (transient [])]
           (loop [off 0]
             (when (<= (+ off 13) (.-length buf))
               (let [ct (.readUInt8 buf off)
                     r-ver (.readUInt16BE buf (+ off 1))
                     _ (when (not= r-ver 0xFEFD)
                         (throw (ex-info "Unsupported peer DTLS record version"
                                         {:type :dtls-unsupported-version :version r-ver})))
                     ep (.readUInt16BE buf (+ off 3))
                     r-len (.readUInt16BE buf (+ off 11))
                     hdr (.subarray buf off (+ off 13))
                     frag (.subarray buf (+ off 13) (+ off 13 r-len))]
                 (when (and (= ep 1) (= ct 23))
                   (conj! chunks (aead-decrypt-dtls-record r-key r-iv hdr frag)))
                 (recur (+ off 13 r-len)))))
           (let [cs (persistent! chunks)]
             {:status :ok
              :bytes (if (seq cs)
                       (js/Uint8Array. (js/Buffer.concat (into-array cs)))
                       b/empty-bytes)}))
         (catch :default _
           {:status nil :bytes nil})))
     (handle-timeout [this _now-ms]
       (handshake-step this b/empty-bytes))))

#?(:cljs
   (defn- create-node-dtls-engine
     [cert-der priv-key client-mode?]
     (let [st-atom (atom {:client-mode? (boolean client-mode?)
                          :cert-der cert-der
                          :priv-key priv-key
                          :epoch0-seq 0
                          :epoch1-seq 0
                          :msg-seq-out 0
                          :client-random (.randomBytes node-crypto 32)
                          :server-random (.randomBytes node-crypto 32)
                          :cookie-secret (.randomBytes node-crypto 32)
                          :cookie (js/Buffer.alloc 0)
                          :ecdh nil
                          :use-ems? false
                          :cert-requested? false
                          :peer-cert-der nil
                          :peer-pub-key nil
                          :peer-fingerprint nil
                          :peer-ecdh-pub nil
                          :master-secret nil
                          :client-write-key nil
                          :server-write-key nil
                          :client-write-iv nil
                          :server-write-iv nil
                          :transcript []
                          :frag-cache {}
                          :pending-hs {}
                          :expected-seq-in 0
                          :pending-epoch1 []
                          :last-flight []
                          :finished? false
                          :started? false})
           build-client-hello!
           (fn []
             (let [st @st-atom
                   cookie (:cookie st)
                   exts (js/Buffer.from
                         #js [0x00 0x0A 0x00 0x04 0x00 0x02 0x00 0x17
                              0x00 0x0B 0x00 0x02 0x01 0x00
                              0x00 0x0D 0x00 0x0E 0x00 0x0C
                              0x04 0x03 0x04 0x01 0x08 0x04 0x05 0x03 0x05 0x01 0x06 0x03
                              0x00 0x17 0x00 0x00
                              0xFF 0x01 0x00 0x01 0x00])
                   ext-len (js/Buffer.alloc 2)
                   _ (.writeUInt16BE ext-len (.-length exts) 0)
                   body (js/Buffer.concat
                         #js [(js/Buffer.from #js [0xFE 0xFD])
                              (:client-random st)
                              (js/Buffer.from #js [0x00])
                              (js/Buffer.from #js [(.-length cookie)])
                              cookie
                              (js/Buffer.from #js [0x00 0x04 0xC0 0x2B 0xC0 0x2F])
                              (js/Buffer.from #js [0x01 0x00])
                              ext-len
                              exts])
                   mseq (:msg-seq-out st)
                   rseq (:epoch0-seq st)
                   hs (wrap-dtls-handshake 1 mseq body)
                   rec (wrap-dtls-record 22 0 rseq hs)]
               (swap! st-atom
                      (fn [s]
                        (cond-> (-> s
                                    (assoc :msg-seq-out (inc mseq)
                                           :epoch0-seq (inc rseq)
                                           :last-flight [rec]))
                          (pos? (.-length cookie))
                          (assoc :transcript [hs]
                                 :expected-seq-in 1))))
               rec))
           derive-session-keys!
           (fn []
             (let [st @st-atom
                   seed (if (:use-ems? st)
                          (sha256-transcript-buf (:transcript st))
                          (js/Buffer.concat #js [(:client-random st) (:server-random st)]))
                   label (if (:use-ems? st) "extended master secret" "master secret")
                   pms (.computeSecret ^js (:ecdh st) (:peer-ecdh-pub st))
                   ms (prf-sha256-buf pms label seed 48)
                   kb (prf-sha256-buf ms "key expansion"
                                      (js/Buffer.concat #js [(:server-random st) (:client-random st)])
                                      40)]
               (swap! st-atom assoc
                      :master-secret ms
                      :client-write-key (.subarray kb 0 16)
                      :server-write-key (.subarray kb 16 32)
                      :client-write-iv (.subarray kb 32 36)
                      :server-write-iv (.subarray kb 36 40))))
           parse-peer-cert!
           (fn [^js body]
             (when (>= (.-length body) 6)
               (let [total-len (.readUIntBE body 0 3)]
                 (when (pos? total-len)
                   (let [cert-len (.readUIntBE body 3 3)
                         c-der (js/Buffer.from (.subarray body 6 (+ 6 cert-len)))
                         x509 (new (.-X509Certificate node-crypto) c-der)
                         fp (format-sha256-fingerprint (js/Uint8Array. c-der))]
                     (swap! st-atom assoc
                            :peer-cert-der c-der
                            :peer-pub-key (.-publicKey x509)
                            :peer-fingerprint fp))))))
           process-epoch1-record!
           (fn [hdr frag out-packets-atom app-chunks-atom]
             (let [st @st-atom
                   ct (.readUInt8 hdr 0)
                   read-key (if (:client-mode? st) (:server-write-key st) (:client-write-key st))
                   read-iv (if (:client-mode? st) (:server-write-iv st) (:client-write-iv st))]
               (if (nil? read-key)
                 (swap! st-atom update :pending-epoch1 conj [hdr frag])
                 (let [plain (aead-decrypt-dtls-record read-key read-iv hdr frag)]
                   (cond
                     (= ct 22)
                     (let [msg-type (.readUInt8 plain 0)
                           body (.subarray plain 12)]
                       (when (and (= msg-type 20) (not (:finished? @st-atom)))
                         (let [cur @st-atom
                               exp-label (if (:client-mode? cur) "server finished" "client finished")
                               expected-vd (prf-sha256-buf (:master-secret cur) exp-label
                                                           (sha256-transcript-buf (:transcript cur)) 12)]
                           (when-not (.equals body expected-vd)
                             (throw (ex-info "DTLS Finished verify_data mismatch" {:type :dtls-verify-failed})))
                           (swap! st-atom update :transcript conj plain)
                           (when-not (:client-mode? cur)
                             (let [s2 @st-atom
                                   ccs-rec (wrap-dtls-record 20 0 (:epoch0-seq s2) (js/Buffer.from #js [0x01]))
                                   srv-vd (prf-sha256-buf (:master-secret s2) "server finished"
                                                          (sha256-transcript-buf (:transcript s2)) 12)
                                   srv-fin-hs (wrap-dtls-handshake 20 (:msg-seq-out s2) srv-vd)
                                   srv-fin-rec (aead-encrypt-dtls-record (:server-write-key s2) (:server-write-iv s2)
                                                                         1 (:epoch1-seq s2) 22 srv-fin-hs)]
                               (swap! st-atom
                                      (fn [s]
                                        (-> s
                                            (update :transcript conj srv-fin-hs)
                                            (update :epoch0-seq inc)
                                            (update :epoch1-seq inc)
                                            (update :msg-seq-out inc)
                                            (assoc :last-flight [ccs-rec srv-fin-rec]))))
                               (swap! out-packets-atom into [ccs-rec srv-fin-rec])))
                           (swap! st-atom assoc :finished? true))))

                     (= ct 23)
                     (swap! app-chunks-atom conj plain))))))
           flush-pending-epoch1!
           (fn [out-packets-atom app-chunks-atom]
             (let [pend (:pending-epoch1 @st-atom)]
               (when (seq pend)
                 (swap! st-atom assoc :pending-epoch1 [])
                 (doseq [[hdr frag] pend]
                   (process-epoch1-record! hdr frag out-packets-atom app-chunks-atom)))))
           process-single-hs!
           (fn [{:keys [msg-type ^js body full-hs]} out-packets-atom app-chunks-atom]
             (let [st @st-atom]
               (if (:client-mode? st)
                 (case msg-type
                   3 ;; HelloVerifyRequest
                   (let [clen (.readUInt8 body 2)
                         cookie (js/Buffer.from (.subarray body 3 (+ 3 clen)))]
                     (swap! st-atom assoc :cookie cookie :pending-hs {})
                     (swap! out-packets-atom conj (build-client-hello!)))

                   2 ;; ServerHello
                   (let [sh-ver (.readUInt16BE body 0)
                         _ (when (not= sh-ver 0xFEFD)
                             (throw (ex-info "Unsupported peer DTLS ServerHello version"
                                             {:type :dtls-unsupported-version :version sh-ver})))
                         s-rand (js/Buffer.from (.subarray body 2 34))
                         sid-len (.readUInt8 body 34)
                         p0 (+ 35 sid-len 3)
                         ems? (loop [p (if (<= (+ p0 2) (.-length body)) (+ p0 2) (.-length body))
                                     end (if (<= (+ p0 2) (.-length body))
                                           (+ p0 2 (.readUInt16BE body p0))
                                           0)
                                     found? false]
                                (if (<= (+ p 4) end)
                                  (let [et (.readUInt16BE body p)
                                        el (.readUInt16BE body (+ p 2))]
                                    (recur (+ p 4 el) end (or found? (= et 0x0017))))
                                  found?))]
                     (swap! st-atom
                            (fn [s]
                              (-> s
                                  (update :transcript conj full-hs)
                                  (assoc :server-random s-rand :use-ems? ems?)))))

                   11 ;; Certificate
                   (do
                     (swap! st-atom update :transcript conj full-hs)
                     (parse-peer-cert! body))

                   12 ;; ServerKeyExchange
                   (let [_ (swap! st-atom update :transcript conj full-hs)
                         cur @st-atom
                         pub-len (.readUInt8 body 3)
                         srv-pub (js/Buffer.from (.subarray body 4 (+ 4 pub-len)))
                         params (.subarray body 0 (+ 4 pub-len))
                         hash-alg (.readUInt8 body (+ 4 pub-len))
                         sig-alg (.readUInt8 body (+ 5 pub-len))
                         sig-len (.readUInt16BE body (+ 6 pub-len))
                         sig-bytes (.subarray body (+ 8 pub-len) (+ 8 pub-len sig-len))
                         signed-data (js/Buffer.concat #js [(:client-random cur) (:server-random cur) params])]
                     (when-not (verify-tls12-signature hash-alg sig-alg signed-data sig-bytes (:peer-pub-key cur))
                       (throw (ex-info "DTLS ServerKeyExchange signature verification failed" {:type :dtls-sig-failed})))
                     (swap! st-atom assoc :peer-ecdh-pub srv-pub))

                   13 ;; CertificateRequest
                   (swap! st-atom
                          (fn [s]
                            (-> s
                                (update :transcript conj full-hs)
                                (assoc :cert-requested? true))))

                   14 ;; ServerHelloDone
                   (let [_ (swap! st-atom update :transcript conj full-hs)
                         ecdh (.createECDH node-crypto "prime256v1")
                         _ (.generateKeys ecdh)
                         cli-pub (.getPublicKey ecdh)
                         _ (swap! st-atom assoc :ecdh ecdh)
                         flight (transient [])]
                     (when (:cert-requested? @st-atom)
                       (let [s @st-atom
                             cert-hs (wrap-dtls-handshake 11 (:msg-seq-out s) (build-cert-hs-body (:cert-der s)))
                             cert-rec (wrap-dtls-record 22 0 (:epoch0-seq s) cert-hs)]
                         (swap! st-atom #(-> % (update :transcript conj cert-hs) (update :msg-seq-out inc) (update :epoch0-seq inc)))
                         (conj! flight cert-rec)))
                     (let [s @st-atom
                           cke-body (js/Buffer.concat #js [(js/Buffer.from #js [(.-length cli-pub)]) cli-pub])
                           cke-hs (wrap-dtls-handshake 16 (:msg-seq-out s) cke-body)
                           cke-rec (wrap-dtls-record 22 0 (:epoch0-seq s) cke-hs)]
                       (swap! st-atom #(-> % (update :transcript conj cke-hs) (update :msg-seq-out inc) (update :epoch0-seq inc)))
                       (conj! flight cke-rec))
                     (derive-session-keys!)
                     (when (:cert-requested? @st-atom)
                       (let [s @st-atom
                             cv-body (sign-tls12-bytes (:priv-key s) (js/Buffer.concat (into-array (:transcript s))))
                             cv-hs (wrap-dtls-handshake 15 (:msg-seq-out s) cv-body)
                             cv-rec (wrap-dtls-record 22 0 (:epoch0-seq s) cv-hs)]
                         (swap! st-atom #(-> % (update :transcript conj cv-hs) (update :msg-seq-out inc) (update :epoch0-seq inc)))
                         (conj! flight cv-rec)))
                     (let [s @st-atom
                           ccs-rec (wrap-dtls-record 20 0 (:epoch0-seq s) (js/Buffer.from #js [0x01]))
                           vd (prf-sha256-buf (:master-secret s) "client finished" (sha256-transcript-buf (:transcript s)) 12)
                           fin-hs (wrap-dtls-handshake 20 (:msg-seq-out s) vd)
                           fin-rec (aead-encrypt-dtls-record (:client-write-key s) (:client-write-iv s) 1 (:epoch1-seq s) 22 fin-hs)
                           fl-vec (persistent! (-> flight (conj! ccs-rec) (conj! fin-rec)))]
                       (swap! st-atom
                              (fn [cur]
                                (-> cur
                                    (update :transcript conj fin-hs)
                                    (update :epoch0-seq inc)
                                    (update :epoch1-seq inc)
                                    (update :msg-seq-out inc)
                                    (assoc :last-flight fl-vec))))
                       (swap! out-packets-atom into fl-vec)
                       (flush-pending-epoch1! out-packets-atom app-chunks-atom)))

                   4 ;; NewSessionTicket
                   (swap! st-atom update :transcript conj full-hs)

                   nil)
                 ;; Server mode
                 (case msg-type
                   1 ;; ClientHello
                   (let [ch-ver (.readUInt16BE body 0)
                         _ (when (not= ch-ver 0xFEFD)
                             (throw (ex-info "Unsupported peer DTLS ClientHello version"
                                             {:type :dtls-unsupported-version :version ch-ver})))
                         c-rand (js/Buffer.from (.subarray body 2 34))
                         sid-len (.readUInt8 body 34)
                         c-len (.readUInt8 body (+ 35 sid-len))
                         cookie (.subarray body (+ 36 sid-len) (+ 36 sid-len c-len))
                         exp-cookie (-> (.createHmac node-crypto "sha256" (:cookie-secret st))
                                        (.update c-rand)
                                        (.digest))]
                     (if (or (zero? c-len) (not (.equals cookie exp-cookie)))
                       (let [hvr-body (js/Buffer.concat #js [(js/Buffer.from #js [0xFE 0xFD (.-length exp-cookie)]) exp-cookie])
                             hvr-hs (wrap-dtls-handshake 3 0 hvr-body)
                             hvr-rec (wrap-dtls-record 22 0 (:epoch0-seq st) hvr-hs)]
                         (swap! st-atom #(-> % (update :epoch0-seq inc) (assoc :expected-seq-in 1 :last-flight [hvr-rec])))
                         (swap! out-packets-atom conj hvr-rec))
                       (let [p-cs (+ 36 sid-len c-len)
                             cs-len (.readUInt16BE body p-cs)
                             p-comp (+ p-cs 2 cs-len)
                             comp-len (.readUInt8 body p-comp)
                             p-ext (+ p-comp 1 comp-len)
                             ems? (loop [p (if (<= (+ p-ext 2) (.-length body)) (+ p-ext 2) (.-length body))
                                         end (if (<= (+ p-ext 2) (.-length body))
                                               (+ p-ext 2 (.readUInt16BE body p-ext))
                                               0)
                                         found? false]
                                    (if (<= (+ p 4) end)
                                      (let [et (.readUInt16BE body p)
                                            el (.readUInt16BE body (+ p 2))]
                                        (recur (+ p 4 el) end (or found? (= et 0x0017))))
                                      found?))
                             cs (if (= (.-asymmetricKeyType (:priv-key st)) "rsa")
                                  (js/Buffer.from #js [0xC0 0x2F])
                                  (js/Buffer.from #js [0xC0 0x2B]))
                             sh-exts (js/Buffer.concat
                                      #js [(js/Buffer.from #js [0xFF 0x01 0x00 0x01 0x00
                                                                0x00 0x0B 0x00 0x02 0x01 0x00])
                                           (if ems? (js/Buffer.from #js [0x00 0x17 0x00 0x00]) (js/Buffer.alloc 0))])
                             sh-ext-len (js/Buffer.alloc 2)
                             _ (.writeUInt16BE sh-ext-len (.-length sh-exts) 0)
                             sh-body (js/Buffer.concat
                                      #js [(js/Buffer.from #js [0xFE 0xFD])
                                           (:server-random st)
                                           (js/Buffer.from #js [0x00])
                                           cs
                                           (js/Buffer.from #js [0x00])
                                           sh-ext-len
                                           sh-exts])
                             ecdh (.createECDH node-crypto "prime256v1")
                             _ (.generateKeys ecdh)
                             srv-pub (.getPublicKey ecdh)
                             params (js/Buffer.concat #js [(js/Buffer.from #js [0x03 0x00 0x17 (.-length srv-pub)]) srv-pub])
                             sig-blk (sign-tls12-bytes (:priv-key st)
                                                       (js/Buffer.concat #js [c-rand (:server-random st) params]))
                             ske-body (js/Buffer.concat #js [params sig-blk])
                             cr-body (js/Buffer.from #js [0x02 0x40 0x01
                                                          0x00 0x08 0x04 0x03 0x04 0x01 0x08 0x04 0x05 0x03
                                                          0x00 0x00])
                             sh-hs (wrap-dtls-handshake 2 1 sh-body)
                             cert-hs (wrap-dtls-handshake 11 2 (build-cert-hs-body (:cert-der st)))
                             ske-hs (wrap-dtls-handshake 12 3 ske-body)
                             cr-hs (wrap-dtls-handshake 13 4 cr-body)
                             shd-hs (wrap-dtls-handshake 14 5 (js/Buffer.alloc 0))
                             r0 (:epoch0-seq st)
                             fl [(wrap-dtls-record 22 0 r0 sh-hs)
                                 (wrap-dtls-record 22 0 (+ r0 1) cert-hs)
                                 (wrap-dtls-record 22 0 (+ r0 2) ske-hs)
                                 (wrap-dtls-record 22 0 (+ r0 3) cr-hs)
                                 (wrap-dtls-record 22 0 (+ r0 4) shd-hs)]]
                         (swap! st-atom assoc
                                :client-random c-rand
                                :use-ems? ems?
                                :ecdh ecdh
                                :transcript [full-hs sh-hs cert-hs ske-hs cr-hs shd-hs]
                                :msg-seq-out 6
                                :epoch0-seq (+ r0 5)
                                :expected-seq-in 2
                                :last-flight fl)
                         (swap! out-packets-atom into fl))))

                   11 ;; Client Certificate
                   (do
                     (swap! st-atom update :transcript conj full-hs)
                     (parse-peer-cert! body))

                   16 ;; ClientKeyExchange
                   (let [pub-len (.readUInt8 body 0)
                         cli-pub (js/Buffer.from (.subarray body 1 (+ 1 pub-len)))]
                     (swap! st-atom #(-> % (update :transcript conj full-hs) (assoc :peer-ecdh-pub cli-pub)))
                     (derive-session-keys!))

                   15 ;; CertificateVerify
                   (let [cur @st-atom
                         hash-alg (.readUInt8 body 0)
                         sig-alg (.readUInt8 body 1)
                         sig-len (.readUInt16BE body 2)
                         sig-bytes (.subarray body 4 (+ 4 sig-len))]
                     (when-not (verify-tls12-signature hash-alg sig-alg
                                                       (js/Buffer.concat (into-array (:transcript cur)))
                                                       sig-bytes (:peer-pub-key cur))
                       (throw (ex-info "DTLS Client CertificateVerify signature verification failed" {:type :dtls-sig-failed})))
                     (swap! st-atom update :transcript conj full-hs)
                     (flush-pending-epoch1! out-packets-atom app-chunks-atom))

                   nil))))
           drain-ordered-hs!
           (fn [out-packets-atom app-chunks-atom]
             (loop []
               (let [st @st-atom
                     exp (:expected-seq-in st)
                     m (get (:pending-hs st) exp)]
                 (when m
                   (swap! st-atom
                          (fn [s]
                            (-> s
                                (update :pending-hs dissoc exp)
                                (assoc :expected-seq-in (inc exp)))))
                   (process-single-hs! m out-packets-atom app-chunks-atom)
                   (recur)))))
           reassemble-and-enqueue-hs!
           (fn [^js frag out-packets-atom app-chunks-atom]
             (loop [off 0]
               (when (<= (+ off 12) (.-length frag))
                 (let [msg-type (.readUInt8 frag off)
                       total-len (.readUIntBE frag (+ off 1) 3)
                       msg-seq (.readUInt16BE frag (+ off 4))
                       frag-off (.readUIntBE frag (+ off 6) 3)
                       frag-len (.readUIntBE frag (+ off 9) 3)
                       chunk (.subarray frag (+ off 12) (+ off 12 frag-len))]
                   (if (and (zero? frag-off) (= frag-len total-len))
                     (swap! st-atom assoc-in [:pending-hs msg-seq]
                            {:msg-type msg-type
                             :msg-seq msg-seq
                             :body chunk
                             :full-hs (wrap-dtls-handshake msg-type msg-seq chunk)})
                     (let [cur-entry (or (get-in @st-atom [:frag-cache msg-seq])
                                         {:msg-type msg-type
                                          :total-len total-len
                                          :buf (js/Buffer.alloc total-len)
                                          :received 0})
                           _ (.copy chunk (:buf cur-entry) frag-off)
                           new-rec (+ (:received cur-entry) (.-length chunk))]
                       (if (>= new-rec total-len)
                         (let [body (:buf cur-entry)]
                           (swap! st-atom
                                  (fn [s]
                                    (-> s
                                        (update :frag-cache dissoc msg-seq)
                                        (assoc-in [:pending-hs msg-seq]
                                                  {:msg-type msg-type
                                                   :msg-seq msg-seq
                                                   :body body
                                                   :full-hs (wrap-dtls-handshake msg-type msg-seq body)})))))
                         (swap! st-atom assoc-in [:frag-cache msg-seq]
                                (assoc cur-entry :received new-rec)))))
                   (recur (+ off 12 frag-len)))))
             (drain-ordered-hs! out-packets-atom app-chunks-atom))]
       (NodeDtlsEngine. st-atom build-client-hello! reassemble-and-enqueue-hs! process-epoch1-record!))))

;; =============================================================================
;; 3. Public Certificate, Context, and Engine Constructors
;; =============================================================================

(defn fingerprint
  "Calculates the SHA-256 fingerprint hash of a given certificate (`X509Certificate` on JVM,
   DER `Uint8Array` / PEM string / `X509Certificate` on CLJS) and returns it as an uppercase
   colon-separated string."
  [cert]
  #?(:clj
     (format-sha256-fingerprint (.getEncoded ^X509Certificate cert))
     :cljs
     (when-let [der (coerce-cert-der-buf cert)]
       (format-sha256-fingerprint (js/Uint8Array. der)))))

#?(:clj
   (defn generate-cert
     "Generates a new self-signed RSA certificate required for WebRTC DTLS setup using `sun.security.tools.keytool` APIs. Returns a map with the certificate, private key, and its SHA-256 fingerprint string."
     []
     (let [key-pair-generator (CertAndKeyGen. "RSA" "SHA256WithRSA" nil)
           x500-name (X500Name. "CN=WebRTC, O=Clojure, C=US")]
       (.generate key-pair-generator 2048)
       (let [key (.getPrivateKey key-pair-generator)
             cert (.getSelfCertificate key-pair-generator
                                       x500-name
                                       (Date.)
                                       (* 60 60 24 3650))]
         {:cert cert
          :key key
          :fingerprint (fingerprint cert)})))
   :cljs
   (defn generate-cert
     "Generates a self-signed ECDSA P-256 X.509 v3 certificate and private key using built-in `node:crypto`."
     []
     (let [kp (.generateKeyPairSync node-crypto "ec" #js {:namedCurve "prime256v1"})
           pub-key (.-publicKey kp)
           priv-key (.-privateKey kp)
           spki (.export pub-key #js {:type "spki" :format "der"})
           ;; OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256)
           sig-alg (der-tag-buf 0x30 (js/Buffer.from #js [0x06 0x08 0x2A 0x86 0x48 0xCE 0x3D 0x04 0x03 0x02]))
           ;; CN=WebRTC
           name-der (js/Buffer.from "3011310f300d06035504030c06576562525443" "hex")
           validity (der-tag-buf 0x30
                                 (js/Buffer.concat
                                  #js [(der-tag-buf 0x17 (js/Buffer.from "250101000000Z" "ascii"))
                                       (der-tag-buf 0x17 (js/Buffer.from "350101000000Z" "ascii"))]))
           serial (der-tag-buf 0x02 (js/Buffer.concat #js [(js/Buffer.from #js [0x01]) (.randomBytes node-crypto 7)]))
           version (der-tag-buf 0xA0 (js/Buffer.from #js [0x02 0x01 0x02]))
           tbs (der-tag-buf 0x30 (js/Buffer.concat #js [version serial sig-alg name-der validity name-der spki]))
           sig (.sign node-crypto "sha256" tbs priv-key)
           cert-buf (der-tag-buf 0x30
                                 (js/Buffer.concat
                                  #js [tbs sig-alg (der-tag-buf 0x03 (js/Buffer.concat #js [(js/Buffer.from #js [0x00]) sig]))]))
           cert-u8 (js/Uint8Array. cert-buf)
           x509 (new (.-X509Certificate node-crypto) cert-buf)
           fp (format-sha256-fingerprint cert-u8)]
       {:cert cert-u8
        :key priv-key
        :cert-pem (.toString x509)
        :key-pem (.export priv-key #js {:type "pkcs8" :format "pem"})
        :fingerprint fp})))

#?(:clj
   (defn create-ssl-context
     "Initializes an `SSLContext` from the provided certificate and key with a dynamic password. Disables deep X509 chain trust managers since WebRTC uses peer fingerprint verification over SDP."
     [cert key]
     (let [ks (KeyStore/getInstance "PKCS12")
           kmf (KeyManagerFactory/getInstance "SunX509")
           tmf (TrustManagerFactory/getInstance "SunX509")
           ctx (SSLContext/getInstance "DTLS")
           pwd-chars (char-array (str (java.util.UUID/randomUUID)))]
       (.load ks nil nil)
       (.setKeyEntry ks "webrtc" key pwd-chars (into-array X509Certificate [cert]))
       (.init kmf ks pwd-chars)
       (.init tmf ks)
       (let [tm (reify X509TrustManager
                  (checkClientTrusted [_ _chain _auth-type])
                  (checkServerTrusted [_ _chain _auth-type])
                  (getAcceptedIssuers [_] (make-array X509Certificate 0)))]
         (.init ctx (.getKeyManagers kmf) (into-array [tm]) nil))
       ctx))
   :cljs
   (defn create-ssl-context
     "Creates a DTLS context map from `cert` (DER `Uint8Array` or PEM string) and `key` (`KeyObject`, PKCS#8 DER, or PEM string)."
     [cert key]
     {:cert-der (coerce-cert-der-buf cert)
      :priv-key (coerce-private-key-obj key)}))

#?(:clj
   (defn create-engine
     "Instantiates a new `SSLEngine` bounded by the context, defining client vs server mode behavior and explicitly requiring mutual authentication for DTLS SRTP."
     [^SSLContext context client-mode]
     (let [engine (.createSSLEngine context)]
       (.setUseClientMode engine client-mode)
       (let [params (.getSSLParameters engine)]
         (.setNeedClientAuth params true)
         (.setMaximumPacketSize params DEFAULT-PACKET-SIZE)
         (.setSSLParameters engine params)
         engine)))
   :cljs
   (defn create-engine
     "Instantiates a pure Node.js (`node:crypto`) DTLS 1.2 `IDtlsEngine` from `context` and `client-mode`."
     [context client-mode]
     (when (and (:cert-der context) (:priv-key context))
       (create-node-dtls-engine (:cert-der context) (:priv-key context) client-mode))))

#?(:clj
   (defn- make-buffer []
     (ByteBuffer/allocateDirect buffer-size)))

#?(:clj
   (defn- buffer->bytes [^ByteBuffer buf]
     (let [len (.remaining buf)
           bs (byte-array len)]
       (.get buf bs)
       bs)))

#?(:clj
   (defn handshake
     "Runs the DTLS handshake loop until I/O is required.
     `engine`: The SSLEngine.
     `in`: A ByteBuffer containing incoming handshake data from the peer. Can be empty.
     `out`: A ByteBuffer to use as scratch space for outgoing data.

     Returns a map with:
     :status - The SSLEngineResult$HandshakeStatus.
     :packets - A vector of byte arrays (outgoing packets).
     :app-data - A byte array of decrypted application data (if any)."
     [^SSLEngine engine ^ByteBuffer in ^ByteBuffer out]
     (.clear out)
     (let [empty-app-buffer (ByteBuffer/allocate 0)
           packets (ArrayList.)
           app-data-out (ByteArrayOutputStream.)]
       (loop [loops 0]
         (if (> loops 100)
           (throw (Exception. "Too many handshake loops"))
           (let [hs-status (.getHandshakeStatus engine)]
             (condp = hs-status
               SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING
               (if (.hasRemaining in)
                 (let [temp-app (make-buffer)
                       res (.unwrap engine in temp-app)]
                   (.flip temp-app)
                   (when (> (.remaining temp-app) 0)
                     (.write app-data-out (buffer->bytes temp-app) 0 (.remaining temp-app)))
                   (condp = (.getStatus res)
                     SSLEngineResult$Status/BUFFER_UNDERFLOW
                     {:status (.getHandshakeStatus engine)
                      :packets (vec packets)
                      :app-data (.toByteArray app-data-out)}
                     SSLEngineResult$Status/CLOSED
                     (throw (Exception. "SSLEngine closed during handshake"))
                     (recur (inc loops))))
                 {:status hs-status
                  :packets (vec packets)
                  :app-data (.toByteArray app-data-out)})

               SSLEngineResult$HandshakeStatus/FINISHED
               {:status hs-status
                :packets (vec packets)
                :app-data (.toByteArray app-data-out)}

               SSLEngineResult$HandshakeStatus/NEED_TASK
               (do
                 (while (let [task (.getDelegatedTask engine)]
                          (when task
                            (.run task)
                            task)))
                 (recur (inc loops)))

               SSLEngineResult$HandshakeStatus/NEED_WRAP
               (do
                 (.clear out)
                 (let [res (.wrap engine empty-app-buffer out)]
                   (.flip out)
                   (when (> (.remaining out) 0)
                     (.add packets (buffer->bytes out)))
                   (condp = (.getStatus res)
                     SSLEngineResult$Status/BUFFER_OVERFLOW
                     (throw (Exception. "Buffer overflow during handshake wrap"))
                     SSLEngineResult$Status/CLOSED
                     (throw (Exception. "SSLEngine closed during handshake"))
                     (recur (inc loops)))))

               SSLEngineResult$HandshakeStatus/NEED_UNWRAP
               (if (.hasRemaining in)
                 (let [temp-app (make-buffer)
                       res (.unwrap engine in temp-app)]
                   (.flip temp-app)
                   (when (> (.remaining temp-app) 0)
                     (.write app-data-out (buffer->bytes temp-app) 0 (.remaining temp-app)))
                   (condp = (.getStatus res)
                     SSLEngineResult$Status/BUFFER_UNDERFLOW
                     {:status (.getHandshakeStatus engine)
                      :packets (vec packets)
                      :app-data (.toByteArray app-data-out)}
                     SSLEngineResult$Status/CLOSED
                     (throw (Exception. "SSLEngine closed during handshake"))
                     (recur (inc loops))))
                 (if (and (zero? loops) (.isEmpty packets))
                   (do
                     (.clear out)
                     (let [res (.wrap engine empty-app-buffer out)]
                       (.flip out)
                       (when (> (.remaining out) 0)
                         (.add packets (buffer->bytes out)))
                       (cond
                         (= (.getStatus res) SSLEngineResult$Status/CLOSED)
                         (throw (Exception. "SSLEngine closed during handshake"))

                         (= (.getHandshakeStatus engine) SSLEngineResult$HandshakeStatus/NEED_WRAP)
                         (recur (inc loops))

                         :else
                         {:status (.getHandshakeStatus engine)
                          :packets (vec packets)
                          :app-data (.toByteArray app-data-out)})))
                   {:status hs-status
                    :packets (vec packets)
                    :app-data (.toByteArray app-data-out)}))

               SSLEngineResult$HandshakeStatus/NEED_UNWRAP_AGAIN
               (let [temp-app (make-buffer)
                     res (.unwrap engine in temp-app)]
                 (.flip temp-app)
                 (when (> (.remaining temp-app) 0)
                   (.write app-data-out (buffer->bytes temp-app) 0 (.remaining temp-app)))
                 (condp = (.getStatus res)
                   SSLEngineResult$Status/BUFFER_UNDERFLOW
                   {:status (.getHandshakeStatus engine)
                    :packets (vec packets)
                    :app-data (.toByteArray app-data-out)}
                   SSLEngineResult$Status/CLOSED
                   (throw (Exception. "SSLEngine closed during handshake"))
                   (recur (inc loops)))))))))))

#?(:clj
   (defn send-app-data
     "Encrypts and sends application data. Should only be called after handshake is complete.
     `engine`: The SSLEngine.
     `app-data`: A ByteBuffer with the application data to send.
     `net-out`: A ByteBuffer to write the encrypted data to.

     Returns a map with:
     :status - The SSLEngineResult$Status.
     :bytes - A byte array of the encrypted data to be sent."
     [^SSLEngine engine ^ByteBuffer app-data ^ByteBuffer net-out]
     (.clear net-out)
     (let [res (.wrap engine app-data net-out)]
       (.flip net-out)
       {:status (.getStatus res)
        :bytes (buffer->bytes net-out)})))

#?(:clj
   (defn receive-app-data
     "Receives and decrypts application data.
     `engine`: The SSLEngine.
     `net-in`: A ByteBuffer containing encrypted data from the peer.
     `app-out`: A ByteBuffer to write the decrypted application data to.

     Returns a map with:
     :status - The SSLEngineResult$Status.
     :bytes - A byte array of the decrypted application data, if any."
     [^SSLEngine engine ^ByteBuffer net-in ^ByteBuffer app-out]
     (.clear app-out)
     (try
       (let [res (.unwrap engine net-in app-out)]
         (.flip app-out)
         {:status (.getStatus res)
          :bytes (buffer->bytes app-out)})
       (catch Exception _
         {:status nil :bytes nil}))))

#?(:clj
   (extend-type SSLEngine
     IDtlsEngine
     (begin-handshake! [engine]
       (.beginHandshake engine))
     (handshake-finished? [engine]
       (let [st (.getHandshakeStatus engine)]
         (or (= st SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING)
             (= st SSLEngineResult$HandshakeStatus/FINISHED))))
     (handshake-step [engine in-bytes]
       (let [in-buf (cond
                      (nil? in-bytes) (ByteBuffer/allocateDirect 0)
                      (instance? ByteBuffer in-bytes) in-bytes
                      :else (ByteBuffer/wrap (b/to-bytes in-bytes)))
             out-buf (ByteBuffer/allocateDirect buffer-size)
             {:keys [status packets app-data]} (handshake engine in-buf out-buf)
             fin? (or (= status SSLEngineResult$HandshakeStatus/FINISHED)
                      (= status SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING))]
         {:status status
          :finished? fin?
          :packets packets
          :app-data app-data}))
     (wrap-app-data [engine plain-bytes]
       (let [in-buf (if (instance? ByteBuffer plain-bytes)
                      plain-bytes
                      (ByteBuffer/wrap (b/to-bytes plain-bytes)))
             net-out (ByteBuffer/allocateDirect buffer-size)]
         (send-app-data engine in-buf net-out)))
     (unwrap-packet [engine net-bytes]
       (let [in-buf (if (instance? ByteBuffer net-bytes)
                      net-bytes
                      (ByteBuffer/wrap (b/to-bytes net-bytes)))
             app-out (ByteBuffer/allocateDirect buffer-size)]
         (receive-app-data engine in-buf app-out)))
     (peer-fingerprint [engine]
       (try
         (when-let [cert (->> engine
                              (.getSession)
                              (.getPeerCertificates)
                              (seq)
                              (first))]
           (fingerprint cert))
         (catch Exception _
           nil)))
     (handle-timeout [engine _now-ms]
       (handshake-step engine b/empty-bytes))))
