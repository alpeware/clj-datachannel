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
    "Returns the peer certificate's uppercase colon-separated SHA-256 fingerprint string, or nil."))

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

(defn- format-sha256-fingerprint
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
                   (let [s-rand (js/Buffer.from (.subarray body 2 34))
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
                   (let [c-rand (js/Buffer.from (.subarray body 2 34))
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
       (reify IDtlsEngine
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
               {:status nil :bytes nil})))))))

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
           nil)))))
