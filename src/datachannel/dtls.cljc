(ns datachannel.dtls
  "Cross-platform DTLS engine abstraction (`IDtlsEngine`) and JVM `SSLEngine` implementation."
  (:require [clojure.string :as str]
            [datachannel.buffer :as b])
  #?(:clj
     (:import [java.io ByteArrayOutputStream]
              [java.nio ByteBuffer]
              [java.security KeyStore MessageDigest]
              [java.security.cert X509Certificate]
              [java.util ArrayList Date]
              [javax.net.ssl KeyManagerFactory SSLContext SSLEngine SSLEngineResult$HandshakeStatus SSLEngineResult$Status TrustManagerFactory X509TrustManager]
              [sun.security.tools.keytool CertAndKeyGen]
              [sun.security.x509 X500Name])))

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

;; =============================================================================
;; 2. JVM `SSLEngine` Implementation & Legacy Helpers
;; =============================================================================

#?(:clj
   (defn fingerprint
     "Calculates the SHA-256 fingerprint hash of a given `X509Certificate` and returns it as a formatted string separated by colons."
     [cert]
     (let [md (MessageDigest/getInstance "SHA-256")]
       (->> (.getEncoded ^X509Certificate cert)
            (.update md))
       (-> (java.util.HexFormat/ofDelimiter ":")
           (.withUpperCase)
           (.formatHex (.digest md))))))

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
     "Returns placeholder certificate metadata when no JVM X509 generator is present."
     []
     {:cert nil
      :key nil
      :fingerprint (str/join ":" (repeatedly 32 #(let [v (b/random-int 256)]
                                                   (str/upper-case
                                                    (str (when (< v 16) "0") (.toString v 16))))))}))

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
     "Placeholder SSLContext initializer for ClojureScript."
     [_cert _key]
     nil))

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
     "Placeholder DTLS engine constructor for ClojureScript."
     [_context _client-mode]
     nil))

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
