(ns datachannel.turn
  "RFC 5766 Traversal Using Relays around NAT (TURN) Client Protocol Implementation.
   Provides message codecs, attribute serializations, long-term credential authentication,
   and ChannelData framing (RFC 5766 §11)."
  (:require [clojure.string :as str]
            [datachannel.stun :as stun])
  (:import [java.net InetAddress InetSocketAddress]
           [java.nio ByteBuffer ByteOrder]
           [java.security MessageDigest SecureRandom]
           [java.util.zip CRC32]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(defonce ^:private secure-rand (SecureRandom.))

;; -----------------------------------------------------------------------------
;; TURN Method Constants (RFC 5766)
;; -----------------------------------------------------------------------------
(def METHOD_ALLOCATE_REQUEST "RFC 5766 TURN method code for Allocate Request (0x0003)." 0x0003)
(def METHOD_ALLOCATE_RESPONSE "RFC 5766 TURN method code for Allocate Success Response (0x0103)." 0x0103)
(def METHOD_ALLOCATE_ERROR "RFC 5766 TURN method code for Allocate Error Response (0x0113)." 0x0113)

(def METHOD_REFRESH_REQUEST "RFC 5766 TURN method code for Refresh Request (0x0004)." 0x0004)
(def METHOD_REFRESH_RESPONSE "RFC 5766 TURN method code for Refresh Success Response (0x0104)." 0x0104)
(def METHOD_REFRESH_ERROR "RFC 5766 TURN method code for Refresh Error Response (0x0114)." 0x0114)

(def METHOD_CREATE_PERMISSION_REQUEST "RFC 5766 TURN method code for CreatePermission Request (0x0008)." 0x0008)
(def METHOD_CREATE_PERMISSION_RESPONSE "RFC 5766 TURN method code for CreatePermission Success Response (0x0108)." 0x0108)
(def METHOD_CREATE_PERMISSION_ERROR "RFC 5766 TURN method code for CreatePermission Error Response (0x0118)." 0x0118)

(def METHOD_CHANNEL_BIND_REQUEST "RFC 5766 TURN method code for ChannelBind Request (0x0009)." 0x0009)
(def METHOD_CHANNEL_BIND_RESPONSE "RFC 5766 TURN method code for ChannelBind Success Response (0x0109)." 0x0109)
(def METHOD_CHANNEL_BIND_ERROR "RFC 5766 TURN method code for ChannelBind Error Response (0x0119)." 0x0119)

(def METHOD_SEND_INDICATION "RFC 5766 TURN method code for Send Indication (0x0016)." 0x0016)
(def METHOD_DATA_INDICATION "RFC 5766 TURN method code for Data Indication (0x0017)." 0x0017)

;; -----------------------------------------------------------------------------
;; TURN Attribute Constants (RFC 5766)
;; -----------------------------------------------------------------------------
(def ATTR_CHANNEL_NUMBER "RFC 5766 TURN attribute code for CHANNEL-NUMBER (0x000C)." 0x000C)
(def ATTR_LIFETIME "RFC 5766 TURN attribute code for LIFETIME (0x000D)." 0x000D)
(def ATTR_XOR_PEER_ADDRESS "RFC 5766 TURN attribute code for XOR-PEER-ADDRESS (0x0012)." 0x0012)
(def ATTR_DATA "RFC 5766 TURN attribute code for DATA (0x0013)." 0x0013)
(def ATTR_REALM "RFC 5766 TURN attribute code for REALM (0x0014)." 0x0014)
(def ATTR_NONCE "RFC 5766 TURN attribute code for NONCE (0x0015)." 0x0015)
(def ATTR_XOR_RELAYED_ADDRESS "RFC 5766 TURN attribute code for XOR-RELAYED-ADDRESS (0x0016)." 0x0016)
(def ATTR_REQUESTED_TRANSPORT "RFC 5766 TURN attribute code for REQUESTED-TRANSPORT (0x0019)." 0x0019)

;; Channel number bounds (RFC 5766 §11)
(def MIN_CHANNEL_NUMBER "RFC 5766 minimum valid channel number (0x4000)." 0x4000)
(def MAX_CHANNEL_NUMBER "RFC 5766 maximum valid channel number (0x7FFF)." 0x7FFF)

;; -----------------------------------------------------------------------------
;; Binary Helpers
;; -----------------------------------------------------------------------------
(defn- put-u16 [^ByteBuffer buf val]
  (.putShort buf (unchecked-short val)))

(defn- get-u16 [^ByteBuffer buf]
  (bit-and (.getShort buf) 0xffff))

(defn- put-u32 [^ByteBuffer buf val]
  (.putInt buf (unchecked-int val)))

(defn- get-u32 [^ByteBuffer buf]
  (bit-and (.getInt buf) 0xffffffff))

(defn- compute-crc32 [data]
  (let [crc (CRC32.)]
    (.update crc data)
    (bit-xor (.getValue crc) 0x5354554e)))

;; -----------------------------------------------------------------------------
;; Long-Term Credential Authentication (RFC 5389 §15.4 / RFC 5766)
;; -----------------------------------------------------------------------------

(defn compute-long-term-key
  "Computes RFC 5389 §15.4 long-term credential key:
   key = MD5(username \":\" realm \":\" password)
   Returns a 16-byte raw byte array."
  [username realm password]
  (let [md5 (MessageDigest/getInstance "MD5")
        input (str (or username "") ":" (or realm "") ":" (or password ""))
        bytes (.getBytes input "UTF-8")]
    (.digest md5 bytes)))

(defn compute-hmac-sha1
  "Computes HMAC-SHA1 signature over `data` using `key-bytes` or a string key."
  [key-bytes-or-str data]
  (let [key-bytes (if (string? key-bytes-or-str)
                    (.getBytes ^String key-bytes-or-str "UTF-8")
                    ^bytes key-bytes-or-str)
        mac (Mac/getInstance "HmacSHA1")
        key-spec (SecretKeySpec. key-bytes "HmacSHA1")]
    (.init mac key-spec)
    (.doFinal mac data)))

;; -----------------------------------------------------------------------------
;; XOR Address Codecs (RFC 5389 / RFC 5766)
;; -----------------------------------------------------------------------------

(defn encode-xor-address
  "Encodes an IPv4 address into an 8-byte XOR address attribute payload."
  [^InetSocketAddress addr cookie]
  (let [buf (ByteBuffer/allocate 8)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        port (.getPort addr)
        xport (bit-xor port (bit-shift-right cookie 16))
        addr-bytes (.getAddress (.getAddress addr))
        cookie-bytes (ByteBuffer/allocate 4)
        _ (.putInt cookie-bytes cookie)
        _ (.flip cookie-bytes)
        c-bytes (.array cookie-bytes)]
    (.put buf (byte 0)) ;; reserved
    (.put buf (byte 1)) ;; family IPv4
    (put-u16 buf xport)
    (dotimes [i 4]
      (.put buf (unchecked-byte (bit-xor (aget addr-bytes i) (aget c-bytes i)))))
    (.array buf)))

(defn decode-xor-address
  "Decodes an 8-byte XOR address attribute payload into {:ip str :port int :address InetAddress}."
  [^bytes val-bytes cookie]
  (let [buf (ByteBuffer/wrap val-bytes)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        _ (.get buf) ;; reserved
        family (bit-and (.get buf) 0xff)
        xport (get-u16 buf)
        port (bit-xor xport (bit-shift-right cookie 16))]
    (if (= family 0x01)
      (let [raw-addr (byte-array 4)
            _ (.get buf raw-addr)
            cookie-bytes (ByteBuffer/allocate 4)
            _ (.putInt cookie-bytes cookie)
            _ (.flip cookie-bytes)
            c-bytes (.array cookie-bytes)
            dec-addr (byte-array 4)]
        (dotimes [i 4]
          (aset dec-addr i (unchecked-byte (bit-xor (aget raw-addr i) (aget c-bytes i)))))
        (let [inet-addr (InetAddress/getByAddress dec-addr)]
          {:family family
           :port port
           :address inet-addr
           :ip (.getHostAddress inet-addr)}))
      (throw (ex-info "Only IPv4 XOR addresses supported" {:family family})))))

;; -----------------------------------------------------------------------------
;; RFC 5766 §11 ChannelData Framing
;; -----------------------------------------------------------------------------

(defn channel-data?
  "Returns true if the buffer or byte array starts with a ChannelData header (0x4000..0x7FFF)."
  [buf-or-bytes]
  (try
    (let [buf (if (instance? ByteBuffer buf-or-bytes)
                (.duplicate ^ByteBuffer buf-or-bytes)
                (ByteBuffer/wrap ^bytes buf-or-bytes))]
      (when (>= (.remaining buf) 4)
        (.order buf ByteOrder/BIG_ENDIAN)
        (let [ch (bit-and (.getShort buf) 0xffff)
              len (bit-and (.getShort buf) 0xffff)]
          (and (>= ch MIN_CHANNEL_NUMBER)
               (<= ch MAX_CHANNEL_NUMBER)
               (>= (.remaining buf) len)))))
    (catch Exception _
      false)))

(defn encode-channel-data
  "Encodes application payload bytes into an RFC 5766 §11 ChannelData frame
   with 4-byte header and 4-byte padding alignment."
  [channel-number data-bytes]
  (let [data (if (string? data-bytes) (.getBytes ^String data-bytes "UTF-8") ^bytes data-bytes)
        len (alength data)
        padding (let [r (mod len 4)] (if (zero? r) 0 (- 4 r)))
        total-len (+ 4 len padding)
        buf (ByteBuffer/allocate total-len)]
    (.order buf ByteOrder/BIG_ENDIAN)
    (put-u16 buf channel-number)
    (put-u16 buf len)
    (.put buf data)
    (dotimes [_ padding] (.put buf (byte 0)))
    (.array buf)))

(defn decode-channel-data
  "Decodes an RFC 5766 §11 ChannelData frame from a ByteBuffer or byte array,
   returning {:channel-number int :data byte[] :length int}."
  [buf-or-bytes]
  (try
    (let [buf (if (instance? ByteBuffer buf-or-bytes)
                (.duplicate ^ByteBuffer buf-or-bytes)
                (ByteBuffer/wrap ^bytes buf-or-bytes))]
      (.order buf ByteOrder/BIG_ENDIAN)
      (when (>= (.remaining buf) 4)
        (let [ch (get-u16 buf)
              len (get-u16 buf)]
          (when (and (>= ch MIN_CHANNEL_NUMBER)
                     (<= ch MAX_CHANNEL_NUMBER)
                     (>= (.remaining buf) len))
            (let [data (byte-array len)]
              (.get buf data)
              {:channel-number ch
               :data data
               :length len})))))
    (catch Exception _
      nil)))

;; -----------------------------------------------------------------------------
;; TURN Message Serialization
;; -----------------------------------------------------------------------------

(defn- append-attr-string [^ByteBuffer buf attr-type ^String s]
  (let [b (.getBytes s "UTF-8")
        len (alength b)
        padding (let [r (mod len 4)] (if (zero? r) 0 (- 4 r)))]
    (put-u16 buf attr-type)
    (put-u16 buf len)
    (.put buf b)
    (dotimes [_ padding] (.put buf (byte 0)))))

(defn- append-attr-u32 [^ByteBuffer buf attr-type val]
  (put-u16 buf attr-type)
  (put-u16 buf 4)
  (put-u32 buf val))

(defn- finalize-turn-message
  "Appends MESSAGE-INTEGRITY and FINGERPRINT attributes to a STUN/TURN buffer."
  [^ByteBuffer buf key-bytes-or-str]
  (when key-bytes-or-str
    ;; Header length includes MESSAGE-INTEGRITY (24 bytes)
    (let [len-before-mi (- (.position buf) 20)
          len-with-mi (+ len-before-mi 24)]
      (.putShort buf 2 (unchecked-short len-with-mi)))
    (let [len-to-sign (.position buf)
          data-to-sign (byte-array len-to-sign)]
      (.position buf 0)
      (.get buf data-to-sign)
      (.position buf len-to-sign)
      (let [hmac (compute-hmac-sha1 key-bytes-or-str data-to-sign)]
        (put-u16 buf stun/ATTR_MESSAGE_INTEGRITY)
        (put-u16 buf 20)
        (.put buf hmac))))
  ;; FINGERPRINT
  (let [len-before-fp (- (.position buf) 20)
        total-len (+ len-before-fp 8)]
    (.putShort buf 2 (unchecked-short total-len)))
  (let [len-to-crc (.position buf)
        data-to-crc (byte-array len-to-crc)]
    (.position buf 0)
    (.get buf data-to-crc)
    (.position buf len-to-crc)
    (let [crc (compute-crc32 data-to-crc)]
      (put-u16 buf stun/ATTR_FINGERPRINT)
      (put-u16 buf 4)
      (.putInt buf (unchecked-int crc))))
  (.flip buf)
  buf)

(defn make-allocate-request
  "Constructs an RFC 5766 Allocate Request packet.
   If nonce/realm are nil, builds an initial unauthenticated request to trigger a 401 challenge.
   If nonce/realm are provided, signs with the long-term MD5 key."
  ([username realm password nonce]
   (make-allocate-request username realm password nonce nil))
  ([username realm password nonce opts]
   (let [buf (ByteBuffer/allocate 1024)
         _ (.order buf ByteOrder/BIG_ENDIAN)
         tx-id (or (:tx-id opts)
                   (let [t (byte-array 12)]
                     (.nextBytes secure-rand t)
                     t))
         lifetime (long (or (:lifetime opts) 600))]
     ;; Header
     (put-u16 buf METHOD_ALLOCATE_REQUEST)
     (put-u16 buf 0) ;; length placeholder
     (.putInt buf stun/magic-cookie)
     (.put buf tx-id)

     ;; REQUESTED-TRANSPORT (UDP = 17, followed by 3 bytes 0x00)
     (put-u16 buf ATTR_REQUESTED_TRANSPORT)
     (put-u16 buf 4)
     (.put buf (byte 17))
     (.put buf (byte 0))
     (.put buf (byte 0))
     (.put buf (byte 0))

     ;; DONT-FRAG (optional, not strictly required for IPv4)
     ;; LIFETIME
     (append-attr-u32 buf ATTR_LIFETIME lifetime)

     ;; Authenticated attributes if credentials provided
     (if (and username realm password nonce)
       (do
         (append-attr-string buf stun/ATTR_USERNAME username)
         (append-attr-string buf ATTR_REALM realm)
         (append-attr-string buf ATTR_NONCE nonce)
         (let [key (compute-long-term-key username realm password)]
           (finalize-turn-message buf key)))
       (finalize-turn-message buf nil)))))

(defn make-refresh-request
  "Constructs an RFC 5766 Refresh Request to extend or terminate an allocation (lifetime = 0 terminates)."
  [username realm password nonce lifetime & [opts]]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        tx-id (or (:tx-id opts)
                  (let [t (byte-array 12)]
                    (.nextBytes secure-rand t)
                    t))]
    (put-u16 buf METHOD_REFRESH_REQUEST)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    (append-attr-u32 buf ATTR_LIFETIME (long lifetime))
    (if (and username realm password nonce)
      (do
        (append-attr-string buf stun/ATTR_USERNAME username)
        (append-attr-string buf ATTR_REALM realm)
        (append-attr-string buf ATTR_NONCE nonce)
        (let [key (compute-long-term-key username realm password)]
          (finalize-turn-message buf key)))
      (finalize-turn-message buf nil))))

(defn make-create-permission-request
  "Constructs an RFC 5766 CreatePermission Request authorizing relay traffic to/from peer-addr."
  [username realm password nonce peer-addr & [opts]]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        tx-id (or (:tx-id opts)
                  (let [t (byte-array 12)]
                    (.nextBytes secure-rand t)
                    t))
        sock-addr (if (instance? InetSocketAddress peer-addr)
                    peer-addr
                    (let [[ip port] (str/split (str peer-addr) #":")]
                      (InetSocketAddress. ^String ip (Integer/parseInt port))))
        xor-peer (encode-xor-address sock-addr stun/magic-cookie)]
    (put-u16 buf METHOD_CREATE_PERMISSION_REQUEST)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    ;; XOR-PEER-ADDRESS
    (put-u16 buf ATTR_XOR_PEER_ADDRESS)
    (put-u16 buf 8)
    (.put buf xor-peer)
    (if (and username realm password nonce)
      (do
        (append-attr-string buf stun/ATTR_USERNAME username)
        (append-attr-string buf ATTR_REALM realm)
        (append-attr-string buf ATTR_NONCE nonce)
        (let [key (compute-long-term-key username realm password)]
          (finalize-turn-message buf key)))
      (finalize-turn-message buf nil))))

(defn make-channel-bind-request
  "Constructs an RFC 5766 ChannelBind Request associating channel-number with peer-addr."
  [username realm password nonce channel-number peer-addr & [opts]]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        tx-id (or (:tx-id opts)
                  (let [t (byte-array 12)]
                    (.nextBytes secure-rand t)
                    t))
        sock-addr (if (instance? InetSocketAddress peer-addr)
                    peer-addr
                    (let [[ip port] (str/split (str peer-addr) #":")]
                      (InetSocketAddress. ^String ip (Integer/parseInt port))))
        xor-peer (encode-xor-address sock-addr stun/magic-cookie)]
    (put-u16 buf METHOD_CHANNEL_BIND_REQUEST)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    ;; CHANNEL-NUMBER (2 bytes channel, 2 bytes reserved 0x00)
    (put-u16 buf ATTR_CHANNEL_NUMBER)
    (put-u16 buf 4)
    (put-u16 buf (int channel-number))
    (put-u16 buf 0)
    ;; XOR-PEER-ADDRESS
    (put-u16 buf ATTR_XOR_PEER_ADDRESS)
    (put-u16 buf 8)
    (.put buf xor-peer)
    (if (and username realm password nonce)
      (do
        (append-attr-string buf stun/ATTR_USERNAME username)
        (append-attr-string buf ATTR_REALM realm)
        (append-attr-string buf ATTR_NONCE nonce)
        (let [key (compute-long-term-key username realm password)]
          (finalize-turn-message buf key)))
      (finalize-turn-message buf nil))))

(defn make-send-indication
  "Constructs an RFC 5766 Send Indication datagram carrying application payload to peer-addr."
  [peer-addr data-bytes & [opts]]
  (let [buf (ByteBuffer/allocate 4096)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        tx-id (or (:tx-id opts)
                  (let [t (byte-array 12)]
                    (.nextBytes secure-rand t)
                    t))
        sock-addr (if (instance? InetSocketAddress peer-addr)
                    peer-addr
                    (let [[ip port] (str/split (str peer-addr) #":")]
                      (InetSocketAddress. ^String ip (Integer/parseInt port))))
        xor-peer (encode-xor-address sock-addr stun/magic-cookie)
        data (if (string? data-bytes) (.getBytes ^String data-bytes "UTF-8") ^bytes data-bytes)
        d-len (alength data)
        padding (let [r (mod d-len 4)] (if (zero? r) 0 (- 4 r)))]
    (put-u16 buf METHOD_SEND_INDICATION)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    ;; XOR-PEER-ADDRESS
    (put-u16 buf ATTR_XOR_PEER_ADDRESS)
    (put-u16 buf 8)
    (.put buf xor-peer)
    ;; DATA
    (put-u16 buf ATTR_DATA)
    (put-u16 buf d-len)
    (.put buf data)
    (dotimes [_ padding] (.put buf (byte 0)))
    ;; Fingerprint
    (finalize-turn-message buf nil)))

(defn make-data-indication
  "Constructs an RFC 5766 Data Indication datagram delivering relay data received from peer-addr."
  [peer-addr data-bytes & [opts]]
  (let [buf (ByteBuffer/allocate 4096)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        tx-id (or (:tx-id opts)
                  (let [t (byte-array 12)]
                    (.nextBytes secure-rand t)
                    t))
        sock-addr (if (instance? InetSocketAddress peer-addr)
                    peer-addr
                    (let [[ip port] (str/split (str peer-addr) #":")]
                      (InetSocketAddress. ^String ip (Integer/parseInt port))))
        xor-peer (encode-xor-address sock-addr stun/magic-cookie)
        data (if (string? data-bytes) (.getBytes ^String data-bytes "UTF-8") ^bytes data-bytes)
        d-len (alength data)
        padding (let [r (mod d-len 4)] (if (zero? r) 0 (- 4 r)))]
    (put-u16 buf METHOD_DATA_INDICATION)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    ;; XOR-PEER-ADDRESS
    (put-u16 buf ATTR_XOR_PEER_ADDRESS)
    (put-u16 buf 8)
    (.put buf xor-peer)
    ;; DATA
    (put-u16 buf ATTR_DATA)
    (put-u16 buf d-len)
    (.put buf data)
    (dotimes [_ padding] (.put buf (byte 0)))
    (finalize-turn-message buf nil)))

;; -----------------------------------------------------------------------------
;; Server Mock Response Helpers (for Tests)
;; -----------------------------------------------------------------------------

(defn make-allocate-error-response
  "Constructs an RFC 5766 401 Unauthorized Error Response to an Allocate Request,
   embedding REALM, NONCE, and ERROR-CODE attributes."
  [tx-id realm nonce]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)]
    (put-u16 buf METHOD_ALLOCATE_ERROR)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    ;; ERROR-CODE (401)
    (put-u16 buf stun/ATTR_ERROR_CODE)
    (put-u16 buf 4)
    (.put buf (byte 0)) ;; reserved
    (.put buf (byte 0))
    (.put buf (byte 4)) ;; class 4
    (.put buf (byte 1)) ;; code 01
    (append-attr-string buf ATTR_REALM realm)
    (append-attr-string buf ATTR_NONCE nonce)
    (finalize-turn-message buf nil)))

(defn make-allocate-success-response
  "Constructs an RFC 5766 Allocate Success Response embedding XOR-RELAYED-ADDRESS,
   LIFETIME, and XOR-MAPPED-ADDRESS."
  [tx-id username realm password ^InetSocketAddress relayed-addr ^InetSocketAddress mapped-addr lifetime]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        xor-relayed (encode-xor-address relayed-addr stun/magic-cookie)
        xor-mapped (encode-xor-address mapped-addr stun/magic-cookie)]
    (put-u16 buf METHOD_ALLOCATE_RESPONSE)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    ;; XOR-RELAYED-ADDRESS
    (put-u16 buf ATTR_XOR_RELAYED_ADDRESS)
    (put-u16 buf 8)
    (.put buf xor-relayed)
    ;; LIFETIME
    (append-attr-u32 buf ATTR_LIFETIME (long lifetime))
    ;; XOR-MAPPED-ADDRESS
    (put-u16 buf stun/ATTR_XOR_MAPPED_ADDRESS)
    (put-u16 buf 8)
    (.put buf xor-mapped)
    (let [key (compute-long-term-key username realm password)]
      (finalize-turn-message buf key))))

(defn make-create-permission-success-response
  "Constructs an RFC 5766 CreatePermission Success Response."
  [tx-id username realm password]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)]
    (put-u16 buf METHOD_CREATE_PERMISSION_RESPONSE)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    (let [key (compute-long-term-key username realm password)]
      (finalize-turn-message buf key))))

(defn make-channel-bind-success-response
  "Constructs an RFC 5766 ChannelBind Success Response."
  [tx-id username realm password]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)]
    (put-u16 buf METHOD_CHANNEL_BIND_RESPONSE)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    (let [key (compute-long-term-key username realm password)]
      (finalize-turn-message buf key))))

(defn make-refresh-success-response
  "Constructs an RFC 5766 Refresh Success Response embedding LIFETIME and MESSAGE-INTEGRITY."
  [tx-id username realm password lifetime]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)]
    (put-u16 buf METHOD_REFRESH_RESPONSE)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    (append-attr-u32 buf ATTR_LIFETIME (long lifetime))
    (let [key (when (and username realm password)
                (compute-long-term-key username realm password))]
      (finalize-turn-message buf key))))

(defn make-turn-error-response
  "Constructs an RFC 5766 TURN Error Response for the given error method (e.g., METHOD_ALLOCATE_ERROR) and error-code."
  [method-error tx-id error-code & [{:keys [realm nonce]}]]
  (let [buf (ByteBuffer/allocate 1024)
        _ (.order buf ByteOrder/BIG_ENDIAN)
        cls (quot (int error-code) 100)
        num (mod (int error-code) 100)]
    (put-u16 buf method-error)
    (put-u16 buf 0)
    (.putInt buf stun/magic-cookie)
    (.put buf tx-id)
    (put-u16 buf stun/ATTR_ERROR_CODE)
    (put-u16 buf 4)
    (.put buf (byte 0))
    (.put buf (byte 0))
    (.put buf (byte cls))
    (.put buf (byte num))
    (when realm (append-attr-string buf ATTR_REALM realm))
    (when nonce (append-attr-string buf ATTR_NONCE nonce))
    (finalize-turn-message buf nil)))

;; -----------------------------------------------------------------------------
;; Response Parser & Dispatcher
;; -----------------------------------------------------------------------------

(defn parse-turn-packet
  "Parses an incoming byte buffer into a structured TURN packet map or ChannelData frame."
  [^ByteBuffer buf]
  (try
    (if (channel-data? buf)
      {:type :channel-data
       :channel-data (decode-channel-data buf)}
      (when (>= (.remaining buf) 20)
        (let [start (.position buf)
              _ (.order buf ByteOrder/BIG_ENDIAN)
              msg-type (get-u16 buf)
              msg-len (get-u16 buf)
              cookie (.getInt buf)
              tx-id (byte-array 12)
              _ (.get buf tx-id)
              parsed (do (.position buf start) (stun/parse-packet buf))
              attrs (:attributes parsed)
              realm-bytes (get attrs ATTR_REALM)
              realm (when realm-bytes (String. ^bytes realm-bytes "UTF-8"))
              nonce-bytes (get attrs ATTR_NONCE)
              nonce (when nonce-bytes (String. ^bytes nonce-bytes "UTF-8"))
              lifetime-bytes (get attrs ATTR_LIFETIME)
              lifetime (when (and lifetime-bytes (>= (alength ^bytes lifetime-bytes) 4))
                         (get-u32 (ByteBuffer/wrap lifetime-bytes)))
              mapped-bytes (get attrs stun/ATTR_XOR_MAPPED_ADDRESS)
              mapped (when mapped-bytes (decode-xor-address mapped-bytes cookie))
              relayed-bytes (get attrs ATTR_XOR_RELAYED_ADDRESS)
              relayed (when relayed-bytes (decode-xor-address relayed-bytes cookie))
              peer-bytes (get attrs ATTR_XOR_PEER_ADDRESS)
              peer (when peer-bytes (decode-xor-address peer-bytes cookie))
              channel-bytes (get attrs ATTR_CHANNEL_NUMBER)
              channel (when (and channel-bytes (>= (alength ^bytes channel-bytes) 2))
                        (get-u16 (ByteBuffer/wrap channel-bytes)))
              data-bytes (get attrs ATTR_DATA)
              err-bytes (get attrs stun/ATTR_ERROR_CODE)
              err-code (when (and err-bytes (>= (alength ^bytes err-bytes) 4))
                         (let [b (ByteBuffer/wrap err-bytes)
                               _ (.getShort b)
                               cls (bit-and (.get b) 0xff)
                               num (bit-and (.get b) 0xff)]
                           (+ (* cls 100) num)))]
          {:msg-type msg-type
           :msg-len msg-len
           :tx-id tx-id
           :realm realm
           :nonce nonce
           :lifetime lifetime
           :relayed-address relayed
           :mapped-address mapped
           :peer-address peer
           :channel-number channel
           :data data-bytes
           :error-code err-code
           :attributes attrs})))
    (catch Exception _
      nil)))

;; -----------------------------------------------------------------------------
;; Pure Sans-IO TURN Client State Machine
;; -----------------------------------------------------------------------------

(defn- tx-key [tx-id]
  (when tx-id
    (if (bytes? tx-id)
      (let [sb (StringBuilder.)]
        (doseq [b ^bytes tx-id]
          (.append sb (format "%02x" (bit-and (int b) 0xff))))
        (.toString sb))
      (str tx-id))))

(defn- peer-ip [peer-addr]
  (cond
    (instance? InetSocketAddress peer-addr) (.getHostString ^InetSocketAddress peer-addr)
    (string? peer-addr) (first (str/split (str peer-addr) #":"))
    :else (str peer-addr)))

(defn- peer-permitted? [permissions peer-addr]
  (let [ip (peer-ip peer-addr)]
    (boolean (or (contains? permissions peer-addr)
                 (contains? permissions ip)
                 (contains? permissions (str peer-addr))))))

(defn verify-turn-message-integrity
  "Verifies RFC 5389 §15.4 / RFC 5766 MESSAGE-INTEGRITY attribute on a TURN message buffer.
   Computes MD5(username:realm:password) long-term key and validates HMAC-SHA1.
   Returns true if valid, false otherwise."
  [buf-or-bytes username realm password]
  (try
    (let [^ByteBuffer buf (if (instance? ByteBuffer buf-or-bytes)
                            (.duplicate ^ByteBuffer buf-or-bytes)
                            (ByteBuffer/wrap ^bytes buf-or-bytes))
          _ (.order buf ByteOrder/BIG_ENDIAN)
          start-pos (.position buf)
          _ (.getShort buf) ;; msg-type
          msg-len (bit-and (.getShort buf) 0xffff)
          key (compute-long-term-key username realm password)
          packet-end (min (.limit buf) (+ start-pos 20 msg-len))]
      (.position buf (+ start-pos 20))
      (loop [mi-offset nil
             received-hmac nil]
        (if (or mi-offset (>= (.position buf) packet-end))
          (if (and mi-offset received-hmac)
            (let [data-to-sign (byte-array (- mi-offset start-pos))]
              (.position buf start-pos)
              (.get buf data-to-sign)
              (let [len-for-hmac (unchecked-short (+ (- mi-offset start-pos 20) 24))]
                (aset data-to-sign 2 (unchecked-byte (bit-shift-right len-for-hmac 8)))
                (aset data-to-sign 3 (unchecked-byte (bit-and len-for-hmac 0xff)))
                (let [calculated-hmac (compute-hmac-sha1 key data-to-sign)]
                  (java.util.Arrays/equals ^bytes calculated-hmac ^bytes received-hmac))))
            false)
          (let [attr-type (get-u16 buf)
                attr-len (get-u16 buf)
                padding (mod attr-len 4)
                pad-len (if (and (> padding 0) (< padding 4)) (- 4 padding) 0)]
            (if (= attr-type stun/ATTR_MESSAGE_INTEGRITY)
              (let [offset (- (.position buf) 4)
                    hmac (byte-array 20)]
                (.get buf hmac)
                (recur offset hmac))
              (do
                (.position buf (+ (.position buf) attr-len pad-len))
                (recur nil nil)))))))
    (catch Exception _
      false)))

(defn init-turn-client
  "Initializes pure Sans-IO TURN client state map."
  [opts]
  {:state :idle
   :username (:username opts)
   :password (:password opts)
   :realm (:realm opts)
   :nonce (:nonce opts)
   :server-addr (or (:server-addr opts)
                    (when (:server-host opts)
                      {:ip (:server-host opts) :port (int (or (:server-port opts) 3478))}))
   :lifetime (long (or (:lifetime opts) 600))
   :allocated-at-ms nil
   :expires-at-ms nil
   :refresh-at-ms nil
   :auth-retries 0
   :max-auth-retries (long (or (:max-auth-retries opts) 1))
   :next-channel-number MIN_CHANNEL_NUMBER
   :relayed-address nil
   :mapped-address nil
   :permissions #{}
   :channels {}
   :peer->channel {}
   :pending-tx {}
   :dropped-frames 0
   :last-error nil})

(defn start-allocation
  "Initiates TURN allocation, returning {:new-state ... :network-out [...] :events [...]}."
  [client-state & [opts]]
  (let [tx-id (let [t (byte-array 12)] (.nextBytes secure-rand t) t)
        tx-k (tx-key tx-id)
        alloc-req (make-allocate-request (:username client-state)
                                         (:realm client-state)
                                         (:password client-state)
                                         (:nonce client-state)
                                         (assoc opts :tx-id tx-id :lifetime (:lifetime client-state)))
        new-state (-> client-state
                      (assoc :state (if (:nonce client-state) :allocating-authenticated :allocating))
                      (assoc-in [:pending-tx tx-k] {:action :allocate :opts opts}))]
    {:new-state new-state
     :network-out [alloc-req]
     :events []}))

(defn request-permission
  "Constructs CreatePermission request and records pending permission in client state."
  [client-state peer-addr & [opts]]
  (let [tx-id (let [t (byte-array 12)] (.nextBytes secure-rand t) t)
        tx-k (tx-key tx-id)
        req (make-create-permission-request (:username client-state)
                                            (:realm client-state)
                                            (:password client-state)
                                            (:nonce client-state)
                                            peer-addr
                                            (assoc opts :tx-id tx-id))
        new-state (assoc-in client-state [:pending-tx tx-k] {:action :create-permission :peer-addr peer-addr})]
    {:new-state new-state
     :network-out [req]
     :events []}))

(defn request-channel-bind
  "Constructs ChannelBind request and records pending channel bind in client state."
  [client-state channel-number peer-addr & [opts]]
  (when-not (and (>= channel-number MIN_CHANNEL_NUMBER) (<= channel-number MAX_CHANNEL_NUMBER))
    (throw (ex-info "Invalid channel number (must be 0x4000..0x7FFF)" {:channel-number channel-number})))
  (let [tx-id (let [t (byte-array 12)] (.nextBytes secure-rand t) t)
        tx-k (tx-key tx-id)
        req (make-channel-bind-request (:username client-state)
                                       (:realm client-state)
                                       (:password client-state)
                                       (:nonce client-state)
                                       channel-number
                                       peer-addr
                                       (assoc opts :tx-id tx-id))
        new-state (assoc-in client-state [:pending-tx tx-k] {:action :channel-bind
                                                             :channel-number channel-number
                                                             :peer-addr peer-addr})]
    {:new-state new-state
     :network-out [req]
     :events []}))

(defn request-refresh
  "Constructs Refresh request to extend or terminate allocation."
  [client-state lifetime & [opts]]
  (let [tx-id (let [t (byte-array 12)] (.nextBytes secure-rand t) t)
        tx-k (tx-key tx-id)
        now-ms (long (or (:now-ms opts) (System/currentTimeMillis)))
        req (make-refresh-request (:username client-state)
                                  (:realm client-state)
                                  (:password client-state)
                                  (:nonce client-state)
                                  lifetime
                                  (assoc opts :tx-id tx-id))
        new-state (assoc-in client-state [:pending-tx tx-k] {:action :refresh
                                                             :lifetime lifetime
                                                             :sent-at-ms now-ms})]
    {:new-state new-state
     :network-out [req]
     :events []}))

(defn send-via-turn
  "Encapsulates application payload for peer-addr.
   Fails closed with {:ok? false :error :no-permission} if peer-addr not in permissions.
   Frames as ChannelData if bound channel exists, else Send Indication."
  [client-state peer-addr payload-bytes]
  (let [ip (peer-ip peer-addr)
        permitted? (peer-permitted? (:permissions client-state) peer-addr)]
    (if-not (and (#{:allocated :channel-bound} (:state client-state)) permitted?)
      {:ok? false :error :no-permission}
      (let [ch (get-in client-state [:peer->channel (str peer-addr)]
                       (get-in client-state [:peer->channel ip]))
            frame (if ch
                    (encode-channel-data ch payload-bytes)
                    (make-send-indication peer-addr payload-bytes))]
        {:ok? true :network-out [frame]}))))

(defn- normalize-peer-sock-addr ^InetSocketAddress [peer-addr]
  (cond
    (instance? InetSocketAddress peer-addr) peer-addr
    (and (map? peer-addr) (:ip peer-addr) (:port peer-addr))
    (InetSocketAddress. ^String (str (:ip peer-addr)) (int (:port peer-addr)))
    (and (string? peer-addr) (str/includes? peer-addr ":"))
    (let [[ip port] (str/split peer-addr #":")]
      (InetSocketAddress. ^String ip (Integer/parseInt port)))
    :else nil))

(defn ensure-peer-relay
  "Ensures CreatePermission and ChannelBind are requested for `peer-addr` when TURN allocation is active."
  [client-state peer-addr]
  (let [sock-addr (normalize-peer-sock-addr peer-addr)]
    (if-not (and sock-addr (#{:allocated :channel-bound} (:state client-state)))
      {:new-state client-state :network-out [] :events []}
      (let [ip (peer-ip sock-addr)
            peer-str (str sock-addr)
            permitted? (peer-permitted? (:permissions client-state) sock-addr)
            pending-perm? (some #(and (= (:action %) :create-permission)
                                      (= (peer-ip (:peer-addr %)) ip))
                                (vals (:pending-tx client-state)))
            bound-ch (or (get-in client-state [:peer->channel peer-str])
                         (get-in client-state [:peer->channel ip]))
            pending-bind? (some #(and (= (:action %) :channel-bind)
                                      (= (peer-ip (:peer-addr %)) ip))
                                (vals (:pending-tx client-state)))
            perm-res (if (or permitted? pending-perm?)
                       {:new-state client-state :network-out [] :events []}
                       (request-permission client-state sock-addr))
            st1 (:new-state perm-res)
            bind-res (if (or bound-ch pending-bind?)
                       {:new-state st1 :network-out [] :events []}
                       (let [ch (long (or (:next-channel-number st1) MIN_CHANNEL_NUMBER))]
                         (if (<= ch MAX_CHANNEL_NUMBER)
                           (let [r (request-channel-bind (assoc st1 :next-channel-number (inc ch)) ch sock-addr)]
                             r)
                           {:new-state st1 :network-out [] :events []})))]
        {:new-state (:new-state bind-res)
         :network-out (into (vec (:network-out perm-res)) (:network-out bind-res))
         :events (into (vec (:events perm-res)) (:events bind-res))}))))

(defn check-turn-expiry
  "Checks whether the TURN allocation needs a refresh or has expired at `now-ms`.
   Emits a Refresh Request when `now-ms >= :refresh-at-ms`, retrying if an in-flight refresh
   has exceeded `:refresh-rto-ms` (default 5000ms), or transitions to `:expired` when `now-ms >= :expires-at-ms`."
  [client-state now-ms]
  (let [now (long (or now-ms (System/currentTimeMillis)))]
    (if-not (#{:allocated :channel-bound} (:state client-state))
      {:new-state client-state :network-out [] :events []}
      (let [exp-at (:expires-at-ms client-state)
            ref-at (:refresh-at-ms client-state)
            refresh-rto-ms (long (or (:refresh-rto-ms client-state) 5000))
            stale-refresh-keys (keep (fn [[k v]]
                                       (when (and (= (:action v) :refresh)
                                                  (>= (- now (long (or (:sent-at-ms v) 0))) refresh-rto-ms))
                                         k))
                                     (:pending-tx client-state))
            cleaned-state (if (seq stale-refresh-keys)
                            (update client-state :pending-tx #(apply dissoc % stale-refresh-keys))
                            client-state)
            pending-refresh? (some #(= (:action %) :refresh) (vals (:pending-tx cleaned-state)))]
        (cond
          (and exp-at (>= now (long exp-at)))
          {:new-state (-> cleaned-state
                          (assoc :state :expired
                                 :last-error :allocation-expired
                                 :permissions #{}
                                 :channels {}
                                 :peer->channel {}))
           :network-out []
           :events [{:type :turn-expired :expires-at-ms exp-at}]}

          (and ref-at (>= now (long ref-at)) (not pending-refresh?))
          (let [lt (long (or (:lifetime cleaned-state) 600))
                res (request-refresh cleaned-state lt {:now-ms now})]
            (update res :events conj {:type :turn-refresh-scheduled :lifetime lt}))

          :else
          {:new-state cleaned-state :network-out [] :events []})))))

(defn step-turn-client
  "Pure state transition step for TURN client processing inbound network packet."
  [client-state packet-buf-or-bytes & [now-ms]]
  (let [now (long (or now-ms (System/currentTimeMillis)))]
    (if (channel-data? packet-buf-or-bytes)
      (let [{:keys [channel-number data]} (decode-channel-data packet-buf-or-bytes)
            peer-addr (get-in client-state [:channels channel-number])]
        (if (and peer-addr (peer-permitted? (:permissions client-state) peer-addr))
          {:new-state client-state
           :network-out []
           :events [{:type :turn-data :peer-address peer-addr :channel-number channel-number :data data}]}
          {:new-state (update client-state :dropped-frames (fnil inc 0))
           :network-out []
           :events [{:type :turn-drop :reason :unbound-channel :channel-number channel-number}]}))
      (let [^ByteBuffer buf (if (instance? ByteBuffer packet-buf-or-bytes)
                              (.duplicate ^ByteBuffer packet-buf-or-bytes)
                              (ByteBuffer/wrap ^bytes packet-buf-or-bytes))
            parsed (parse-turn-packet buf)]
        (if (nil? parsed)
          {:new-state (update client-state :dropped-frames (fnil inc 0))
           :network-out []
           :events [{:type :turn-drop :reason :parse-failed}]}
          (let [tx-k (tx-key (:tx-id parsed))
                pending (get-in client-state [:pending-tx tx-k])
                new-client-state (update client-state :pending-tx dissoc tx-k)
                msg-type (:msg-type parsed)]
            (cond
              ;; 401 Unauthorized / 438 Stale Nonce Challenge on Allocate, Refresh, CreatePermission, or ChannelBind
              ;; (bounded retry up to :max-auth-retries)
              (and (#{METHOD_ALLOCATE_ERROR
                      METHOD_REFRESH_ERROR
                      METHOD_CREATE_PERMISSION_ERROR
                      METHOD_CHANNEL_BIND_ERROR} msg-type)
                   (#{401 438} (:error-code parsed))
                   (:realm parsed)
                   (:nonce parsed))
              (let [retries (long (or (:auth-retries client-state) 0))
                    max-retries (long (or (:max-auth-retries client-state) 1))
                    act (:action pending)]
                (if (and (#{:allocate :allocate-auth :refresh :create-permission :channel-bind nil} act)
                         (< retries max-retries))
                  (let [realm (:realm parsed)
                        nonce (:nonce parsed)
                        retry-tx-id (let [t (byte-array 12)] (.nextBytes secure-rand t) t)
                        retry-tx-k (tx-key retry-tx-id)
                        user (:username client-state)
                        pass (:password client-state)
                        [retry-pkt retry-pending next-st]
                        (case act
                          :refresh
                          (let [lt (or (:lifetime pending) (:lifetime client-state) 600)]
                            [(make-refresh-request user realm pass nonce lt {:tx-id retry-tx-id})
                             {:action :refresh :lifetime lt :sent-at-ms now}
                             (:state client-state)])

                          :create-permission
                          (let [pa (:peer-addr pending)]
                            [(make-create-permission-request user realm pass nonce pa {:tx-id retry-tx-id})
                             {:action :create-permission :peer-addr pa}
                             (:state client-state)])

                          :channel-bind
                          (let [ch (:channel-number pending)
                                pa (:peer-addr pending)]
                            [(make-channel-bind-request user realm pass nonce ch pa {:tx-id retry-tx-id})
                             {:action :channel-bind :channel-number ch :peer-addr pa}
                             (:state client-state)])

                          ;; default: :allocate / :allocate-auth / nil
                          [(make-allocate-request user realm pass nonce {:tx-id retry-tx-id :lifetime (:lifetime client-state)})
                           {:action :allocate-auth}
                           :allocating-authenticated])]
                    {:new-state (-> new-client-state
                                    (assoc :state next-st
                                           :realm realm
                                           :nonce nonce
                                           :auth-retries (inc retries))
                                    (assoc-in [:pending-tx retry-tx-k] retry-pending))
                     :network-out [retry-pkt]
                     :events [{:type :turn-challenge-retry :realm realm :nonce nonce :action (or act :allocate)}]})
                  {:new-state (assoc new-client-state
                                     :state :error
                                     :last-error :turn-auth-retry-exhausted)
                   :network-out []
                   :events [{:type :turn-error
                             :reason :turn-auth-retry-exhausted
                             :error-code (:error-code parsed)
                             :msg-type msg-type}]}))

              ;; Non-401 (or unretryable) TURN Error Responses
              ;; Allocation and Refresh errors are fatal to the allocation; per-peer Permission/ChannelBind errors preserve the allocation.
              (#{METHOD_ALLOCATE_ERROR
                 METHOD_REFRESH_ERROR
                 METHOD_CREATE_PERMISSION_ERROR
                 METHOD_CHANNEL_BIND_ERROR} msg-type)
              (let [err-code (:error-code parsed)
                    action (:action pending)
                    fatal? (#{METHOD_ALLOCATE_ERROR METHOD_REFRESH_ERROR} msg-type)]
                {:new-state (cond-> (assoc new-client-state
                                           :last-error {:error-code err-code :msg-type msg-type :action action})
                              fatal? (assoc :state :error))
                 :network-out []
                 :events [{:type :turn-error
                           :reason :server-error
                           :error-code err-code
                           :msg-type msg-type
                           :action action}]})

              ;; Allocate Success
              (= msg-type METHOD_ALLOCATE_RESPONSE)
              (let [valid-mi? (if (and (:username client-state) (:realm client-state) (:password client-state))
                                (verify-turn-message-integrity packet-buf-or-bytes (:username client-state) (:realm client-state) (:password client-state))
                                true)]
                (if-not valid-mi?
                  {:new-state (assoc new-client-state :state :error :last-error :turn-auth-failed)
                   :network-out []
                   :events [{:type :turn-auth-failed :reason :invalid-message-integrity}]}
                  (let [lt (long (or (:lifetime parsed) (:lifetime client-state) 600))
                        exp-at (+ now (* lt 1000))
                        ref-at (+ now (* (long (* lt 0.8)) 1000))
                        st (assoc new-client-state
                                  :state :allocated
                                  :auth-retries 0
                                  :relayed-address (:relayed-address parsed)
                                  :mapped-address (:mapped-address parsed)
                                  :lifetime lt
                                  :allocated-at-ms now
                                  :expires-at-ms exp-at
                                  :refresh-at-ms ref-at)]
                    {:new-state st
                     :network-out []
                     :events [{:type :turn-allocated
                               :relayed-address (:relayed-address parsed)
                               :lifetime lt
                               :expires-at-ms exp-at
                               :refresh-at-ms ref-at}]})))

              ;; CreatePermission Success
              (= msg-type METHOD_CREATE_PERMISSION_RESPONSE)
              (let [valid-mi? (if (and (:username client-state) (:realm client-state) (:password client-state))
                                (verify-turn-message-integrity packet-buf-or-bytes (:username client-state) (:realm client-state) (:password client-state))
                                true)]
                (if-not valid-mi?
                  {:new-state (assoc new-client-state :state :error :last-error :turn-auth-failed)
                   :network-out []
                   :events [{:type :turn-auth-failed :reason :invalid-message-integrity}]}
                  (let [peer-addr (:peer-addr pending)
                        ip (when peer-addr (peer-ip peer-addr))
                        st (-> new-client-state
                               (assoc :auth-retries 0)
                               (update :permissions (fnil conj #{}) (or ip (str peer-addr))))]
                    {:new-state st
                     :network-out []
                     :events [{:type :turn-permission-created :peer-address peer-addr}]})))

              ;; ChannelBind Success
              (= msg-type METHOD_CHANNEL_BIND_RESPONSE)
              (let [valid-mi? (if (and (:username client-state) (:realm client-state) (:password client-state))
                                (verify-turn-message-integrity packet-buf-or-bytes (:username client-state) (:realm client-state) (:password client-state))
                                true)]
                (if-not valid-mi?
                  {:new-state (assoc new-client-state :state :error :last-error :turn-auth-failed)
                   :network-out []
                   :events [{:type :turn-auth-failed :reason :invalid-message-integrity}]}
                  (let [ch (:channel-number pending)
                        peer-addr (:peer-addr pending)
                        ip (when peer-addr (peer-ip peer-addr))
                        st (-> new-client-state
                               (assoc :state :channel-bound :auth-retries 0)
                               (assoc-in [:channels ch] peer-addr)
                               (assoc-in [:peer->channel (str peer-addr)] ch)
                               (cond-> ip (assoc-in [:peer->channel ip] ch))
                               (update :permissions (fnil conj #{}) (or ip (str peer-addr))))]
                    {:new-state st
                     :network-out []
                     :events [{:type :turn-channel-bound :channel-number ch :peer-address peer-addr}]})))

              ;; Refresh Success
              (= msg-type METHOD_REFRESH_RESPONSE)
              (let [valid-mi? (if (and (:username client-state) (:realm client-state) (:password client-state))
                                (verify-turn-message-integrity packet-buf-or-bytes (:username client-state) (:realm client-state) (:password client-state))
                                true)]
                (if-not valid-mi?
                  {:new-state (assoc new-client-state :state :error :last-error :turn-auth-failed)
                   :network-out []
                   :events [{:type :turn-auth-failed :reason :invalid-message-integrity}]}
                  (let [lt (long (or (:lifetime parsed) 0))
                        exp-at (if (zero? lt) now (+ now (* lt 1000)))
                        ref-at (if (zero? lt) nil (+ now (* (long (* lt 0.8)) 1000)))
                        st (assoc new-client-state
                                  :auth-retries 0
                                  :lifetime lt
                                  :allocated-at-ms (if (zero? lt) (:allocated-at-ms new-client-state) now)
                                  :expires-at-ms exp-at
                                  :refresh-at-ms ref-at
                                  :state (if (zero? lt) :closed (:state new-client-state)))]
                    {:new-state st
                     :network-out []
                     :events [{:type (if (zero? lt) :turn-closed :turn-refreshed)
                               :lifetime lt
                               :expires-at-ms exp-at
                               :refresh-at-ms ref-at}]})))

              ;; Data Indication
              (= msg-type METHOD_DATA_INDICATION)
              (let [peer-addr (:peer-address parsed)
                    permitted? (peer-permitted? (:permissions client-state) peer-addr)]
                (if permitted?
                  {:new-state new-client-state
                   :network-out []
                   :events [{:type :turn-data :peer-address peer-addr :data (:data parsed)}]}
                  {:new-state (update new-client-state :dropped-frames (fnil inc 0))
                   :network-out []
                   :events [{:type :turn-drop :reason :unauthorized-peer :peer-address peer-addr}]}))

              :else
              {:new-state (update new-client-state :dropped-frames (fnil inc 0))
               :network-out []
               :events [{:type :turn-drop :reason :unexpected-msg-type :msg-type msg-type}]})))))))
