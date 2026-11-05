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
  (let [buf (if (instance? ByteBuffer buf-or-bytes)
              (.duplicate ^ByteBuffer buf-or-bytes)
              (ByteBuffer/wrap ^bytes buf-or-bytes))]
    (when (>= (.remaining buf) 4)
      (.order buf ByteOrder/BIG_ENDIAN)
      (let [ch (bit-and (.getShort buf) 0xffff)]
        (and (>= ch MIN_CHANNEL_NUMBER) (<= ch MAX_CHANNEL_NUMBER))))))

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
  (let [buf (if (instance? ByteBuffer buf-or-bytes)
              (.duplicate ^ByteBuffer buf-or-bytes)
              (ByteBuffer/wrap ^bytes buf-or-bytes))]
    (.order buf ByteOrder/BIG_ENDIAN)
    (let [ch (get-u16 buf)
          len (get-u16 buf)]
      (when-not (and (>= ch MIN_CHANNEL_NUMBER) (<= ch MAX_CHANNEL_NUMBER))
        (throw (ex-info "Invalid channel number in ChannelData" {:channel ch})))
      (let [data (byte-array len)]
        (.get buf data)
        {:channel-number ch
         :data data
         :length len}))))

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
    (when (and username realm password nonce)
      (append-attr-string buf stun/ATTR_USERNAME username)
      (append-attr-string buf ATTR_REALM realm)
      (append-attr-string buf ATTR_NONCE nonce)
      (let [key (compute-long-term-key username realm password)]
        (finalize-turn-message buf key)))))

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
    (when (and username realm password nonce)
      (append-attr-string buf stun/ATTR_USERNAME username)
      (append-attr-string buf ATTR_REALM realm)
      (append-attr-string buf ATTR_NONCE nonce)
      (let [key (compute-long-term-key username realm password)]
        (finalize-turn-message buf key)))))

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
    (when (and username realm password nonce)
      (append-attr-string buf stun/ATTR_USERNAME username)
      (append-attr-string buf ATTR_REALM realm)
      (append-attr-string buf ATTR_NONCE nonce)
      (let [key (compute-long-term-key username realm password)]
        (finalize-turn-message buf key)))))

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

;; -----------------------------------------------------------------------------
;; Response Parser & Dispatcher
;; -----------------------------------------------------------------------------

(defn parse-turn-packet
  "Parses an incoming byte buffer into a structured TURN packet map or ChannelData frame."
  [^ByteBuffer buf]
  (if (channel-data? buf)
    {:type :channel-data
     :channel-data (decode-channel-data buf)}
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
       :peer-address peer
       :channel-number channel
       :data data-bytes
       :error-code err-code
       :attributes attrs})))
