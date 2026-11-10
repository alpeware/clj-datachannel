(ns datachannel.stun
  "Cross-platform RFC 5389 / RFC 5245 / RFC 8445 STUN message encoder, decoder, and ICE Binding handler."
  (:require [clojure.string :as str]
            [datachannel.buffer :as b]))

(def magic-cookie
  "RFC 5389 compliant STUN magic cookie (0x2112A442) indicating protocol version 2."
  0x2112A442)

;; Attributes
(def ATTR_USERNAME
  "RFC 5389 STUN attribute code for USERNAME (0x0006)."
  0x0006)
(def ATTR_MESSAGE_INTEGRITY
  "RFC 5389 STUN attribute code for MESSAGE-INTEGRITY (0x0008)."
  0x0008)
(def ATTR_ERROR_CODE
  "RFC 5389 STUN attribute code for ERROR-CODE (0x0009)."
  0x0009)
(def ATTR_UNKNOWN_ATTRIBUTES
  "RFC 5389 STUN attribute code for UNKNOWN-ATTRIBUTES (0x000A)."
  0x000A)
(def ATTR_XOR_MAPPED_ADDRESS
  "RFC 5389 STUN attribute code for XOR-MAPPED-ADDRESS (0x0020)."
  0x0020)
(def ATTR_PRIORITY
  "RFC 5245 ICE STUN attribute code for PRIORITY (0x0024)."
  0x0024)
(def ATTR_USE_CANDIDATE
  "RFC 5245 ICE STUN attribute code for USE-CANDIDATE (0x0025)."
  0x0025)
(def ATTR_FINGERPRINT
  "RFC 5389 STUN attribute code for FINGERPRINT (0x8028)."
  0x8028)
(def ATTR_ICE_CONTROLLED
  "RFC 5245 ICE STUN attribute code for ICE-CONTROLLED (0x8029)."
  0x8029)
(def ATTR_ICE_CONTROLLING
  "RFC 5245 ICE STUN attribute code for ICE-CONTROLLING (0x802A)."
  0x802A)

(def DEFAULT_PRIORITY
  "A default integer priority value provided for ICE agent candidate comparisons."
  1853824767)

(defn- put-unsigned-short [buf val]
  (b/buf-put-u16! buf val))

(defn- get-unsigned-short [buf]
  (b/buf-get-u16! buf))

(defn- get-unsigned-byte [buf]
  (b/buf-get-u8! buf))

(defn- compute-hmac-sha1 [key data]
  (b/hmac-sha1 key data))

(defn- compute-crc32 [data]
  (bit-xor (b/crc32-ieee data) 0x5354554e))

(defn- magic-cookie-bytes []
  (let [cb (b/allocate-buffer 4)]
    (b/buf-put-u32! cb magic-cookie)
    (b/buf-flip! cb)
    (b/buf->bytes cb)))

(defn make-binding-request
  "Constructs an RFC 5389 STUN Binding Request packet containing USERNAME, PRIORITY,
   ICE-CONTROLLED or ICE-CONTROLLING, optional USE-CANDIDATE,
   MESSAGE-INTEGRITY (signed using HMAC-SHA1 and `remote-pwd`), and a CRC32 FINGERPRINT."
  ([local-ufrag remote-ufrag remote-pwd]
   (make-binding-request local-ufrag remote-ufrag remote-pwd nil))
  ([local-ufrag remote-ufrag remote-pwd opts]
   (let [buf (b/allocate-buffer 1024)
         _ (b/buf-set-order! buf :big-endian)
         tx-id (or (:tx-id opts) (b/random-bytes 12))]
     ;; Header
     (put-unsigned-short buf 0x0001) ;; Binding Request
     (put-unsigned-short buf 0) ;; Length placeholder
     (b/buf-put-u32! buf magic-cookie)
     (b/buf-put-bytes! buf tx-id)

     ;; USERNAME
     (let [username (str remote-ufrag ":" local-ufrag)
           u-bytes (b/utf8->bytes username)
           len (b/blength u-bytes)
           padding (let [r (mod len 4)] (if (zero? r) 0 (- 4 r)))]
       (put-unsigned-short buf ATTR_USERNAME)
       (put-unsigned-short buf len)
       (b/buf-put-bytes! buf u-bytes)
       (dotimes [_ padding] (b/buf-put-u8! buf 0)))

     ;; PRIORITY
     (let [p (long (or (:priority opts) DEFAULT_PRIORITY))]
       (put-unsigned-short buf ATTR_PRIORITY)
       (put-unsigned-short buf 4)
       (b/buf-put-u32! buf p))

     ;; ICE-CONTROLLING or ICE-CONTROLLED
     (let [role (or (:role opts) :controlled)
           tb (long (or (:tie-breaker opts) (b/random-u64)))]
       (if (= role :controlling)
         (do
           (put-unsigned-short buf ATTR_ICE_CONTROLLING)
           (put-unsigned-short buf 8)
           (b/buf-put-i64! buf tb))
         (do
           (put-unsigned-short buf ATTR_ICE_CONTROLLED)
           (put-unsigned-short buf 8)
           (b/buf-put-i64! buf tb))))

     ;; USE-CANDIDATE
     (when (:use-candidate? opts)
       (put-unsigned-short buf ATTR_USE_CANDIDATE)
       (put-unsigned-short buf 0))

     ;; Update Header Length for MI
     (let [len-before-mi (- (b/buf-position buf) 20)
           len-with-mi (+ len-before-mi 24)]
       (b/buf-put-u16-at! buf 2 len-with-mi))

     ;; MESSAGE-INTEGRITY
     (let [len-to-sign (b/buf-position buf)
           data-to-sign (b/alloc-bytes len-to-sign)]
       (b/buf-set-position! buf 0)
       (b/buf-get-bytes! buf data-to-sign)
       (b/buf-set-position! buf len-to-sign)
       (let [hmac (compute-hmac-sha1 remote-pwd data-to-sign)]
         (put-unsigned-short buf ATTR_MESSAGE_INTEGRITY)
         (put-unsigned-short buf 20)
         (b/buf-put-bytes! buf hmac)))

     ;; FINGERPRINT
     (let [len-before-fp (- (b/buf-position buf) 20)
           total-len (+ len-before-fp 8)]
       (b/buf-put-u16-at! buf 2 total-len))

     (let [len-to-crc (b/buf-position buf)
           data-to-crc (b/alloc-bytes len-to-crc)]
       (b/buf-set-position! buf 0)
       (b/buf-get-bytes! buf data-to-crc)
       (b/buf-set-position! buf len-to-crc)
       (let [crc (compute-crc32 data-to-crc)]
         (put-unsigned-short buf ATTR_FINGERPRINT)
         (put-unsigned-short buf 4)
         (b/buf-put-u32! buf crc)))

     (b/buf-flip! buf)
     buf)))

(defn make-simple-binding-request
  "Constructs a minimal, unauthenticated STUN Binding Request lacking extensions or integrity checks."
  []
  (let [buf (b/allocate-buffer 1024)
        _ (b/buf-set-order! buf :big-endian)
        tx-id (b/random-bytes 12)]
    (put-unsigned-short buf 0x0001) ;; Binding Request
    (put-unsigned-short buf 0) ;; Length is 0
    (b/buf-put-u32! buf magic-cookie)
    (b/buf-put-bytes! buf tx-id)
    (b/buf-flip! buf)
    buf))

(defn decode-xor-mapped-address
  "Un-XORs the payload of an RFC 5389 XOR-MAPPED-ADDRESS attribute using the STUN `magic-cookie` and transactional ID, returning a map mapping `:family`, `:port`, and `:address`."
  [val-bytes cookie]
  (let [buf (b/wrap-buffer val-bytes)
        _ (b/buf-set-order! buf :big-endian)
        _ (get-unsigned-byte buf) ;; reserved
        family (get-unsigned-byte buf)
        port (get-unsigned-short buf)]
    (if (= family 0x01)
      (let [addr-bytes (b/alloc-bytes 4)]
        (b/buf-get-bytes! buf addr-bytes)
        (let [xport (bit-xor port (unsigned-bit-shift-right cookie 16))
              cookie-buf (b/allocate-buffer 4)
              _ (b/buf-put-u32! cookie-buf cookie)
              _ (b/buf-flip! cookie-buf)
              magic-bytes (b/buf->bytes cookie-buf)
              decoded-addr (b/alloc-bytes 4)]
          (dotimes [i 4]
            (b/bset-u8! decoded-addr i (bit-xor (b/bget-u8 addr-bytes i) (b/bget-u8 magic-bytes i))))
          {:family family
           :port xport
           :ip (b/ipv4-bytes->str decoded-addr)
           :address (b/make-inet-address decoded-addr)}))
      (throw (ex-info "Only IPv4 supported for now" {:family family})))))

(defn parse-packet
  "Reads an RFC 5389 STUN message byte stream, separating the header elements and extracting all TLV attributes into an unparsed map."
  [buf-or-bytes]
  (let [buf (if (b/binary-buffer? buf-or-bytes) buf-or-bytes (b/wrap-buffer buf-or-bytes))
        _ (b/buf-set-order! buf :big-endian)
        msg-type (get-unsigned-short buf)
        msg-len (get-unsigned-short buf)
        cookie (b/buf-get-s32! buf)
        tx-id (b/alloc-bytes 12)]
    (b/buf-get-bytes! buf tx-id)
    (loop [attrs {}]
      (if (< (b/buf-position buf) (b/buf-limit buf))
        (let [attr-type (get-unsigned-short buf)
              attr-len (get-unsigned-short buf)
              val-bytes (b/alloc-bytes attr-len)
              _ (b/buf-get-bytes! buf val-bytes)
              padding (mod attr-len 4)
              _ (when (and (> padding 0) (< padding 4))
                  (let [pad-len (- 4 padding)]
                    (dotimes [_ pad-len] (b/buf-get-u8! buf))))]
          (recur (assoc attrs attr-type val-bytes)))
        {:type msg-type :length msg-len :cookie cookie :tx-id tx-id :attributes attrs}))))

(defn check-message-integrity
  "Validates the MESSAGE-INTEGRITY attribute of a STUN message."
  [buf start-pos msg-len password]
  (let [packet-end (min (b/buf-limit buf) (+ start-pos 20 msg-len))]
    (try
      (b/buf-set-position! buf (+ start-pos 20))
      (loop [mi-offset nil
             received-hmac nil]
        (if (or mi-offset (>= (b/buf-position buf) packet-end))
          (if (and mi-offset received-hmac)
            (let [data-to-sign (b/alloc-bytes (- mi-offset start-pos))]
              (b/buf-set-position! buf start-pos)
              (b/buf-get-bytes! buf data-to-sign)
              (let [len-for-hmac (bit-and (+ (- mi-offset start-pos 20) 24) 0xFFFF)]
                (b/bset-u8! data-to-sign 2 (unsigned-bit-shift-right len-for-hmac 8))
                (b/bset-u8! data-to-sign 3 (bit-and len-for-hmac 0xFF))
                (let [calculated-hmac (compute-hmac-sha1 password data-to-sign)]
                  (b/bytes= calculated-hmac received-hmac))))
            false)
          (let [attr-type (get-unsigned-short buf)
                attr-len (get-unsigned-short buf)
                padding (mod attr-len 4)
                pad-len (if (and (> padding 0) (< padding 4)) (- 4 padding) 0)]
            (if (= attr-type ATTR_MESSAGE_INTEGRITY)
              (let [offset (- (b/buf-position buf) 4)
                    hmac (b/alloc-bytes 20)]
                (b/buf-get-bytes! buf hmac)
                (recur offset hmac))
              (do
                (b/buf-set-position! buf (+ (b/buf-position buf) attr-len pad-len))
                (recur nil nil))))))
      (catch #?(:clj Exception :cljs :default) _
        false)
      (finally
        (b/buf-set-position! buf start-pos)))))

(defn make-binding-response
  "Constructs an RFC 5389 STUN Success Response mirroring the request's transaction ID, embedding the resolved `peer-addr` inside an XOR-MAPPED-ADDRESS attribute, and finalizing with MESSAGE-INTEGRITY and FINGERPRINT."
  [password tx-id peer-addr]
  (when-let [norm-peer (b/normalize-socket-addr peer-addr)]
    (let [resp-buf (b/allocate-buffer 1024)
          _ (b/buf-set-order! resp-buf :big-endian)]
      ;; Header
      (put-unsigned-short resp-buf 0x0101) ;; Success Response
      (put-unsigned-short resp-buf 0)
      (b/buf-put-u32! resp-buf magic-cookie)
      (b/buf-put-bytes! resp-buf tx-id)

      ;; XOR-MAPPED-ADDRESS
      (put-unsigned-short resp-buf ATTR_XOR_MAPPED_ADDRESS)
      (put-unsigned-short resp-buf 8)
      (b/buf-put-u8! resp-buf 0)
      (b/buf-put-u8! resp-buf 1)
      (put-unsigned-short resp-buf (bit-xor (:port norm-peer) (unsigned-bit-shift-right magic-cookie 16)))
      (let [addr-bytes (b/ipv4-str->bytes (:ip norm-peer))
            magic-bytes (magic-cookie-bytes)
            xor-addr (b/alloc-bytes 4)]
        (dotimes [i 4]
          (b/bset-u8! xor-addr i (bit-xor (b/bget-u8 addr-bytes i) (b/bget-u8 magic-bytes i))))
        (b/buf-put-bytes! resp-buf xor-addr))

      ;; MESSAGE-INTEGRITY
      (let [len-before-mi (- (b/buf-position resp-buf) 20)
            len-with-mi (+ len-before-mi 24)]
        (b/buf-put-u16-at! resp-buf 2 len-with-mi))
      (let [len-to-sign (b/buf-position resp-buf)
            data-to-sign (b/alloc-bytes len-to-sign)]
        (b/buf-set-position! resp-buf 0)
        (b/buf-get-bytes! resp-buf data-to-sign)
        (b/buf-set-position! resp-buf len-to-sign)
        (let [hmac (compute-hmac-sha1 password data-to-sign)]
          (put-unsigned-short resp-buf ATTR_MESSAGE_INTEGRITY)
          (put-unsigned-short resp-buf 20)
          (b/buf-put-bytes! resp-buf hmac)))

      ;; FINGERPRINT
      (let [len-before-fp (- (b/buf-position resp-buf) 20)
            total-len (+ len-before-fp 8)]
        (b/buf-put-u16-at! resp-buf 2 total-len))
      (let [len-to-crc (b/buf-position resp-buf)
            data-to-crc (b/alloc-bytes len-to-crc)]
        (b/buf-set-position! resp-buf 0)
        (b/buf-get-bytes! resp-buf data-to-crc)
        (b/buf-set-position! resp-buf len-to-crc)
        (let [crc (compute-crc32 data-to-crc)]
          (put-unsigned-short resp-buf ATTR_FINGERPRINT)
          (put-unsigned-short resp-buf 4)
          (b/buf-put-u32! resp-buf crc)))

      (b/buf-flip! resp-buf)
      resp-buf)))

(defn resolve-role-conflict
  "Resolves RFC 8445 §7.2.1.1 ICE role conflicts using tie-breaker comparisons.
   Returns {:conflict? bool :switched-role? bool :error-code int :new-role kw}."
  [local-role local-tie-breaker remote-controlling? remote-controlled? remote-tie-breaker]
  (cond
    (and (= local-role :controlling) remote-controlling?)
    (if (>= (b/compare-u64 (long (or local-tie-breaker 0)) (long (or remote-tie-breaker 0))) 0)
      {:conflict? true :error-code 487 :new-role :controlling}
      {:conflict? true :switched-role? true :new-role :controlled})

    (and (= local-role :controlled) remote-controlled?)
    (if (< (b/compare-u64 (long (or local-tie-breaker 0)) (long (or remote-tie-breaker 0))) 0)
      {:conflict? true :error-code 487 :new-role :controlled}
      {:conflict? true :switched-role? true :new-role :controlling})

    :else
    {:conflict? false :new-role local-role}))

(defn make-error-response
  "Constructs an RFC 5389 STUN Binding Error Response with ERROR-CODE, MESSAGE-INTEGRITY, and FINGERPRINT."
  [password tx-id error-code reason-phrase]
  (let [resp-buf (b/allocate-buffer 1024)
        _ (b/buf-set-order! resp-buf :big-endian)
        reason-bytes (b/utf8->bytes (or reason-phrase "Role Conflict"))
        r-len (b/blength reason-bytes)
        attr-len (+ 4 r-len)
        padding (let [r (mod r-len 4)] (if (zero? r) 0 (- 4 r)))]
    (put-unsigned-short resp-buf 0x0111) ;; Binding Error Response
    (put-unsigned-short resp-buf 0)
    (b/buf-put-u32! resp-buf magic-cookie)
    (b/buf-put-bytes! resp-buf tx-id)
    ;; ERROR-CODE
    (put-unsigned-short resp-buf ATTR_ERROR_CODE)
    (put-unsigned-short resp-buf attr-len)
    (b/buf-put-u8! resp-buf 0)
    (b/buf-put-u8! resp-buf 0)
    (b/buf-put-u8! resp-buf (quot error-code 100))
    (b/buf-put-u8! resp-buf (mod error-code 100))
    (b/buf-put-bytes! resp-buf reason-bytes)
    (dotimes [_ padding] (b/buf-put-u8! resp-buf 0))
    ;; MESSAGE-INTEGRITY
    (when (some? password)
      (let [len-before-mi (- (b/buf-position resp-buf) 20)
            total-len (+ len-before-mi 24)]
        (b/buf-put-u16-at! resp-buf 2 total-len))
      (let [len-to-sign (b/buf-position resp-buf)
            data-to-sign (b/alloc-bytes len-to-sign)]
        (b/buf-set-position! resp-buf 0)
        (b/buf-get-bytes! resp-buf data-to-sign)
        (b/buf-set-position! resp-buf len-to-sign)
        (let [hmac (compute-hmac-sha1 password data-to-sign)]
          (put-unsigned-short resp-buf ATTR_MESSAGE_INTEGRITY)
          (put-unsigned-short resp-buf 20)
          (b/buf-put-bytes! resp-buf hmac))))
    ;; FINGERPRINT
    (let [len-before-fp (- (b/buf-position resp-buf) 20)
          total-len (+ len-before-fp 8)]
      (b/buf-put-u16-at! resp-buf 2 total-len))
    (let [len-to-crc (b/buf-position resp-buf)
          data-to-crc (b/alloc-bytes len-to-crc)]
      (b/buf-set-position! resp-buf 0)
      (b/buf-get-bytes! resp-buf data-to-crc)
      (b/buf-set-position! resp-buf len-to-crc)
      (let [crc (compute-crc32 data-to-crc)]
        (put-unsigned-short resp-buf ATTR_FINGERPRINT)
        (put-unsigned-short resp-buf 4)
        (b/buf-put-u32! resp-buf crc)))
    (b/buf-flip! resp-buf)
    resp-buf))

(defn handle-packet
  "Decodes an incoming UDP datagram as STUN bytes. Dispatches ICE Binding Requests to yield a generated `response` if authenticated, and Binding Responses to map newly discovered `candidate` addresses."
  [buf-or-bytes peer-addr connection]
  (let [buf (if (b/binary-buffer? buf-or-bytes) buf-or-bytes (b/wrap-buffer buf-or-bytes))]
    (try
      (let [start-pos (b/buf-position buf)
            _ (b/buf-set-order! buf :big-endian)
            msg-type (get-unsigned-short buf)
            msg-len (get-unsigned-short buf)
            cookie (b/buf-get-s32! buf)
            tx-id (b/alloc-bytes 12)
            _ (b/buf-get-bytes! buf tx-id)
            res (cond
                  ;; Binding Request
                  (= msg-type 0x0001)
                  (if-let [password (:ice-pwd connection)]
                    (if (check-message-integrity buf start-pos msg-len password)
                      (do
                        (b/buf-set-position! buf start-pos)
                        (let [parsed (parse-packet buf)
                              attrs (:attributes parsed)
                              u-bytes (get attrs ATTR_USERNAME)
                              username-str (when u-bytes (b/bytes->utf8 u-bytes))
                              [target-ufrag caller-ufrag] (when (and username-str (str/includes? username-str ":"))
                                                            (str/split username-str #":" 2))
                              conn-ufrag (:ice-ufrag connection)
                              controlling-bytes (get attrs ATTR_ICE_CONTROLLING)
                              controlling-tb (when (and controlling-bytes (>= (b/blength controlling-bytes) 8))
                                               (b/buf-get-i64! (b/wrap-buffer controlling-bytes)))
                              controlled-bytes (get attrs ATTR_ICE_CONTROLLED)
                              controlled-tb (when (and controlled-bytes (>= (b/blength controlled-bytes) 8))
                                              (b/buf-get-i64! (b/wrap-buffer controlled-bytes)))
                              use-candidate? (contains? attrs ATTR_USE_CANDIDATE)
                              priority-bytes (get attrs ATTR_PRIORITY)
                              priority (when (and priority-bytes (>= (b/blength priority-bytes) 4))
                                         (b/buf-get-u32! (b/wrap-buffer priority-bytes)))
                              prflx-cand (when peer-addr (b/format-ip-port peer-addr))
                              local-role (:ice-role connection)
                              local-tb (:ice-tie-breaker connection)
                              remote-controlling? (some? controlling-tb)
                              remote-controlled? (some? controlled-tb)
                              remote-tb (or controlling-tb controlled-tb)
                              rc (if (and local-role (or remote-controlling? remote-controlled?))
                                   (resolve-role-conflict local-role local-tb remote-controlling? remote-controlled? remote-tb)
                                   {:conflict? false :new-role local-role})]
                          (if (and (string? conn-ufrag)
                                   (not (str/blank? conn-ufrag))
                                   (string? target-ufrag)
                                   (not (str/blank? target-ufrag))
                                   (not= target-ufrag conn-ufrag))
                            {}
                            (if (and (:conflict? rc) (= (:error-code rc) 487))
                              (cond-> {:response (make-error-response password tx-id 487 "Role Conflict")
                                       :role-conflict? true
                                       :error-code 487
                                       :new-role (:new-role rc)}
                                (and caller-ufrag (not (str/blank? caller-ufrag)))
                                (assoc :remote-ice-ufrag caller-ufrag :username username-str)
                                controlling-tb (assoc :ice-controlling true :tie-breaker controlling-tb)
                                controlled-tb (assoc :ice-controlled true :tie-breaker controlled-tb)
                                use-candidate? (assoc :use-candidate? true)
                                priority (assoc :priority priority)
                                prflx-cand (assoc :prflx-address prflx-cand
                                                  :peer-reflexive-candidate prflx-cand))
                              (if-let [resp (make-binding-response password tx-id peer-addr)]
                                (cond-> {:response resp}
                                  (and caller-ufrag (not (str/blank? caller-ufrag)))
                                  (assoc :remote-ice-ufrag caller-ufrag :username username-str)
                                  controlling-tb (assoc :ice-controlling true :tie-breaker controlling-tb)
                                  controlled-tb (assoc :ice-controlled true :tie-breaker controlled-tb)
                                  use-candidate? (assoc :use-candidate? true)
                                  priority (assoc :priority priority)
                                  prflx-cand (assoc :prflx-address prflx-cand
                                                    :peer-reflexive-candidate prflx-cand)
                                  (:switched-role? rc) (assoc :switched-role? true :new-role (:new-role rc))
                                  (and (:new-role rc) (not (:switched-role? rc))) (assoc :new-role (:new-role rc)))
                                {})))))
                      {})
                    {})

                  ;; Binding Response
                  (= msg-type 0x0101)
                  (do
                    (b/buf-set-position! buf start-pos)
                    (let [parsed (parse-packet buf)
                          xor-addr-bytes (get (:attributes parsed) ATTR_XOR_MAPPED_ADDRESS)]
                      (if xor-addr-bytes
                        (let [decoded (decode-xor-mapped-address xor-addr-bytes cookie)
                              candidate-str (str (b/inet-address->str (:address decoded)) ":" (:port decoded))]
                          {:binding-response? true :mapped-address candidate-str :candidate candidate-str})
                        {:binding-response? true})))

                  :else
                  {})]
        (b/buf-set-position! buf (min (b/buf-limit buf) (+ start-pos 20 msg-len)))
        res)
      (catch #?(:clj Exception :cljs :default) _
        {}))))
