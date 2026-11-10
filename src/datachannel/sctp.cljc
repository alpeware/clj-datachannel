(ns datachannel.sctp
  "Cross-platform RFC 4960 SCTP packet and chunk encoder/decoder with CRC32c checksum validation."
  (:require [clojure.set :as set]
            [datachannel.buffer :as b]))

(def ^:private EMPTY-BYTE-ARRAY b/empty-bytes)

;; Chunk types
(def chunk-types
  "Mapping of SCTP chunk type keywords to their integer codes as defined in RFC 4960."
  {:data 0
   :init 1
   :init-ack 2
   :sack 3
   :heartbeat 4
   :heartbeat-ack 5
   :abort 6
   :shutdown 7
   :shutdown-ack 8
   :error 9
   :cookie-echo 10
   :cookie-ack 11
   :ecne 12
   :cwr 13
   :shutdown-complete 14
   :auth 15
   :re-config 130
   :asconf-ack 0x80
   :asconf 0xc1
   :forward-tsn 192})

(def chunk-type-map
  "Inverted mapping of SCTP chunk integer codes to their keywords."
  (set/map-invert chunk-types))

;; Parameters
(def parameters
  "Mapping of SCTP parameter keywords to their integer codes as defined in RFC 4960."
  {:heartbeat 1
   :ipv4 5
   :ipv6 6
   :cookie 7
   :cookie-ttl 9
   :hostname 11
   :address-family 12
   :forward-tsn 49152
   :extensions 0x8008
   :random 0x8002
   :hmac-algo 0x8004
   :chunks 0x8003})

(def parameter-map
  "Inverted mapping of SCTP parameter integer codes to their keywords."
  (set/map-invert parameters))

;; Protocols
(def protocols
  "Mapping of WebRTC payload protocol identifiers (PPIDs) to their integer codes."
  {:webrtc/dcep 50
   :webrtc/string 51
   :webrtc/binary 53
   :webrtc/empty-string 56
   :webrtc/empty-binary 57})

(def protocol-map
  "Inverted mapping of WebRTC PPID integer codes to their keywords."
  (set/map-invert protocols))

;; Data Channel Message Types (DCEP)
(def dcep-types
  "Mapping of WebRTC Data Channel Establishment Protocol (DCEP) message types to their integer codes."
  {:ack 2
   :open 3})

(def dcep-type-map
  "Inverted mapping of DCEP message integer codes to their keywords."
  (set/map-invert dcep-types))

;; Channel Types
(def channel-types
  "Mapping of WebRTC Data Channel reliability types to their integer codes."
  {:reliable 0x00
   :reliable-unordered 0x80
   :partial-reliable 0x01
   :partial-reliable-unordered 0x81
   :partial-reliable-timed 0x02
   :partial-reliable-timed-unordered 0x82})

(def channel-type-map
  "Inverted mapping of WebRTC Data Channel reliability integer codes to their keywords."
  (set/map-invert channel-types))

(defn- pad [len]
  (let [rem (mod len 4)]
    (if (zero? rem) 0 (- 4 rem))))

(defn- get-unsigned-int [buf]
  (try (b/buf-get-u32! buf) (catch #?(:clj Exception :cljs :default) _ 0)))

(defn- get-unsigned-short [buf]
  (try (b/buf-get-u16! buf) (catch #?(:clj Exception :cljs :default) _ 0)))

(defn- get-unsigned-byte [buf]
  (try (b/buf-get-u8! buf) (catch #?(:clj Exception :cljs :default) _ 0)))

(defn decode-params
  "Parses a contiguous buffer of TLV-formatted SCTP parameters into a Clojure map. Expects `buf` to be positioned at the start of the parameters and `total-length` to bound the parsing."
  [buf total-length]
  (let [end (+ (b/buf-position buf) total-length)]
    (loop [params {}]
      (if (>= (b/buf-position buf) end)
        params
        (let [type-code (get-unsigned-short buf)
              len (get-unsigned-short buf)
              val-len (- len 4)
              type-key (get parameter-map type-code type-code)
              val-bytes (b/alloc-bytes val-len)]
          (b/buf-get-bytes! buf val-bytes)
          (let [padding (pad len)]
            (if (< (b/buf-remaining buf) padding)
              params
              (do
                (b/buf-set-position! buf (+ (b/buf-position buf) padding))
                (recur (assoc params type-key val-bytes))))))))))

(defn- set-length-and-padding [buf start-pos]
  (let [end-pos (b/buf-position buf)
        len (- end-pos start-pos)
        padding (pad len)]
    (b/buf-put-u16-at! buf (+ start-pos 2) len)
    (dotimes [_ padding] (b/buf-put-u8! buf 0))))

(defn encode-params
  "Encodes a map of SCTP parameters into TLV format and writes them sequentially to the provided buffer. Ensures appropriate padding to 4-byte boundaries per RFC 4960."
  [buf params]
  (doseq [[k v] params]
    (let [start-pos (b/buf-position buf)
          type-code (if (keyword? k) (get parameters k) k)
          v-bytes (if (b/byte-array? v) v EMPTY-BYTE-ARRAY)]
      (b/buf-put-u16! buf type-code)
      (b/buf-put-u16! buf 0)
      (b/buf-put-bytes! buf v-bytes)
      (set-length-and-padding buf start-pos))))

(defmulti decode-chunk-payload
  "Multimethod dispatcher for decoding the type-specific payload of an SCTP chunk. Dispatches based on the chunk's `:type` keyword."
  (fn [type-key _buf _chunk-data _val-len _chunk-start _flags] type-key))

(defmethod decode-chunk-payload :cookie-ack [_ _ chunk-data _ _ _]
  chunk-data)

(defmethod decode-chunk-payload :forward-tsn [_ buf chunk-data val-len _ _]
  (let [new-cum-tsn (get-unsigned-int buf)
        streams-len (- val-len 4)
        num-streams (quot streams-len 4)
        streams (vec (for [_ (range num-streams)]
                       {:stream-id (get-unsigned-short buf)
                        :stream-sequence (get-unsigned-short buf)}))]
    (merge chunk-data {:new-cumulative-tsn new-cum-tsn :streams streams})))

(defmethod decode-chunk-payload :shutdown [_ _ chunk-data _ _ _]
  chunk-data)

(defmethod decode-chunk-payload :shutdown-ack [_ _ chunk-data _ _ _]
  chunk-data)

(defmethod decode-chunk-payload :shutdown-complete [_ _ chunk-data _ _ _]
  chunk-data)

(defn decode-abort-chunk
  "Advances the buffer position past an ABORT chunk payload. ABORTs are generally not parsed deeply beyond their presence."
  [buf chunk-data val-len chunk-start]
  (b/buf-set-position! buf (+ chunk-start val-len))
  chunk-data)

(defmethod decode-chunk-payload :abort [_ buf chunk-data val-len chunk-start _]
  (decode-abort-chunk buf chunk-data val-len chunk-start))

(defn decode-default-chunk
  "Generic fallback for unhandled chunk types, capturing the raw byte payload as `:body` within the chunk map."
  [buf chunk-data val-len]
  (let [body (b/alloc-bytes val-len)]
    (b/buf-get-bytes! buf body)
    (merge chunk-data {:body body})))

(defmethod decode-chunk-payload :default [_ buf chunk-data val-len _ _]
  (decode-default-chunk buf chunk-data val-len))

(defn decode-data-chunk
  "Parses the payload of an SCTP DATA chunk according to RFC 4960, extracting the TSN, Stream Identifier, Stream Sequence Number, Payload Protocol Identifier, and the user data payload, mapping U/B/E flags to booleans."
  [buf chunk-data val-len flags]
  (let [tsn (get-unsigned-int buf)
        stream-id (get-unsigned-short buf)
        seq-num (get-unsigned-short buf)
        proto-id (get-unsigned-int buf)
        payload-len (- val-len 12)
        payload (b/alloc-bytes payload-len)]
    (b/buf-get-bytes! buf payload)
    (merge chunk-data
           {:tsn tsn
            :stream-id stream-id
            :seq-num seq-num
            :protocol (get protocol-map proto-id proto-id)
            :payload payload
            :unordered (bit-test flags 2)
            :beginning (bit-test flags 1)
            :ending (bit-test flags 0)})))

(defmethod decode-chunk-payload :data [_ buf chunk-data val-len _ flags]
  (decode-data-chunk buf chunk-data val-len flags))

(defn decode-init-chunk
  "Parses the payload of an SCTP INIT chunk, extracting the Initiate Tag, Advertised Receiver Window Credit (a_rwnd), Number of Outbound/Inbound Streams, Initial TSN, and variable-length TLV parameters."
  [buf chunk-data val-len]
  (let [init-tag (get-unsigned-int buf)
        a-rwnd (get-unsigned-int buf)
        outbound-streams (get-unsigned-short buf)
        inbound-streams (get-unsigned-short buf)
        initial-tsn (get-unsigned-int buf)
        params-len (- val-len 20)]
    (merge chunk-data
           {:init-tag init-tag
            :a-rwnd a-rwnd
            :outbound-streams outbound-streams
            :inbound-streams inbound-streams
            :initial-tsn initial-tsn
            :params (decode-params buf params-len)})))

(defmethod decode-chunk-payload :init [_ buf chunk-data val-len _ _]
  (decode-init-chunk buf chunk-data val-len))

(defn decode-init-ack-chunk
  "Parses the payload of an SCTP INIT ACK chunk, extracting the Initiate Tag, Advertised Receiver Window Credit (a_rwnd), Number of Outbound/Inbound Streams, Initial TSN, and variable-length TLV parameters."
  [buf chunk-data val-len]
  (let [init-tag (get-unsigned-int buf)
        a-rwnd (get-unsigned-int buf)
        outbound-streams (get-unsigned-short buf)
        inbound-streams (get-unsigned-short buf)
        initial-tsn (get-unsigned-int buf)
        params-len (- val-len 20)]
    (merge chunk-data
           {:init-tag init-tag
            :a-rwnd a-rwnd
            :outbound-streams outbound-streams
            :inbound-streams inbound-streams
            :initial-tsn initial-tsn
            :params (decode-params buf params-len)})))

(defmethod decode-chunk-payload :init-ack [_ buf chunk-data val-len _ _]
  (decode-init-ack-chunk buf chunk-data val-len))

(defn decode-cookie-echo-chunk
  "Parses the payload of an SCTP COOKIE ECHO chunk, extracting the opaque state cookie byte array."
  [buf chunk-data val-len]
  (let [cookie (b/alloc-bytes val-len)]
    (b/buf-get-bytes! buf cookie)
    (merge chunk-data {:cookie cookie})))

(defmethod decode-chunk-payload :cookie-echo [_ buf chunk-data val-len _ _]
  (decode-cookie-echo-chunk buf chunk-data val-len))

(defn decode-sack-chunk
  "Parses the payload of an SCTP SACK chunk, extracting the Cumulative TSN Ack, Advertised Receiver Window Credit (a_rwnd), Gap Ack Blocks, and Duplicate TSNs."
  [buf chunk-data]
  (let [cum-tsn-ack (get-unsigned-int buf)
        a-rwnd (get-unsigned-int buf)
        num-gap-ack-blocks (get-unsigned-short buf)
        num-duplicate-tsns (get-unsigned-short buf)
        gap-blocks (vec (repeatedly num-gap-ack-blocks
                                    #(vector (get-unsigned-short buf) (get-unsigned-short buf))))
        duplicate-tsns (vec (repeatedly num-duplicate-tsns #(get-unsigned-int buf)))]
    (merge chunk-data
           {:cum-tsn-ack cum-tsn-ack
            :a-rwnd a-rwnd
            :gap-blocks gap-blocks
            :duplicate-tsns duplicate-tsns})))

(defmethod decode-chunk-payload :sack [_ buf chunk-data _ _ _]
  (decode-sack-chunk buf chunk-data))

(defn decode-heartbeat-chunk
  "Parses the payload of an SCTP HEARTBEAT chunk, extracting the variable-length sender-specific Heartbeat Information parameter."
  [buf chunk-data val-len]
  (let [params (decode-params buf val-len)]
    (merge chunk-data {:params params})))

(defmethod decode-chunk-payload :heartbeat [_ buf chunk-data val-len _ _]
  (decode-heartbeat-chunk buf chunk-data val-len))

(defn decode-heartbeat-ack-chunk
  "Parses the payload of an SCTP HEARTBEAT ACK chunk, extracting the variable-length sender-specific Heartbeat Information parameter echoed back by the receiver."
  [buf chunk-data val-len]
  (let [params (decode-params buf val-len)]
    (merge chunk-data {:params params})))

(defmethod decode-chunk-payload :heartbeat-ack [_ buf chunk-data val-len _ _]
  (decode-heartbeat-ack-chunk buf chunk-data val-len))

(defn decode-chunk
  "Reads an SCTP chunk header (Type, Flags, Length) from the buffer and delegates the payload parsing to `decode-chunk-payload`. Advances the buffer position past the chunk including any padding."
  [buf]
  (if (< (b/buf-remaining buf) 4)
    nil
    (let [type-code (get-unsigned-byte buf)
          flags (get-unsigned-byte buf)
          len (get-unsigned-short buf)
          type-key (get chunk-type-map type-code type-code)
          val-len (- len 4)]
      (cond
        (or (< len 4) (> val-len (b/buf-remaining buf)))
        nil

        :else
        (let [chunk-start (b/buf-position buf)
              chunk-data {:type type-key
                          :flags flags
                          :length len}
              parsed-data
              (try
                (decode-chunk-payload type-key buf chunk-data val-len chunk-start flags)
                (catch #?(:clj Exception :cljs :default) _ nil))]

          (let [padding (pad len)]
            (if (<= (+ (b/buf-position buf) padding) (b/buf-limit buf))
              (b/buf-set-position! buf (+ (b/buf-position buf) padding))
              (b/buf-set-position! buf (b/buf-limit buf))))

          parsed-data)))))

(defn update-checksum
  "Calculates and injects the CRC32c checksum into the SCTP common header within the provided buffer. RFC 4960 requires the checksum to be evaluated over the entire packet with the checksum field initialized to zero."
  [buf]
  (let [pos (b/buf-position buf)
        orig-order (b/buf-order buf)]
    (b/buf-flip! buf)
    ;; Checksum field is at offset 8.
    (b/buf-set-order! buf :big-endian)
    (b/buf-put-u32-at! buf 8 0)
    (let [checksum (b/crc32c buf)]
      (b/buf-set-order! buf :little-endian)
      (b/buf-put-u32-at! buf 8 checksum)
      (b/buf-set-order! buf orig-order)
      (b/buf-set-position! buf pos)
      buf)))

(defn- validate-checksum?
  "Validates the CRC32c checksum of an incoming SCTP packet within the provided buffer. Returns true if the checksum is valid, false otherwise."
  [buf]
  (if (< (b/buf-remaining buf) 12)
    false
    (let [start-pos (b/buf-position buf)
          orig-order (b/buf-order buf)
          _ (b/buf-set-order! buf :little-endian)
          stored-checksum (b/buf-get-u32-at buf (+ start-pos 8))
          _ (b/buf-put-u32-at! buf (+ start-pos 8) 0)
          _ (b/buf-set-position! buf start-pos)
          calculated-checksum (b/crc32c buf)
          _ (b/buf-put-u32-at! buf (+ start-pos 8) stored-checksum)
          _ (b/buf-set-position! buf start-pos)
          _ (b/buf-set-order! buf orig-order)]
      (= stored-checksum calculated-checksum))))

(defn decode-packet
  "Parses an SCTP common header (Source Port, Destination Port, Verification Tag, Checksum) and decodes all contained chunks into a vector. Returns nil if the checksum is invalid."
  [buf-or-bytes]
  (let [buf (if (b/binary-buffer? buf-or-bytes) buf-or-bytes (b/wrap-buffer buf-or-bytes))]
    (when (validate-checksum? buf)
      (b/buf-set-order! buf :big-endian)
      (let [src-port (get-unsigned-short buf)
            dst-port (get-unsigned-short buf)
            ver-tag (get-unsigned-int buf)
            _ (b/buf-set-order! buf :little-endian)
            checksum (get-unsigned-int buf)
            _ (b/buf-set-order! buf :big-endian)]
        {:src-port src-port
         :dst-port dst-port
         :verification-tag ver-tag
         :checksum checksum
         :chunks (loop [chunks []]
                   (if (b/buf-has-remaining? buf)
                     (if-let [chunk (decode-chunk buf)]
                       (recur (conj chunks chunk))
                       chunks)
                     chunks))}))))

(defmulti encode-chunk-payload
  "Multimethod dispatcher for serializing the type-specific payload of an SCTP chunk into a buffer. Dispatches based on the chunk's `:type` keyword."
  (fn [type-key _buf _chunk] type-key))

(defmethod encode-chunk-payload :data [_ buf chunk]
  (b/buf-put-u32! buf (:tsn chunk))
  (b/buf-put-u16! buf (:stream-id chunk))
  (b/buf-put-u16! buf (:seq-num chunk))
  (b/buf-put-u32! buf (get protocols (:protocol chunk) (:protocol chunk)))
  (b/buf-put-bytes! buf (:payload chunk)))

(defmethod encode-chunk-payload :init [_ buf chunk]
  (b/buf-put-u32! buf (:init-tag chunk))
  (b/buf-put-u32! buf (:a-rwnd chunk))
  (b/buf-put-u16! buf (:outbound-streams chunk))
  (b/buf-put-u16! buf (:inbound-streams chunk))
  (b/buf-put-u32! buf (:initial-tsn chunk))
  (encode-params buf (:params chunk)))

(defmethod encode-chunk-payload :init-ack [_ buf chunk]
  (b/buf-put-u32! buf (:init-tag chunk))
  (b/buf-put-u32! buf (:a-rwnd chunk))
  (b/buf-put-u16! buf (:outbound-streams chunk))
  (b/buf-put-u16! buf (:inbound-streams chunk))
  (b/buf-put-u32! buf (:initial-tsn chunk))
  (encode-params buf (:params chunk)))

(defmethod encode-chunk-payload :cookie-echo [_ buf chunk]
  (b/buf-put-bytes! buf (:cookie chunk)))

(defmethod encode-chunk-payload :sack [_ buf chunk]
  (b/buf-put-u32! buf (:cum-tsn-ack chunk))
  (b/buf-put-u32! buf (:a-rwnd chunk))
  (b/buf-put-u16! buf (count (:gap-blocks chunk)))
  (b/buf-put-u16! buf (count (:duplicate-tsns chunk)))
  (doseq [[start end] (:gap-blocks chunk)]
    (b/buf-put-u16! buf start)
    (b/buf-put-u16! buf end))
  (doseq [dup (:duplicate-tsns chunk)]
    (b/buf-put-u32! buf dup)))

(defmethod encode-chunk-payload :heartbeat [_ buf chunk]
  (encode-params buf (:params chunk)))

(defmethod encode-chunk-payload :heartbeat-ack [_ buf chunk]
  (encode-params buf (:params chunk)))

(defmethod encode-chunk-payload :forward-tsn [_ buf chunk]
  (b/buf-put-u32! buf (:new-cumulative-tsn chunk))
  (doseq [s (:streams chunk [])]
    (b/buf-put-u16! buf (:stream-id s))
    (b/buf-put-u16! buf (:stream-sequence s))))

(defmethod encode-chunk-payload :shutdown [_ _buf _chunk])
(defmethod encode-chunk-payload :shutdown-ack [_ _buf _chunk])
(defmethod encode-chunk-payload :shutdown-complete [_ _buf _chunk])

(defmethod encode-chunk-payload :default [_ buf chunk]
  (when (:body chunk)
    (b/buf-put-bytes! buf (:body chunk))))

(defn encode-chunk
  "Writes an SCTP chunk header (Type, Flags, Length) to the buffer and delegates payload serialization to `encode-chunk-payload`. Ensures the final chunk length is written back to the header and appropriately padded."
  [buf chunk]
  (let [start-pos (b/buf-position buf)
        type-key (:type chunk)
        type-code (if (keyword? type-key) (get chunk-types type-key) type-key)
        flags (:flags chunk 0)]
    (b/buf-put-u8! buf type-code)
    (b/buf-put-u8! buf flags)
    (b/buf-put-u16! buf 0)
    (encode-chunk-payload type-key buf chunk)
    (set-length-and-padding buf start-pos)))

(defn encode-packet
  "Serializes an entire SCTP packet to the provided buffer, writing the common header and delegating chunk serialization. Calculates and updates the CRC32c checksum unless `:zero-checksum?` is explicitly requested and permitted."
  ([packet buf] (encode-packet packet buf nil))
  ([packet buf {:keys [zero-checksum?]}]
   (let [orig-order (b/buf-order buf)]
     (b/buf-set-order! buf :big-endian)
     (b/buf-put-u16! buf (:src-port packet))
     (b/buf-put-u16! buf (:dst-port packet))
     (b/buf-put-u32! buf (:verification-tag packet))
     (b/buf-put-u32! buf 0)
     (doseq [chunk (:chunks packet)]
       (encode-chunk buf chunk))
     (let [has-init-or-cookie-echo? (some #(#{:init :cookie-echo} (:type %)) (:chunks packet))]
       (when-not (and zero-checksum? (not has-init-or-cookie-echo?))
         (update-checksum buf)))
     (b/buf-set-order! buf orig-order))))
