(ns datachannel.dcep
  "Cross-platform RFC 8832 WebRTC Data Channel Establishment Protocol (DCEP) codec."
  (:require [datachannel.buffer :as b]
            [datachannel.sctp :as sctp]))

(defn decode-message
  "Parses RFC 8832 WebRTC Data Channel Establishment Protocol (DCEP) messages from an incoming byte array, decoding `DATA_CHANNEL_OPEN` attributes like reliability and label, and `DATA_CHANNEL_ACK` messages."
  [payload]
  (try
    (let [buf (b/wrap-buffer payload)
          msg-type (b/buf-get-u8! buf)]
      (if (= msg-type 3) ; DATA_CHANNEL_OPEN
        (let [channel-type-code (b/buf-get-u8! buf)
              priority (b/buf-get-u16! buf)
              reliability (b/buf-get-u32! buf)
              label-len (b/buf-get-u16! buf)
              protocol-len (b/buf-get-u16! buf)
              _ (when (< (b/buf-remaining buf) (+ label-len protocol-len))
                  (throw (ex-info "Buffer underflow" {:remaining (b/buf-remaining buf)})))
              label-bytes (b/alloc-bytes label-len)
              _ (b/buf-get-bytes! buf label-bytes)
              protocol-bytes (b/alloc-bytes protocol-len)
              _ (b/buf-get-bytes! buf protocol-bytes)
              channel-type (get sctp/channel-type-map channel-type-code :reliable)
              ordered? (not (some #{channel-type} [:reliable-unordered :partial-reliable-unordered :partial-reliable-timed-unordered]))
              max-retransmits (if (some #{channel-type} [:partial-reliable :partial-reliable-unordered]) reliability nil)
              max-packet-life-time (if (some #{channel-type} [:partial-reliable-timed :partial-reliable-timed-unordered]) reliability nil)]
          {:type :open
           :channel-type channel-type
           :priority priority
           :reliability reliability
           :label (b/bytes->utf8 label-bytes)
           :protocol (b/bytes->utf8 protocol-bytes)
           :ordered ordered?
           :max-retransmits max-retransmits
           :max-packet-life-time max-packet-life-time})
        (if (= msg-type 2) ; DATA_CHANNEL_ACK
          {:type :ack}
          {:type :unknown})))
    (catch #?(:clj Exception :cljs :default) _
      {:type :unknown})))

(defn encode-message
  "Serializes DCEP messages into a byte array for network transmission, mapping WebRTC data channel configuration options to the appropriate RFC 8832 byte encodings."
  [msg]
  (if (= (:type msg) :open)
    (let [label-bytes (b/utf8->bytes (or (:label msg) ""))
          protocol-bytes (b/utf8->bytes (or (:protocol msg) ""))
          label-len (b/blength label-bytes)
          protocol-len (b/blength protocol-bytes)
          ordered? (get msg :ordered true)
          max-retransmits (:max-retransmits msg)
          max-packet-life-time (:max-packet-life-time msg)
          channel-type (cond
                         (some? max-retransmits) (if ordered? :partial-reliable :partial-reliable-unordered)
                         (some? max-packet-life-time) (if ordered? :partial-reliable-timed :partial-reliable-timed-unordered)
                         :else (if ordered? :reliable :reliable-unordered))
          channel-type-code (get sctp/channel-types channel-type 0x00)
          priority (get msg :priority 256)
          reliability (or max-retransmits max-packet-life-time 0)
          buf (b/allocate-buffer (+ 12 label-len protocol-len))]
      (b/buf-put-u8! buf 3) ; msg-type
      (b/buf-put-u8! buf channel-type-code)
      (b/buf-put-u16! buf priority)
      (b/buf-put-u32! buf reliability)
      (b/buf-put-u16! buf label-len)
      (b/buf-put-u16! buf protocol-len)
      (b/buf-put-bytes! buf label-bytes)
      (b/buf-put-bytes! buf protocol-bytes)
      (b/buf-flip! buf)
      (b/buf->bytes buf))
    (if (= (:type msg) :ack)
      (b/bytes-from-seq [2])
      b/empty-bytes)))
