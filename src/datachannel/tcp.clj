(ns datachannel.tcp
  "RFC 4571 framing and TCP NIO socket helpers for WebRTC DataChannel transport."
  (:import [java.net InetSocketAddress StandardSocketOptions]
           [java.nio ByteBuffer]
           [java.nio.channels ServerSocketChannel SocketChannel]))

;; -----------------------------------------------------------------------------
;; 1. Pure RFC 4571 §3 Framing & Deframing
;; -----------------------------------------------------------------------------

(defn encode-rfc4571-frame
  "Encodes a byte array payload into an RFC 4571 frame by prepending a 2-byte
   unsigned big-endian length header."
  ^bytes [^bytes payload]
  (let [len (if payload (alength payload) 0)]
    (when (> len 65535)
      (throw (ex-info (str "Payload too large for RFC 4571 frame (>65535 bytes): " len)
                      {:payload-length len})))
    (let [framed (byte-array (+ len 2))]
      (aset-byte framed 0 (unchecked-byte (bit-shift-right len 8)))
      (aset-byte framed 1 (unchecked-byte (bit-and len 0xFF)))
      (when (pos? len)
        (System/arraycopy payload 0 framed 2 len))
      framed)))

(defn decode-rfc4571-stream
  "Pure deframer for RFC 4571 byte streams. Concatenates acc-bytes and newly
   received chunk-bytes, parsing out all complete frames into :frames, and
   returning leftover bytes in :remaining."
  [^bytes acc-bytes ^bytes chunk-bytes]
  (let [acc-len (if acc-bytes (alength acc-bytes) 0)
        chunk-len (if chunk-bytes (alength chunk-bytes) 0)
        total-len (+ acc-len chunk-len)]
    (if (zero? total-len)
      {:frames [] :remaining (byte-array 0)}
      (let [buf (byte-array total-len)]
        (when (pos? acc-len)
          (System/arraycopy acc-bytes 0 buf 0 acc-len))
        (when (pos? chunk-len)
          (System/arraycopy chunk-bytes 0 buf acc-len chunk-len))
        (loop [offset 0
               frames []]
          (if (>= (- total-len offset) 2)
            (let [b0 (bit-and (int (aget buf offset)) 0xFF)
                  b1 (bit-and (int (aget buf (inc offset))) 0xFF)
                  frame-len (bit-or (bit-shift-left b0 8) b1)]
              (if (>= (- total-len (+ offset 2)) frame-len)
                (let [frame (byte-array frame-len)]
                  (when (pos? frame-len)
                    (System/arraycopy buf (+ offset 2) frame 0 frame-len))
                  (recur (+ offset 2 frame-len) (conj frames frame)))
                ;; Incomplete frame payload, retain leftover bytes
                (let [rem-len (- total-len offset)
                      rem-bytes (byte-array rem-len)]
                  (System/arraycopy buf offset rem-bytes 0 rem-len)
                  {:frames frames :remaining rem-bytes})))
            ;; Less than 2 bytes remaining (incomplete length header)
            (let [rem-len (- total-len offset)
                  rem-bytes (byte-array rem-len)]
              (when (pos? rem-len)
                (System/arraycopy buf offset rem-bytes 0 rem-len))
              {:frames frames :remaining rem-bytes})))))))

;; -----------------------------------------------------------------------------
;; 2. TCP NIO Socket Helpers
;; -----------------------------------------------------------------------------

(defn create-server-socket-channel
  "Opens a ServerSocketChannel configured for non-blocking I/O and binds it."
  ([port]
   (create-server-socket-channel port nil))
  ([port host]
   (let [server-ch (ServerSocketChannel/open)]
     (.setOption server-ch StandardSocketOptions/SO_REUSEADDR true)
     (.configureBlocking server-ch false)
     (if host
       (.bind server-ch (InetSocketAddress. ^String host (int port)))
       (.bind server-ch (InetSocketAddress. (int port))))
     server-ch)))

(defn connect-socket-channel
  "Opens a SocketChannel, sets TCP_NODELAY, connects to host:port with timeout,
   and configures non-blocking I/O."
  ([host port]
   (connect-socket-channel host port 5000))
  ([host port timeout-ms]
   (let [socket-ch (SocketChannel/open)]
     (.setOption socket-ch StandardSocketOptions/TCP_NODELAY true)
     (let [sock (.socket socket-ch)
           addr (InetSocketAddress. ^String host (int port))]
       (.connect sock addr (int (or timeout-ms 5000))))
     (.configureBlocking socket-ch false)
     socket-ch)))

(defn write-framed-packet!
  "Encodes packet-bytes into an RFC 4571 frame and writes it completely to
   the given SocketChannel."
  [^SocketChannel ch ^bytes packet-bytes]
  (when (and ch (.isOpen ch) packet-bytes)
    (let [framed (encode-rfc4571-frame packet-bytes)
          buf (ByteBuffer/wrap framed)]
      (while (.hasRemaining buf)
        (.write ch buf)))))
