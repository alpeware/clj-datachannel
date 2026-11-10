(ns datachannel.tcp
  "RFC 4571 framing, HTTP CONNECT proxy protocol codec, and JVM TCP NIO socket helpers
   for WebRTC DataChannel transport."
  (:require [clojure.string :as str]
            [datachannel.buffer :as b])
  #?(:clj
     (:import [java.io ByteArrayOutputStream]
              [java.net InetSocketAddress SocketTimeoutException StandardSocketOptions]
              [java.nio ByteBuffer]
              [java.nio.channels ServerSocketChannel SocketChannel])))

;; -----------------------------------------------------------------------------
;; 1. Pure RFC 4571 §3 Framing & Deframing
;; -----------------------------------------------------------------------------

(defn encode-rfc4571-frame
  "Encodes a byte array payload into an RFC 4571 frame by prepending a 2-byte
   unsigned big-endian length header."
  [payload]
  (let [len (b/blength payload)]
    (when (> len 65535)
      (throw (ex-info (str "Payload too large for RFC 4571 frame (>65535 bytes): " len)
                      {:payload-length len})))
    (let [framed (b/alloc-bytes (+ len 2))]
      (b/bset-u8! framed 0 (unsigned-bit-shift-right len 8))
      (b/bset-u8! framed 1 (bit-and len 0xFF))
      (when (pos? len)
        (b/bcopy! payload 0 framed 2 len))
      framed)))

(defn decode-rfc4571-stream
  "Pure deframer for RFC 4571 byte streams. Concatenates acc-bytes and newly
   received chunk-bytes, parsing out all complete frames into :frames, and
   returning leftover bytes in :remaining."
  [acc-bytes chunk-bytes]
  (let [acc-len (b/blength acc-bytes)
        chunk-len (b/blength chunk-bytes)
        total-len (+ acc-len chunk-len)]
    (if (zero? total-len)
      {:frames [] :remaining (b/alloc-bytes 0)}
      (let [buf (b/alloc-bytes total-len)]
        (when (pos? acc-len)
          (b/bcopy! acc-bytes 0 buf 0 acc-len))
        (when (pos? chunk-len)
          (b/bcopy! chunk-bytes 0 buf acc-len chunk-len))
        (loop [offset 0
               frames []]
          (if (>= (- total-len offset) 2)
            (let [b0 (b/bget-u8 buf offset)
                  b1 (b/bget-u8 buf (inc offset))
                  frame-len (bit-or (bit-shift-left b0 8) b1)]
              (if (>= (- total-len (+ offset 2)) frame-len)
                (let [frame (b/bslice buf (+ offset 2) (+ offset 2 frame-len))]
                  (recur (+ offset 2 frame-len) (conj frames frame)))
                ;; Incomplete frame payload, retain leftover bytes
                {:frames frames :remaining (b/bslice buf offset total-len)}))
            ;; Less than 2 bytes remaining (incomplete length header)
            {:frames frames :remaining (b/bslice buf offset total-len)}))))))

;; -----------------------------------------------------------------------------
;; 2. TCP NIO Socket Helpers (JVM Shell Boundary)
;; -----------------------------------------------------------------------------

#?(:clj
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
        server-ch))))

#?(:clj
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
        socket-ch))))

#?(:clj
   (defn write-framed-packet!
     "Encodes packet-bytes into an RFC 4571 frame and writes it completely to
      the given SocketChannel."
     [^SocketChannel ch ^bytes packet-bytes]
     (when (and ch (.isOpen ch) packet-bytes)
       (let [framed (encode-rfc4571-frame packet-bytes)
             buf (ByteBuffer/wrap framed)]
         (while (.hasRemaining buf)
           (.write ch buf))))))

;; -----------------------------------------------------------------------------
;; 3. HTTP CONNECT Proxy Client (Preemptive Auth & Tunneling)
;; -----------------------------------------------------------------------------

(defn parse-proxy-url
  "Pure function. Parses a proxy URL string or map into {:host ... :port ... :proxy-auth ...}.
   Supports http://user:pass@host:port, http://host:port, host:port, or host (defaults to port 8080)."
  [proxy-spec]
  (if (map? proxy-spec)
    {:host (:host proxy-spec)
     :port (int (or (:port proxy-spec) 8080))
     :proxy-auth (:proxy-auth proxy-spec)}
    (let [raw (str/trim (or proxy-spec ""))
          cleaned (str/replace-first raw #"^https?://" "")
          at-idx (str/index-of cleaned "@")
          auth (when (and at-idx (pos? at-idx))
                 (subs cleaned 0 at-idx))
          host-port (if at-idx (subs cleaned (inc at-idx)) cleaned)]
      (cond
        ;; Bracketed IPv6: [::1]:8080 or [::1]
        (str/starts-with? host-port "[")
        (let [close-bracket (str/index-of host-port "]")
              host (subs host-port 1 close-bracket)
              port-str (when (> (count host-port) (inc close-bracket))
                         (subs host-port (+ close-bracket 2)))]
          {:host host
           :port (if (seq port-str) (int (b/parse-int port-str 8080)) 8080)
           :proxy-auth (when (seq auth) auth)})

        ;; Host with port: host:port
        (str/includes? host-port ":")
        (let [last-colon (str/last-index-of host-port ":")
              host (subs host-port 0 last-colon)
              port-str (subs host-port (inc last-colon))]
          {:host host
           :port (int (b/parse-int port-str 8080))
           :proxy-auth (when (seq auth) auth)})

        ;; Host only: default port 8080
        :else
        {:host host-port
         :port 8080
         :proxy-auth (when (seq auth) auth)}))))

(defn build-connect-request
  "Pure function. Formats an HTTP CONNECT request as UTF-8 bytes.
   Preemptively includes Proxy-Authorization: Basic <base64> if :proxy-auth is provided."
  [{:keys [target-host target-port proxy-auth]}]
  (let [target (str target-host ":" target-port)
        auth-hdr (when (and proxy-auth (seq proxy-auth))
                   (let [b64 (b/base64-encode (b/utf8->bytes proxy-auth))]
                     (str "Proxy-Authorization: Basic " b64 "\r\n")))
        req-str (str "CONNECT " target " HTTP/1.1\r\n"
                     "Host: " target "\r\n"
                     "Proxy-Connection: keep-alive\r\n"
                     (or auth-hdr "")
                     "\r\n")]
    (b/utf8->bytes req-str)))

(defn parse-connect-response
  "Pure function. Parses an HTTP CONNECT response from byte buffer.
   Returns:
     - {:status :ok :http-status 200 :remaining <byte-array>}
     - {:status :error :http-status <code> :message <msg> :remaining <byte-array>}
     - {:status :incomplete}"
  [buf]
  (let [len (b/blength buf)]
    (if (zero? len)
      {:status :incomplete}
      (let [header-end
            (loop [idx 0]
              (if (<= (+ idx 4) len)
                (if (and (= (b/bget-u8 buf idx) 13)
                         (= (b/bget-u8 buf (+ idx 1)) 10)
                         (= (b/bget-u8 buf (+ idx 2)) 13)
                         (= (b/bget-u8 buf (+ idx 3)) 10))
                  (+ idx 4)
                  (if (and (= (b/bget-u8 buf idx) 10)
                           (= (b/bget-u8 buf (+ idx 1)) 10))
                    (+ idx 2)
                    (recur (inc idx))))
                (when (and (<= (+ idx 2) len)
                           (= (b/bget-u8 buf idx) 10)
                           (= (b/bget-u8 buf (inc idx)) 10))
                  (+ idx 2))))]
        (if-not header-end
          {:status :incomplete}
          (let [hdr-str (b/bytes->utf8 buf 0 header-end)
                status-line (first (str/split-lines hdr-str))
                [_ status-code-str reason] (re-matches #"HTTP/\d\.\d\s+(\d{3})(?:\s+(.*))?" (or status-line ""))
                rem-bytes (b/bslice buf header-end len)]
            (if-let [code (when status-code-str (b/parse-int status-code-str))]
              (if (= code 200)
                {:status :ok :http-status 200 :remaining rem-bytes}
                {:status :error :http-status code :message (or reason hdr-str) :remaining rem-bytes})
              {:status :error :http-status 0 :message (str "Malformed HTTP status line: " status-line) :remaining rem-bytes})))))))

#?(:clj
   (defn connect-via-proxy-socket-channel
     "Connects to target-host:target-port through an HTTP CONNECT proxy.
      Performs the HTTP CONNECT handshake with preemptive Basic proxy auth,
      and configures the channel for non-blocking I/O.
      Returns {:channel SocketChannel :remaining byte[]}. Throws on failure."
     ([proxy-spec target-host target-port]
      (connect-via-proxy-socket-channel proxy-spec target-host target-port 5000))
     ([proxy-spec target-host target-port timeout-ms]
      (let [t-ms (int (or timeout-ms 5000))
            proxy-map (parse-proxy-url proxy-spec)
            socket-ch (SocketChannel/open)]
        (.setOption socket-ch StandardSocketOptions/TCP_NODELAY true)
        (let [sock (.socket socket-ch)
              proxy-addr (InetSocketAddress. ^String (:host proxy-map) (int (:port proxy-map)))]
          (.connect sock proxy-addr t-ms)
          (.setSoTimeout sock t-ms)
          (try
            (let [deadline (+ (System/currentTimeMillis) t-ms)
                  out (.getOutputStream sock)
                  in (.getInputStream sock)
                  req-bytes (build-connect-request {:target-host target-host
                                                    :target-port target-port
                                                    :proxy-auth (:proxy-auth proxy-map)})]
              (.write out req-bytes)
              (.flush out)
              (let [buf (byte-array 4096)
                    baos (ByteArrayOutputStream.)]
                (loop []
                  (let [rem-ms (- deadline (System/currentTimeMillis))]
                    (when (<= rem-ms 0)
                      (throw (SocketTimeoutException. "Read timed out waiting for HTTP CONNECT response")))
                    (.setSoTimeout sock (max 1 (int rem-ms)))
                    (let [n (.read in buf 0 4096)]
                      (if (neg? n)
                        (throw (ex-info "Proxy closed connection during CONNECT handshake" {:status :error :http-status 0}))
                        (do
                          (.write baos buf 0 n)
                          (let [curr-bytes (.toByteArray baos)
                                parsed (parse-connect-response curr-bytes)]
                            (case (:status parsed)
                              :ok
                              (do
                                (.setSoTimeout sock 0)
                                (.configureBlocking socket-ch false)
                                {:channel socket-ch :remaining (:remaining parsed)})
                              :error
                              (throw (ex-info (str "HTTP CONNECT proxy handshake failed: " (:http-status parsed) " " (:message parsed))
                                              parsed))
                              :incomplete
                              (recur))))))))))
            (catch Exception e
              (try (.close socket-ch) (catch Exception _ nil))
              (throw e))))))))
