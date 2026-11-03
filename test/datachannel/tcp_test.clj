(ns datachannel.tcp-test
  "Generative property tests and integration tests for RFC 4571 TCP framing and transport."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.api :as api]
            [datachannel.tcp :as tcp])
  (:import [java.net ServerSocket Socket]
           [java.nio.charset StandardCharsets]
           [java.util Arrays Base64]))

(defn- find-free-port
  "Finds an ephemeral free port for testing."
  []
  (with-open [s (ServerSocket. 0)]
    (.getLocalPort s)))

(defn- concat-byte-arrays
  "Concatenates a collection of byte arrays into a single contiguous byte array."
  [byte-arrays]
  (let [total-len (reduce + 0 (map #(alength ^bytes %) byte-arrays))
        out (byte-array total-len)]
    (loop [offset 0
           [b & rest-bs] byte-arrays]
      (if-not b
        out
        (do
          (System/arraycopy b 0 out offset (alength ^bytes b))
          (recur (+ offset (alength ^bytes b)) rest-bs))))))

(defn- slice-into-chunks
  "Slices a byte array into a sequence of chunk byte arrays according to chunk-sizes."
  [^bytes data chunk-sizes]
  (let [total-len (alength data)]
    (loop [offset 0
           [sz & rest-sizes] chunk-sizes
           acc []]
      (if (>= offset total-len)
        acc
        (let [actual-sz (min (or sz 100) (- total-len offset))
              chunk (byte-array actual-sz)]
          (System/arraycopy data offset chunk 0 actual-sz)
          (recur (+ offset actual-sz) rest-sizes (conj acc chunk)))))))

;; -----------------------------------------------------------------------------
;; 1. Generative Property Tests for RFC 4571 Framing
;; -----------------------------------------------------------------------------

(def gen-payload
  "Generator producing random byte-array payloads up to 2000 bytes."
  (gen/fmap (fn [bytes-vec] (byte-array bytes-vec))
            (gen/vector gen/byte 0 2000)))

(def gen-payloads
  "Generator producing a vector of random byte-array payloads."
  (gen/vector gen-payload 1 25))

(def gen-chunk-sizes
  "Generator producing a vector of chunk slicing lengths."
  (gen/vector (gen/choose 1 128) 1 60))

(def prop-rfc4571-framing-roundtrip-arbitrary-chunks
  "Invariant: arbitrary chunk slicing of an RFC 4571 stream perfectly recovers all payloads."
  (prop/for-all [payloads gen-payloads
                 chunk-sizes gen-chunk-sizes]
                (let [encoded-frames (mapv tcp/encode-rfc4571-frame payloads)
                      stream-bytes (concat-byte-arrays encoded-frames)
                      chunks (slice-into-chunks stream-bytes chunk-sizes)
                      result (reduce (fn [{:keys [frames acc]} chunk]
                                       (let [{new-frames :frames rem-bytes :remaining} (tcp/decode-rfc4571-stream acc chunk)]
                                         {:frames (into frames new-frames)
                                          :acc rem-bytes}))
                                     {:frames [] :acc (byte-array 0)}
                                     chunks)]
                  (and (= (count payloads) (count (:frames result)))
                       (= 0 (alength ^bytes (:acc result)))
                       (every? (fn [[^bytes orig ^bytes dec]]
                                 (Arrays/equals orig dec))
                               (map vector payloads (:frames result)))))))

(defspec test-rfc4571-framing-roundtrip-arbitrary-chunks
  50
  prop-rfc4571-framing-roundtrip-arbitrary-chunks)

(def prop-rfc4571-incomplete-frame-preserved-in-remaining
  "Invariant: truncated RFC 4571 streams correctly leave incomplete payload fragments in :remaining."
  (prop/for-all [payloads gen-payloads
                 cut-offset (gen/choose 1 50)]
                (let [encoded-frames (mapv tcp/encode-rfc4571-frame payloads)
                      stream-bytes (concat-byte-arrays encoded-frames)
                      total-len (alength stream-bytes)
                      actual-cut (min cut-offset (max 1 (dec total-len)))
                      truncated-len (- total-len actual-cut)
                      truncated-bytes (byte-array truncated-len)]
                  (System/arraycopy stream-bytes 0 truncated-bytes 0 truncated-len)
                  (let [{:keys [remaining]} (tcp/decode-rfc4571-stream (byte-array 0) truncated-bytes)]
                    (<= (alength ^bytes remaining) (min 65537 truncated-len))))))

(defspec test-rfc4571-incomplete-frame-preserved-in-remaining
  30
  prop-rfc4571-incomplete-frame-preserved-in-remaining)

(deftest test-rfc4571-payload-size-validation
  (testing "Payloads <= 65535 succeed, while larger payloads throw"
    (let [max-payload (byte-array 65535)
          framed (tcp/encode-rfc4571-frame max-payload)]
      (is (= 65537 (alength ^bytes framed)))
      (is (= (unchecked-byte 0xFF) (aget ^bytes framed 0)))
      (is (= (unchecked-byte 0xFF) (aget ^bytes framed 1))))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Payload too large"
                          (tcp/encode-rfc4571-frame (byte-array 65536))))))

;; -----------------------------------------------------------------------------
;; 2. Integration Tests: TCP Loopback E2E & DTLS Fingerprint Mismatch
;; -----------------------------------------------------------------------------

(deftest test-tcp-loopback-datachannel-e2e
  (testing "Two peers establish WebRTC DataChannel over TCP loopback and exchange messages"
    (let [port (find-free-port)
          server-conns (atom [])
          server-opened? (promise)
          server-msg (promise)
          server-node (api/listen-tcp! {:port port}
                                       {:on-connection (fn [child-node]
                                                         (swap! server-conns conj child-node)
                                                         (api/set-callbacks! child-node
                                                                             {:on-open (fn [_] (deliver server-opened? true))
                                                                              :on-message (fn [evt]
                                                                                            (deliver server-msg (:payload evt))
                                                                                            (api/send! child-node "echo from server" (or (:channel-id evt) 0)))}))})
          client-node (api/create-node {:port 0 :setup "active"})
          client-opened? (promise)
          client-msg (promise)
          client-callbacks {:on-open (fn [_] (deliver client-opened? true))
                            :on-message (fn [evt]
                                          (deliver client-msg (:payload evt)))}
          remote-sdp {:ip "127.0.0.1"
                      :port port
                      :fingerprint (:fingerprint (:cert-data server-node))
                      :remote-ice-ufrag (:ufrag (:ice-creds server-node))
                      :remote-ice-pwd (:pwd (:ice-creds server-node))}]
      (try
        (api/start-tcp! client-node remote-sdp client-callbacks)
        ;; Both peers should open
        (is (= true (deref client-opened? 5000 :timeout)) "Client should open")
        (is (= true (deref server-opened? 5000 :timeout)) "Server child should open")

        ;; Client sends message to server
        (api/send! client-node "hello from client" 0)
        (let [rcv-by-server (deref server-msg 5000 :timeout)]
          (is (not= :timeout rcv-by-server))
          (is (= "hello from client" (String. ^bytes rcv-by-server "UTF-8"))))

        ;; Server echoed back to client
        (let [rcv-by-client (deref client-msg 5000 :timeout)]
          (is (not= :timeout rcv-by-client))
          (is (= "echo from server" (String. ^bytes rcv-by-client "UTF-8"))))

        (finally
          (try (api/close! client-node) (catch Exception _ nil))
          (try (api/close! server-node) (catch Exception _ nil)))))))

(deftest test-tcp-dtls-fingerprint-mismatch
  (testing "TCP client dialing server with mismatched fingerprint fails closed"
    (let [port (find-free-port)
          server-node (api/listen-tcp! {:port port}
                                       {:on-connection (fn [child-node]
                                                         (api/set-callbacks! child-node {}))})
          client-node (api/create-node {:port 0 :setup "active"})
          client-error (promise)
          client-callbacks {:on-error (fn [evt]
                                        (when (str/includes? (str (:message evt)) "Fingerprint")
                                          (deliver client-error (:message evt))))}
          ;; Syntactically valid but mismatched fingerprint
          bogus-fp "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
          remote-sdp {:ip "127.0.0.1"
                      :port port
                      :fingerprint bogus-fp
                      :remote-ice-ufrag (:ufrag (:ice-creds server-node))
                      :remote-ice-pwd (:pwd (:ice-creds server-node))}]
      (try
        (api/start-tcp! client-node remote-sdp client-callbacks)
        (let [err (deref client-error 5000 :timeout)]
          (is (not= :timeout err))
          (is (str/includes? (str err) "Fingerprint Mismatch")))
        (finally
          (try (api/close! client-node) (catch Exception _ nil))
          (try (api/close! server-node) (catch Exception _ nil)))))))

;; -----------------------------------------------------------------------------
;; 3. HTTP CONNECT Proxy Tunneling Tests (Generative, Unit & E2E)
;; -----------------------------------------------------------------------------

(defspec prop-parse-proxy-url-invariants
  50
  (prop/for-all [scheme (gen/elements ["" "http://" "https://"])
                 user (gen/not-empty gen/string-alphanumeric)
                 pass (gen/not-empty gen/string-alphanumeric)
                 host (gen/elements ["127.0.0.1" "proxy.corp.internal" "example.com"])
                 port (gen/choose 1 65535)]
                (let [auth (str user ":" pass)
                      url (str scheme auth "@" host ":" port)
                      parsed (tcp/parse-proxy-url url)]
                  (and (= host (:host parsed))
                       (= port (:port parsed))
                       (= auth (:proxy-auth parsed))))))

(defspec prop-build-and-parse-connect-roundtrip
  50
  (prop/for-all [target-host (gen/elements ["node1.ingress.bitecho.org" "127.0.0.1" "ingress.bitecho.org"])
                 target-port (gen/choose 1 65535)
                 auth (gen/elements [nil "alice:secret" "admin:pass123"])
                 trailing-len (gen/choose 0 50)]
                (let [req-bytes (tcp/build-connect-request {:target-host target-host
                                                            :target-port target-port
                                                            :proxy-auth auth})
                      req-str (String. ^bytes req-bytes StandardCharsets/UTF_8)
                      expected-target (str target-host ":" target-port)
                      trailing-bytes (byte-array trailing-len)
                      resp-str "HTTP/1.1 200 Connection established\r\nProxy-Agent: mock\r\n\r\n"
                      resp-bytes (concat-byte-arrays [(.getBytes resp-str StandardCharsets/UTF_8) trailing-bytes])
                      parsed-resp (tcp/parse-connect-response resp-bytes)]
                  (and (str/includes? req-str (str "CONNECT " expected-target " HTTP/1.1\r\n"))
                       (str/includes? req-str (str "Host: " expected-target "\r\n"))
                       (if auth
                         (str/includes? req-str "Proxy-Authorization: Basic ")
                         (not (str/includes? req-str "Proxy-Authorization:")))
                       (= :ok (:status parsed-resp))
                       (= 200 (:http-status parsed-resp))
                       (= trailing-len (alength ^bytes (:remaining parsed-resp)))))))

(defspec prop-parse-connect-response-errors
  50
  (prop/for-all [status-code (gen/elements [400 401 403 407 500 502 503 504])
                 reason (gen/elements ["Bad Request" "Unauthorized" "Proxy Authentication Required" "Bad Gateway"])]
                (let [resp-str (str "HTTP/1.1 " status-code " " reason "\r\nContent-Length: 0\r\n\r\n")
                      resp-bytes (.getBytes resp-str StandardCharsets/UTF_8)
                      parsed (tcp/parse-connect-response resp-bytes)]
                  (and (= :error (:status parsed))
                       (= status-code (:http-status parsed))))))

(defspec prop-parse-connect-response-incomplete
  50
  (prop/for-all [cut-len (gen/choose 1 20)]
                (let [full-resp "HTTP/1.1 200 OK\r\nHeader: val\r\n\r\n"
                      cut-idx (max 1 (- (count full-resp) cut-len))
                      partial-bytes (.getBytes (subs full-resp 0 cut-idx) StandardCharsets/UTF_8)
                      parsed (tcp/parse-connect-response partial-bytes)]
                  (= :incomplete (:status parsed)))))

(deftest test-proxy-helpers-unit
  (testing "parse-proxy-url parses various URL formats"
    (is (= {:host "127.0.0.1" :port 8080 :proxy-auth "alice:secret"}
           (tcp/parse-proxy-url "http://alice:secret@127.0.0.1:8080")))
    (is (= {:host "proxy.example.com" :port 3128 :proxy-auth nil}
           (tcp/parse-proxy-url "http://proxy.example.com:3128")))
    (is (= {:host "proxy.example.com" :port 8080 :proxy-auth nil}
           (tcp/parse-proxy-url "proxy.example.com")))
    (is (= {:host "127.0.0.1" :port 9090 :proxy-auth "user:pass"}
           (tcp/parse-proxy-url {:host "127.0.0.1" :port 9090 :proxy-auth "user:pass"}))))

  (testing "build-connect-request builds valid HTTP CONNECT request"
    (let [req (tcp/build-connect-request {:target-host "node1.ingress.bitecho.org"
                                          :target-port 443
                                          :proxy-auth "alice:secret"})
          req-str (String. ^bytes req StandardCharsets/UTF_8)]
      (is (str/starts-with? req-str "CONNECT node1.ingress.bitecho.org:443 HTTP/1.1\r\n"))
      (is (str/includes? req-str "Host: node1.ingress.bitecho.org:443\r\n"))
      (is (str/includes? req-str "Proxy-Connection: keep-alive\r\n"))
      (is (str/includes? req-str (str "Proxy-Authorization: Basic "
                                      (.encodeToString (Base64/getEncoder) (.getBytes "alice:secret" StandardCharsets/UTF_8))
                                      "\r\n")))
      (is (str/ends-with? req-str "\r\n\r\n"))))

  (testing "parse-connect-response parses 200 Connection established with trailing bytes"
    (let [resp-bytes (.getBytes "HTTP/1.1 200 Connection established\r\nProxy-Agent: mock\r\n\r\nTRAIL" StandardCharsets/UTF_8)
          parsed (tcp/parse-connect-response resp-bytes)]
      (is (= :ok (:status parsed)))
      (is (= 200 (:http-status parsed)))
      (is (= "TRAIL" (String. ^bytes (:remaining parsed) StandardCharsets/UTF_8))))))

(defn- handle-proxy-client!
  [^Socket client ^String expected-b64]
  (try
    (let [in (.getInputStream client)
          out (.getOutputStream client)
          buf (byte-array 4096)
          n (.read in buf 0 4096)]
      (when (pos? n)
        (let [req (String. buf 0 n StandardCharsets/UTF_8)
              lines (str/split-lines req)
              first-line (first lines)
              [_ target-host target-port-str] (re-matches #"CONNECT\s+([^:]+):(\d+)\s+HTTP/1\.[01]" (or first-line ""))
              auth-hdr (some (fn [l]
                               (when (str/starts-with? (str/lower-case l) "proxy-authorization:")
                                 (str/trim (subs l (count "proxy-authorization:")))))
                             lines)]
          (cond
            (and expected-b64 (not= (str "Basic " expected-b64) auth-hdr))
            (do
              (.write out (.getBytes "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n" StandardCharsets/UTF_8))
              (.flush out)
              (.close client))

            (and target-host target-port-str)
            (let [target-port (Integer/parseInt target-port-str)
                  target-sock (Socket. ^String target-host (int target-port))
                  t-in (.getInputStream target-sock)
                  t-out (.getOutputStream target-sock)]
              (.write out (.getBytes "HTTP/1.1 200 Connection established\r\n\r\n" StandardCharsets/UTF_8))
              (.flush out)
              (.start (Thread/ofVirtual)
                      (fn []
                        (try (.transferTo in t-out) (catch Exception _ nil) (finally (try (.close client) (catch Exception _ nil)) (try (.close target-sock) (catch Exception _ nil))))))
              (.start (Thread/ofVirtual)
                      (fn []
                        (try (.transferTo t-in out) (catch Exception _ nil) (finally (try (.close client) (catch Exception _ nil)) (try (.close target-sock) (catch Exception _ nil)))))))

            :else
            (do
              (.write out (.getBytes "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n" StandardCharsets/UTF_8))
              (.flush out)
              (.close client))))))
    (catch Exception _
      (try (.close client) (catch Exception _ nil)))))

(defn- start-mock-connect-proxy!
  ([port] (start-mock-connect-proxy! port nil))
  ([port expected-auth]
   (let [server-sock (ServerSocket. (int port))
         running? (atom true)
         expected-b64 (when expected-auth
                        (.encodeToString (Base64/getEncoder) (.getBytes ^String expected-auth StandardCharsets/UTF_8)))
         proxy-fut (future
                     (try
                       (while @running?
                         (let [client (.accept server-sock)]
                           (.start (Thread/ofVirtual) (fn [] (handle-proxy-client! client expected-b64)))))
                       (catch Exception _ nil)))]
     {:port port
      :stop-fn (fn []
                 (reset! running? false)
                 (try (.close server-sock) (catch Exception _ nil))
                 (future-cancel proxy-fut))})))

(deftest test-http-connect-proxy-tunnel-e2e
  (testing "Two peers establish WebRTC DataChannel over an authenticated HTTP CONNECT proxy tunnel"
    (let [proxy-port (find-free-port)
          server-port (find-free-port)
          proxy (start-mock-connect-proxy! proxy-port "alice:secret")
          server-conns (atom [])
          server-opened? (promise)
          server-msg (promise)
          server-node (api/listen-tcp! {:port server-port}
                                       {:on-connection (fn [child-node]
                                                         (swap! server-conns conj child-node)
                                                         (api/set-callbacks! child-node
                                                                             {:on-open (fn [_] (deliver server-opened? true))
                                                                              :on-message (fn [evt]
                                                                                            (deliver server-msg (:payload evt))
                                                                                            (api/send! child-node "echo from server" (or (:channel-id evt) 0)))}))})
          client-node (api/create-node {:port 0 :setup "active"})
          client-opened? (promise)
          client-msg (promise)
          client-callbacks {:on-open (fn [_] (deliver client-opened? true))
                            :on-message (fn [evt]
                                          (deliver client-msg (:payload evt)))}
          proxy-url (str "http://alice:secret@127.0.0.1:" proxy-port)
          remote-sdp {:ip "127.0.0.1"
                      :port server-port
                      :proxy proxy-url
                      :fingerprint (:fingerprint (:cert-data server-node))
                      :remote-ice-ufrag (:ufrag (:ice-creds server-node))
                      :remote-ice-pwd (:pwd (:ice-creds server-node))}]
      (try
        (api/start-tcp! client-node remote-sdp client-callbacks)
        ;; Both peers should open
        (is (= true (deref client-opened? 5000 :timeout)) "Client should open via proxy")
        (is (= true (deref server-opened? 5000 :timeout)) "Server child should open via proxy")

        ;; Client sends message to server
        (api/send! client-node "hello via proxy" 0)
        (let [rcv-by-server (deref server-msg 5000 :timeout)]
          (is (not= :timeout rcv-by-server))
          (is (= "hello via proxy" (String. ^bytes rcv-by-server "UTF-8"))))

        ;; Server echoed back to client
        (let [rcv-by-client (deref client-msg 5000 :timeout)]
          (is (not= :timeout rcv-by-client))
          (is (= "echo from server" (String. ^bytes rcv-by-client "UTF-8"))))

        (finally
          (try (api/close! client-node) (catch Exception _ nil))
          (try (api/close! server-node) (catch Exception _ nil))
          ((:stop-fn proxy)))))))

(deftest test-http-connect-proxy-auth-failure
  (testing "Client dialing with invalid proxy credentials throws error"
    (let [proxy-port (find-free-port)
          server-port (find-free-port)
          proxy (start-mock-connect-proxy! proxy-port "correct:credentials")
          client-node (api/create-node {:port 0 :setup "active"})
          remote-sdp {:ip "127.0.0.1"
                      :port server-port
                      :proxy (str "http://wrong:creds@127.0.0.1:" proxy-port)
                      :fingerprint "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
                      :remote-ice-ufrag "ufrag"
                      :remote-ice-pwd "pwd"}]
      (try
        (is (thrown-with-msg? clojure.lang.ExceptionInfo #"HTTP CONNECT proxy handshake failed: 407"
                              (api/start-tcp! client-node remote-sdp {})))
        (finally
          ((:stop-fn proxy)))))))

(deftest test-http-connect-proxy-read-timeout
  (testing "connect-via-proxy-socket-channel fails with timeout when proxy stalls before sending response"
    (let [proxy-port (find-free-port)
          server-sock (ServerSocket. (int proxy-port))
          running? (atom true)
          client-sock (atom nil)
          _ (future
              (try
                (while @running?
                  (let [client (.accept server-sock)
                        _ (reset! client-sock client)
                        in (.getInputStream client)
                        buf (byte-array 1024)]
                    (.read in buf 0 1024)
                    (while @running?
                      (Thread/sleep 20))))
                (catch Exception _ nil)))
          t0 (System/currentTimeMillis)]
      (try
        (is (thrown? java.net.SocketTimeoutException
                     (tcp/connect-via-proxy-socket-channel
                      (str "http://127.0.0.1:" proxy-port)
                      "target.example.com"
                      443
                      200)))
        (let [elapsed (- (System/currentTimeMillis) t0)]
          (is (< elapsed 800) (str "Handshake should time out quickly, took: " elapsed "ms")))
        (finally
          (reset! running? false)
          (when-let [c @client-sock] (try (.close ^Socket c) (catch Exception _ nil)))
          (try (.close server-sock) (catch Exception _ nil)))))))
