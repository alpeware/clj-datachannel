(ns datachannel.tcp-test
  "Generative property tests and integration tests for RFC 4571 TCP framing and transport."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.api :as api]
            [datachannel.tcp :as tcp])
  (:import [java.net ServerSocket]
           [java.util Arrays]))

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
