(ns datachannel.ice-turn-holepunch-test
  (:require [clojure.test :refer [deftest is testing]]
            [datachannel.core :as dc]
            [datachannel.sdp :as sdp]
            [datachannel.stun :as stun]
            [datachannel.turn :as turn])
  (:import [java.net InetSocketAddress]
           [java.nio ByteBuffer]))

(deftest test-ice-candidate-priority-and-pairing
  (testing "RFC 8445 §5.1.2 Candidate Priority calculation"
    (let [host-p (sdp/calculate-candidate-priority "host" 65535 1)
          prflx-p (sdp/calculate-candidate-priority "prflx" 65535 1)
          srflx-p (sdp/calculate-candidate-priority "srflx" 65535 1)
          relay-p (sdp/calculate-candidate-priority "relay" 65535 1)]
      ;; Type preferences: host (126) > prflx (110) > srflx (100) > relay (0)
      (is (> host-p prflx-p))
      (is (> prflx-p srflx-p))
      (is (> srflx-p relay-p))
      (is (= host-p (sdp/calculate-candidate-priority :host)))
      (is (= srflx-p (sdp/calculate-candidate-priority :srflx)))))

  (testing "RFC 8445 §6.1.2.3 Pair Priority calculation"
    (let [g (sdp/calculate-candidate-priority "host" 65535 1)
          d (sdp/calculate-candidate-priority "srflx" 65535 1)
          pair-p (sdp/calculate-pair-priority g d)]
      (is (pos? pair-p))
      ;; When controlling priority changes, pair priority reflects it
      (is (> (sdp/calculate-pair-priority g d)
             (sdp/calculate-pair-priority d d))))))

(deftest test-ice-candidate-formatting-and-parsing
  (testing "Roundtrip host candidate"
    (let [cand {:foundation "1"
                :component 1
                :transport "UDP"
                :priority 2130706431
                :ip "192.168.1.10"
                :port 5000
                :type "host"
                :ufrag "ufrag123"}
          s (sdp/format-candidate cand)
          parsed (sdp/parse-candidate s)]
      (is (= "192.168.1.10" (:ip parsed)))
      (is (= 5000 (:port parsed)))
      (is (= "host" (:type parsed)))
      (is (= "1" (:foundation parsed)))
      (is (= 1 (:component parsed)))
      (is (= "UDP" (:transport parsed)))
      (is (= "ufrag123" (:ufrag parsed)))))

  (testing "Roundtrip srflx candidate with raddr and rport"
    (let [cand {:foundation "2"
                :component 1
                :transport "UDP"
                :priority 1694498815
                :ip "203.0.113.1"
                :port 5000
                :type "srflx"
                :raddr "192.168.1.10"
                :rport 5000}
          s (sdp/format-candidate cand)
          parsed (sdp/parse-candidate s)]
      (is (= "203.0.113.1" (:ip parsed)))
      (is (= 5000 (:port parsed)))
      (is (= "srflx" (:type parsed)))
      (is (= "192.168.1.10" (:raddr parsed)))
      (is (= 5000 (:rport parsed)))))

  (testing "Roundtrip relay candidate"
    (let [cand {:foundation "3"
                :component 1
                :transport "UDP"
                :priority 8421375
                :ip "198.51.100.5"
                :port 60000
                :type "relay"
                :raddr "203.0.113.1"
                :rport 5000}
          s (str "a=" (sdp/format-candidate cand))
          parsed (sdp/parse-candidate s)]
      (is (= "198.51.100.5" (:ip parsed)))
      (is (= 60000 (:port parsed)))
      (is (= "relay" (:type parsed))))))

(deftest test-ice-controlling-controlled-and-nomination
  (testing "make-binding-request with controlling role, tie-breaker, and USE-CANDIDATE"
    (let [buf (stun/make-binding-request "local-u" "remote-u" "password123456789012"
                                         {:role :controlling
                                          :tie-breaker 9876543210
                                          :use-candidate? true
                                          :priority 123456})
          peer (InetSocketAddress. "192.168.1.50" 6000)
          conn {:ice-pwd "password123456789012" :ice-ufrag "remote-u"}
          res (stun/handle-packet buf peer conn)]
      (is (some? (:response res)))
      (is (true? (:ice-controlling res)))
      (is (= 9876543210 (:tie-breaker res)))
      (is (true? (:use-candidate? res)))
      (is (= 123456 (:priority res)))
      (is (= "192.168.1.50:6000" (:prflx-address res)))))

  (testing "make-binding-request with controlled role"
    (let [buf (stun/make-binding-request "local-u" "remote-u" "password123456789012"
                                         {:role :controlled
                                          :tie-breaker 1122334455})
          peer (InetSocketAddress. "10.0.0.5" 7000)
          conn {:ice-pwd "password123456789012" :ice-ufrag "remote-u"}
          res (stun/handle-packet buf peer conn)]
      (is (some? (:response res)))
      (is (true? (:ice-controlled res)))
      (is (= 1122334455 (:tie-breaker res)))
      (is (= "10.0.0.5:7000" (:peer-reflexive-candidate res))))))

(deftest test-turn-long-term-credentials
  (testing "RFC 5389 §15.4 Long-Term Credential Key MD5 derivation"
    (let [key1 (turn/compute-long-term-key "alice" "example.org" "secret123")
          key2 (turn/compute-long-term-key "alice" "example.org" "secret123")
          key3 (turn/compute-long-term-key "bob" "example.org" "secret123")]
      (is (= 16 (alength ^bytes key1)))
      (is (java.util.Arrays/equals ^bytes key1 ^bytes key2))
      (is (not (java.util.Arrays/equals ^bytes key1 ^bytes key3))))))

(deftest test-turn-allocation-lifecycle
  (testing "Initial Allocate Request triggers 401 Unauthorized"
    (let [alloc-probe (turn/make-allocate-request "alice" nil nil nil)
          parsed-probe (turn/parse-turn-packet alloc-probe)]
      (is (= turn/METHOD_ALLOCATE_REQUEST (:msg-type parsed-probe)))
      (is (nil? (:realm parsed-probe)))
      (is (nil? (:nonce parsed-probe)))
      ;; Simulate TURN server responding with 401 challenge
      (let [tx-id (:tx-id parsed-probe)
            resp-401 (turn/make-allocate-error-response tx-id "turn.bitecho.org" "nonce-xyz-123")
            parsed-401 (turn/parse-turn-packet resp-401)]
        (is (= turn/METHOD_ALLOCATE_ERROR (:msg-type parsed-401)))
        (is (= 401 (:error-code parsed-401)))
        (is (= "turn.bitecho.org" (:realm parsed-401)))
        (is (= "nonce-xyz-123" (:nonce parsed-401))))))

  (testing "Authenticated Allocate Request and Success Response"
    (let [tx (byte-array 12)
          _ (dotimes [i 12] (aset tx i (byte (inc i))))
          alloc-req (turn/make-allocate-request "alice" "turn.bitecho.org" "secret123" "nonce-xyz-123"
                                                {:tx-id tx :lifetime 600})
          parsed-req (turn/parse-turn-packet alloc-req)]
      (is (= turn/METHOD_ALLOCATE_REQUEST (:msg-type parsed-req)))
      (is (= "turn.bitecho.org" (:realm parsed-req)))
      (is (= "nonce-xyz-123" (:nonce parsed-req)))
      (is (= 600 (:lifetime parsed-req)))

      ;; Server creates Allocate Success Response with XOR-RELAYED-ADDRESS
      (let [relayed (InetSocketAddress. "198.51.100.2" 49152)
            mapped (InetSocketAddress. "203.0.113.1" 54321)
            resp-ok (turn/make-allocate-success-response tx "alice" "turn.bitecho.org" "secret123" relayed mapped 600)
            parsed-ok (turn/parse-turn-packet resp-ok)]
        (is (= turn/METHOD_ALLOCATE_RESPONSE (:msg-type parsed-ok)))
        (is (= 600 (:lifetime parsed-ok)))
        (is (= "198.51.100.2" (get-in parsed-ok [:relayed-address :ip])))
        (is (= 49152 (get-in parsed-ok [:relayed-address :port])))))))

(deftest test-turn-permission-and-channel-bind
  (testing "CreatePermission and ChannelBind requests"
    (let [peer-addr (InetSocketAddress. "203.0.113.88" 9000)
          perm-req (turn/make-create-permission-request "alice" "turn.bitecho.org" "secret123" "nonce-1" peer-addr)
          parsed-perm (turn/parse-turn-packet perm-req)]
      (is (= turn/METHOD_CREATE_PERMISSION_REQUEST (:msg-type parsed-perm)))
      (is (= "203.0.113.88" (get-in parsed-perm [:peer-address :ip])))
      (is (= 9000 (get-in parsed-perm [:peer-address :port]))))

    (let [peer-addr (InetSocketAddress. "203.0.113.88" 9000)
          bind-req (turn/make-channel-bind-request "alice" "turn.bitecho.org" "secret123" "nonce-1" 0x4001 peer-addr)
          parsed-bind (turn/parse-turn-packet bind-req)]
      (is (= turn/METHOD_CHANNEL_BIND_REQUEST (:msg-type parsed-bind)))
      (is (= 0x4001 (:channel-number parsed-bind)))
      (is (= "203.0.113.88" (get-in parsed-bind [:peer-address :ip])))
      (is (= 9000 (get-in parsed-bind [:peer-address :port]))))))

(deftest test-turn-indications-and-channel-data-framing
  (testing "Send and Data Indications"
    (let [peer (InetSocketAddress. "192.0.2.1" 8080)
          payload (.getBytes "hello-relayed-world" "UTF-8")
          send-ind (turn/make-send-indication peer payload)
          parsed-send (turn/parse-turn-packet send-ind)]
      (is (= turn/METHOD_SEND_INDICATION (:msg-type parsed-send)))
      (is (= "192.0.2.1" (get-in parsed-send [:peer-address :ip])))
      (is (= 8080 (get-in parsed-send [:peer-address :port])))
      (is (java.util.Arrays/equals ^bytes payload ^bytes (:data parsed-send))))

    (let [peer (InetSocketAddress. "192.0.2.1" 8080)
          payload (.getBytes "incoming-relay-data" "UTF-8")
          data-ind (turn/make-data-indication peer payload)
          parsed-data (turn/parse-turn-packet data-ind)]
      (is (= turn/METHOD_DATA_INDICATION (:msg-type parsed-data)))
      (is (= "192.0.2.1" (get-in parsed-data [:peer-address :ip])))
      (is (= 8080 (get-in parsed-data [:peer-address :port])))
      (is (java.util.Arrays/equals ^bytes payload ^bytes (:data parsed-data)))))

  (testing "RFC 5766 §11 ChannelData framing"
    (let [payload (.getBytes "test-payload-bytes" "UTF-8")
          frame (turn/encode-channel-data 0x4005 payload)
          buf (ByteBuffer/wrap frame)]
      (is (turn/channel-data? buf))
      (let [decoded (turn/decode-channel-data buf)]
        (is (= 0x4005 (:channel-number decoded)))
        (is (= (alength payload) (:length decoded)))
        (is (java.util.Arrays/equals ^bytes payload ^bytes (:data decoded)))))))

(defn- bb->bytes [^ByteBuffer bb]
  (let [buf (byte-array (.remaining bb))]
    (.get (.duplicate bb) buf)
    buf))

(defn- pump-holepunch-or-turn
  [state-a state-b via-turn? condition? max-iterations start-time]
  (loop [a state-a
         b state-b
         i 0]
    (let [now-ms (+ start-time (* i 100))
          a-events (:app-events a [])
          b-events (:app-events b [])]
      (if (or (>= i max-iterations)
              (not (condition? a b)))
        [a b]
        (let [a-bytes (:network-out-bytes a [])
              b-bytes (:network-out-bytes b [])
              relay-frame (fn [^bytes raw]
                            (if via-turn?
                              (:data (turn/decode-channel-data (ByteBuffer/wrap (turn/encode-channel-data 0x4001 raw))))
                              raw))
              b-rx (reduce (fn [res item]
                             (let [bb (if (map? item) (:packet item) item)
                                   bytes (relay-frame (bb->bytes bb))
                                   out (dc/handle-receive (:new-state res) bytes now-ms (InetSocketAddress. "127.0.0.1" 5000))]
                               (-> out
                                   (dc/serialize-network-out)
                                   (update :app-events into (:app-events res []))
                                   (update :network-out-bytes into (:network-out-bytes res [])))))
                           (assoc b :network-out-bytes [] :app-events b-events)
                           a-bytes)
              a-rx (reduce (fn [res item]
                             (let [bb (if (map? item) (:packet item) item)
                                   bytes (relay-frame (bb->bytes bb))
                                   out (dc/handle-receive (:new-state res) bytes now-ms (InetSocketAddress. "127.0.0.1" 5001))]
                               (-> out
                                   (dc/serialize-network-out)
                                   (update :app-events into (:app-events res []))
                                   (update :network-out-bytes into (:network-out-bytes res [])))))
                           (assoc a :network-out-bytes [] :app-events a-events)
                           b-bytes)
              a-time (reduce (fn [res [tid timer]]
                               (if (>= now-ms (:expires-at timer))
                                 (let [out (dc/handle-timeout (:new-state res) tid now-ms (:dtls/engine (:new-state res)))]
                                   (-> out
                                       (dc/serialize-network-out)
                                       (update :app-events into (:app-events res []))
                                       (update :network-out-bytes into (:network-out-bytes res []))))
                                 res))
                             a-rx
                             (:timers (:new-state a-rx)))
              b-time (reduce (fn [res [tid timer]]
                               (if (>= now-ms (:expires-at timer))
                                 (let [out (dc/handle-timeout (:new-state res) tid now-ms (:dtls/engine (:new-state res)))]
                                   (-> out
                                       (dc/serialize-network-out)
                                       (update :app-events into (:app-events res []))
                                       (update :network-out-bytes into (:network-out-bytes res []))))
                                 res))
                             b-rx
                             (:timers (:new-state b-rx)))]
          (recur a-time b-time (inc i)))))))

(deftest test-end-to-end-holepunch-and-turn-relay-datachannel
  (testing "End-to-end ICE candidate SDP exchange, STUN holepunching, and TURN ChannelData fallback establish DTLS+SCTP DataChannel"
    (doseq [via-turn? [false true]]
      (let [cand-a-sdp (sdp/format-candidate {:foundation "1" :component 1 :transport "UDP"
                                              :priority (sdp/calculate-candidate-priority (if via-turn? "relay" "srflx"))
                                              :ip "127.0.0.1" :port 5000
                                              :type (if via-turn? "relay" "srflx")
                                              :raddr "10.0.0.1" :rport 5000})
            cand-b-sdp (sdp/format-candidate {:foundation "2" :component 1 :transport "UDP"
                                              :priority (sdp/calculate-candidate-priority (if via-turn? "relay" "srflx"))
                                              :ip "127.0.0.1" :port 5001
                                              :type (if via-turn? "relay" "srflx")
                                              :raddr "10.0.0.2" :rport 5001})
            parsed-a (sdp/parse-candidate cand-a-sdp)
            parsed-b (sdp/parse-candidate cand-b-sdp)
            client-a (dc/create-connection {:ice-ufrag "Alice" :ice-pwd "pwdA-123456789012345678"
                                            :remote-ice-ufrag "Bob" :remote-ice-pwd "pwdB-123456789012345678"
                                            :ice-lite? false} true)
            client-b (dc/create-connection {:ice-ufrag "Bob" :ice-pwd "pwdB-123456789012345678"
                                            :remote-ice-ufrag "Alice" :remote-ice-pwd "pwdA-123456789012345678"
                                            :ice-lite? false} false)
            client-a (-> client-a
                         (assoc :remote-fingerprint (:fingerprint (:cert-data client-b)))
                         (assoc :remote-candidates [(str (:ip parsed-b) ":" (:port parsed-b))])
                         (assoc-in [:timers :stun/keepalive :expires-at] 0))
            client-b (-> client-b
                         (assoc :remote-fingerprint (:fingerprint (:cert-data client-a)))
                         (assoc :remote-candidates [(str (:ip parsed-a) ":" (:port parsed-a))])
                         (assoc-in [:timers :stun/keepalive :expires-at] 0))
            now-ms 1000000
            init-b (-> (dc/handle-timeout client-b :stun/keepalive now-ms nil) (dc/serialize-network-out))
            init-a (-> (dc/handle-timeout client-a :stun/keepalive now-ms nil) (dc/serialize-network-out))
            _ (.beginHandshake (:dtls/engine client-a))
            _ (.beginHandshake (:dtls/engine client-b))
            init-a (-> (dc/handle-timeout (:new-state init-a) :dtls/flight-timeout now-ms (:dtls/engine (:new-state init-a)))
                       (dc/serialize-network-out)
                       (update :app-events into (:app-events init-a []))
                       (update :network-out-bytes into (:network-out-bytes init-a [])))
            [conn-a conn-b] (pump-holepunch-or-turn
                             init-a init-b via-turn?
                             (fn [a b] (not (and (= :connected (:ice-connection-state (:new-state a)))
                                                 (= :connected (:ice-connection-state (:new-state b)))
                                                 (= :established (:state (:new-state a)))
                                                 (= :established (:state (:new-state b))))))
                             300 now-ms)]
        (is (= :connected (:ice-connection-state (:new-state conn-a))))
        (is (= :connected (:ice-connection-state (:new-state conn-b))))
        (is (= :established (:state (:new-state conn-a))))
        (is (= :established (:state (:new-state conn-b))))
        (let [payload-str (if via-turn? "Holepunch fallback via TURN ChannelData!" "Direct STUN/ICE UDP Holepunch!")
              send-res (-> (dc/send-data (:new-state conn-a) (.getBytes payload-str "UTF-8") 0 :webrtc/string (+ now-ms 5000))
                           (dc/serialize-network-out))
              a-sent (-> conn-a
                         (assoc :new-state (:new-state send-res))
                         (update :network-out-bytes into (:network-out-bytes send-res [])))
              [_ final-b] (pump-holepunch-or-turn
                           a-sent conn-b via-turn?
                           (fn [_a b] (not-any? #(= :on-message (:type %)) (:app-events b)))
                           50 (+ now-ms 5000))
              msg-ev (first (filter #(= :on-message (:type %)) (:app-events final-b)))]
          (is (some? msg-ev))
          (is (= payload-str (String. ^bytes (:payload msg-ev) "UTF-8"))))))))
