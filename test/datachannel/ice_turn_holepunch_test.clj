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
              relay-frame (fn [sender-state peer-addr ^bytes raw]
                            (if via-turn?
                              (let [tc (:turn-client (:new-state sender-state))
                                    sent (turn/send-via-turn tc peer-addr raw)]
                                (first (:network-out sent)))
                              raw))
              b-rx (reduce (fn [res item]
                             (let [bb (if (map? item) (:packet item) item)
                                   peer-a (InetSocketAddress. "127.0.0.1" 5000)
                                   bytes (relay-frame a (InetSocketAddress. "127.0.0.1" 5001) (bb->bytes bb))
                                   out (dc/handle-receive (:new-state res) bytes now-ms peer-a)]
                               (-> out
                                   (dc/serialize-network-out)
                                   (update :app-events into (:app-events res []))
                                   (update :network-out-bytes into (:network-out-bytes res [])))))
                           (assoc b :network-out-bytes [] :app-events b-events)
                           a-bytes)
              a-rx (reduce (fn [res item]
                             (let [bb (if (map? item) (:packet item) item)
                                   peer-b (InetSocketAddress. "127.0.0.1" 5001)
                                   bytes (relay-frame b (InetSocketAddress. "127.0.0.1" 5000) (bb->bytes bb))
                                   out (dc/handle-receive (:new-state res) bytes now-ms peer-b)]
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

(defn- establish-turn-channel-for-peer
  "Runs the real TURN client state machine through Allocate -> 401 -> Auth Allocate -> Success -> ChannelBind."
  [username password peer-addr channel-num]
  (let [tc0 (turn/init-turn-client {:username username :password password :lifetime 600})
        s1 (turn/start-allocation tc0)
        req1 (turn/parse-turn-packet (first (:network-out s1)))
        r401 (turn/make-allocate-error-response (:tx-id req1) "turn.bitecho.org" "nonce-e2e")
        s2 (turn/step-turn-client (:new-state s1) r401)
        req2 (turn/parse-turn-packet (first (:network-out s2)))
        r-ok (turn/make-allocate-success-response (:tx-id req2) username "turn.bitecho.org" password
                                                  (InetSocketAddress. "198.51.100.1" 49152)
                                                  (InetSocketAddress. "203.0.113.1" 5000)
                                                  600)
        s3 (turn/step-turn-client (:new-state s2) r-ok)
        s4 (turn/request-channel-bind (:new-state s3) channel-num peer-addr)
        req-bind (turn/parse-turn-packet (first (:network-out s4)))
        r-bind (turn/make-channel-bind-success-response (:tx-id req-bind) username "turn.bitecho.org" password)
        s5 (turn/step-turn-client (:new-state s4) r-bind)]
    (:new-state s5)))

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
            tc-a (when via-turn?
                   (establish-turn-channel-for-peer "alice" "secretA" (InetSocketAddress. "127.0.0.1" 5001) 0x4001))
            tc-b (when via-turn?
                   (establish-turn-channel-for-peer "bob" "secretB" (InetSocketAddress. "127.0.0.1" 5000) 0x4001))
            client-a (dc/create-connection {:ice-ufrag "Alice" :ice-pwd "pwdA-123456789012345678"
                                            :remote-ice-ufrag "Bob" :remote-ice-pwd "pwdB-123456789012345678"
                                            :ice-lite? false} true)
            client-b (dc/create-connection {:ice-ufrag "Bob" :ice-pwd "pwdB-123456789012345678"
                                            :remote-ice-ufrag "Alice" :remote-ice-pwd "pwdA-123456789012345678"
                                            :ice-lite? false} false)
            client-a (-> client-a
                         (cond-> tc-a (assoc :turn-client tc-a))
                         (assoc :remote-fingerprint (:fingerprint (:cert-data client-b)))
                         (assoc :remote-candidates [(str (:ip parsed-b) ":" (:port parsed-b))])
                         (assoc-in [:timers :stun/keepalive :expires-at] 0))
            client-b (-> client-b
                         (cond-> tc-b (assoc :turn-client tc-b))
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

(deftest test-unauthenticated-requests-non-nil
  (testing "Unauthenticated refresh, create-permission, and channel-bind return non-nil ByteBuffer"
    (let [ref (turn/make-refresh-request nil nil nil nil 600)
          perm (turn/make-create-permission-request nil nil nil nil (InetSocketAddress. "1.2.3.4" 5000))
          bind (turn/make-channel-bind-request nil nil nil nil 0x4001 (InetSocketAddress. "1.2.3.4" 5000))]
      (is (instance? ByteBuffer ref))
      (is (instance? ByteBuffer perm))
      (is (instance? ByteBuffer bind))
      (is (= turn/METHOD_REFRESH_REQUEST (:msg-type (turn/parse-turn-packet ref))))
      (is (= turn/METHOD_CREATE_PERMISSION_REQUEST (:msg-type (turn/parse-turn-packet perm))))
      (is (= turn/METHOD_CHANNEL_BIND_REQUEST (:msg-type (turn/parse-turn-packet bind)))))))

(deftest test-turn-client-state-machine-full-lifecycle
  (testing "Full TURN client state machine: unauth alloc -> 401 challenge -> auto retry -> alloc success -> permission -> channel bind -> send"
    (let [cli0 (turn/init-turn-client {:username "alice" :password "secret123" :lifetime 600})
          _ (is (= :idle (:state cli0)))
          ;; 1. Start allocation (unauthenticated)
          alloc-step (turn/start-allocation cli0)
          cli1 (:new-state alloc-step)
          alloc-pkt (first (:network-out alloc-step))]
      (is (= :allocating (:state cli1)))
      (is (instance? ByteBuffer alloc-pkt))
      (let [parsed-alloc (turn/parse-turn-packet alloc-pkt)]
        (is (= turn/METHOD_ALLOCATE_REQUEST (:msg-type parsed-alloc)))
        ;; 2. Server responds with 401 challenge
        (let [resp-401 (turn/make-allocate-error-response (:tx-id parsed-alloc) "turn.bitecho.org" "nonce-xyz-999")
              step-401 (turn/step-turn-client cli1 resp-401)
              cli2 (:new-state step-401)
              retry-pkt (first (:network-out step-401))
              retry-evt (first (:events step-401))]
          (is (= :allocating-authenticated (:state cli2)))
          (is (= "turn.bitecho.org" (:realm cli2)))
          (is (= "nonce-xyz-999" (:nonce cli2)))
          (is (= :turn-challenge-retry (:type retry-evt)))
          (is (instance? ByteBuffer retry-pkt))
          ;; 3. Server responds with Allocate Success (with HMAC)
          (let [parsed-retry (turn/parse-turn-packet retry-pkt)
                relayed (InetSocketAddress. "198.51.100.10" 49160)
                mapped (InetSocketAddress. "203.0.113.50" 54321)
                resp-ok (turn/make-allocate-success-response (:tx-id parsed-retry) "alice" "turn.bitecho.org" "secret123" relayed mapped 600)
                ;; First test: tampered HMAC is rejected!
                tampered (let [arr (byte-array (.remaining resp-ok))
                               _ (.get (.duplicate resp-ok) arr)]
                           (aset arr 15 (unchecked-byte (bit-xor (int (aget arr 15)) 0xff)))
                           arr)
                tampered-res (turn/step-turn-client cli2 tampered)]
            (is (= :error (:state (:new-state tampered-res))))
            (is (= :turn-auth-failed (:type (first (:events tampered-res)))))

            ;; Legitimate Allocate Success
            (let [step-alloc-ok (turn/step-turn-client cli2 resp-ok)
                  cli3 (:new-state step-alloc-ok)
                  alloc-evt (first (:events step-alloc-ok))]
              (is (= :allocated (:state cli3)))
              (is (= :turn-allocated (:type alloc-evt)))
              (is (= "198.51.100.10" (get-in cli3 [:relayed-address :ip])))

              ;; 4. Permission creation
              (let [peer-addr (InetSocketAddress. "192.0.2.77" 9999)
                    ;; Sending to unpermitted peer fails closed
                    pre-send (turn/send-via-turn cli3 peer-addr (.getBytes "data" "UTF-8"))
                    _ (is (false? (:ok? pre-send)))
                    _ (is (= :no-permission (:error pre-send)))
                    perm-step (turn/request-permission cli3 peer-addr)
                    cli4 (:new-state perm-step)
                    perm-pkt (first (:network-out perm-step))
                    parsed-perm (turn/parse-turn-packet perm-pkt)
                    resp-perm (turn/make-create-permission-success-response (:tx-id parsed-perm) "alice" "turn.bitecho.org" "secret123")
                    step-perm-ok (turn/step-turn-client cli4 resp-perm)
                    cli5 (:new-state step-perm-ok)]
                (is (= :turn-permission-created (:type (first (:events step-perm-ok)))))
                (is (contains? (:permissions cli5) "192.0.2.77"))

                ;; 5. Send via TURN without channel binding uses Send Indication
                (let [send-res (turn/send-via-turn cli5 peer-addr (.getBytes "hello-peer" "UTF-8"))]
                  (is (true? (:ok? send-res)))
                  (let [parsed-ind (turn/parse-turn-packet (first (:network-out send-res)))]
                    (is (= turn/METHOD_SEND_INDICATION (:msg-type parsed-ind)))))

                ;; 6. Channel binding
                (let [bind-step (turn/request-channel-bind cli5 0x4002 peer-addr)
                      cli6 (:new-state bind-step)
                      bind-pkt (first (:network-out bind-step))
                      parsed-bind (turn/parse-turn-packet bind-pkt)
                      resp-bind (turn/make-channel-bind-success-response (:tx-id parsed-bind) "alice" "turn.bitecho.org" "secret123")
                      step-bind-ok (turn/step-turn-client cli6 resp-bind)
                      cli7 (:new-state step-bind-ok)]
                  (is (= :channel-bound (:state cli7)))
                  (is (= :turn-channel-bound (:type (first (:events step-bind-ok)))))
                  (is (= peer-addr (get-in cli7 [:channels 0x4002])))

                  ;; 7. Send via TURN with bound channel uses ChannelData
                  (let [send-ch (turn/send-via-turn cli7 peer-addr (.getBytes "fast-channel-data" "UTF-8"))]
                    (is (true? (:ok? send-ch)))
                    (let [ch-frame (first (:network-out send-ch))]
                      (is (turn/channel-data? ch-frame))
                      (let [decoded (turn/decode-channel-data ch-frame)]
                        (is (= 0x4002 (:channel-number decoded)))
                        (is (= "fast-channel-data" (String. ^bytes (:data decoded) "UTF-8"))))))

                  ;; 8. Receiving ChannelData from peer
                  (let [incoming-ch (turn/encode-channel-data 0x4002 (.getBytes "inbound-msg" "UTF-8"))
                        rx-step (turn/step-turn-client cli7 incoming-ch)
                        rx-evt (first (:events rx-step))]
                    (is (= :turn-data (:type rx-evt)))
                    (is (= "inbound-msg" (String. ^bytes (:data rx-evt) "UTF-8"))))

                  ;; 9. Receiving ChannelData for unbound channel drops frame
                  (let [unbound-ch (turn/encode-channel-data 0x4009 (.getBytes "unbound" "UTF-8"))
                        drop-step (turn/step-turn-client cli7 unbound-ch)
                        drop-evt (first (:events drop-step))]
                    (is (= :turn-drop (:type drop-evt)))
                    (is (= :unbound-channel (:reason drop-evt)))))))))))))

(deftest test-ice-role-conflict-and-nomination-in-core
  (testing "resolve-role-conflict logic"
    ;; Both controlling: higher tie-breaker sends 487 error, lower switches to controlled
    (let [c1 (stun/resolve-role-conflict :controlling 100 true false 50)
          c2 (stun/resolve-role-conflict :controlling 50 true false 100)]
      (is (= 487 (:error-code c1)))
      (is (= :controlling (:new-role c1)))
      (is (true? (:switched-role? c2)))
      (is (= :controlled (:new-role c2))))
    ;; Both controlled: higher tie-breaker switches to controlling, lower sends 487 error
    (let [d1 (stun/resolve-role-conflict :controlled 50 false true 100)
          d2 (stun/resolve-role-conflict :controlled 100 false true 50)]
      (is (= 487 (:error-code d1)))
      (is (= :controlled (:new-role d1)))
      (is (true? (:switched-role? d2)))
      (is (= :controlling (:new-role d2)))))

  (testing "core/handle-receive STUN nomination, prflx discovery, and role switching"
    (let [state0 (dc/create-connection {:ice-ufrag "local-u"
                                        :ice-pwd "local-pwd-123456789012"
                                        :remote-ice-ufrag "remote-u"
                                        :remote-ice-pwd "remote-pwd-123456789012"
                                        :ice-role :controlled
                                        :ice-tie-breaker 1000} false)
          ;; Incoming Binding Request with USE-CANDIDATE and remote tie-breaker 2000
          req-buf (stun/make-binding-request "remote-u" "local-u" "local-pwd-123456789012"
                                             {:role :controlling
                                              :tie-breaker 2000
                                              :use-candidate? true
                                              :priority 2130706431})
          peer (InetSocketAddress. "198.51.100.99" 7777)
          res (dc/handle-receive state0 (bb->bytes req-buf) 1000 peer)]
      ;; Response generated
      (is (seq (:network-out res)))
      ;; Peer-reflexive candidate added to remote-candidates and seen-candidates
      (is (contains? (:seen-candidates (:new-state res)) "198.51.100.99:7777"))
      (is (some #{"198.51.100.99:7777"} (:remote-candidates (:new-state res))))
      ;; Nominated pair is populated on new-state
      (let [nom (:nominated-pair (:new-state res))]
        (is (some? nom))
        (is (= "198.51.100.99:7777" (:candidate nom)))
        (is (true? (:nominated? nom)))
        (is (true? (:nominated? (:new-state res)))))
      ;; Candidate nomination event emitted
      (is (some #(= :on-ice-candidate-nominated (:type %)) (:app-events res))))))
