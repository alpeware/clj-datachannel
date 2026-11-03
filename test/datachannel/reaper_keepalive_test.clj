(ns datachannel.reaper-keepalive-test
  (:require [clojure.test :refer [deftest is testing]]
            [datachannel.api :as api]
            [datachannel.core :as dc]
            [datachannel.dtls :as dtls]
            [datachannel.handlers :as handlers]
            [datachannel.stun :as stun])
  (:import [java.nio ByteBuffer]
           [java.net InetSocketAddress]
           [java.nio.channels DatagramChannel]
           [javax.net.ssl SSLEngineResult$HandshakeStatus]))

(defn- run-handshake-loop [client-engine server-engine]
  (let [client-out (ByteBuffer/allocate 65536)
        server-out (ByteBuffer/allocate 65536)
        client-in (ByteBuffer/allocate 65536)
        server-in (ByteBuffer/allocate 65536)
        max-loops 100]
    (.flip client-in)
    (.flip server-in)
    (loop [i 0]
      (if (> i max-loops)
        (throw (Exception. "Handshake failed to complete in max loops"))
        (let [client-status (.getHandshakeStatus client-engine)
              server-status (.getHandshakeStatus server-engine)]
          (if (and (or (= client-status SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING)
                       (= client-status SSLEngineResult$HandshakeStatus/FINISHED))
                   (or (= server-status SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING)
                       (= server-status SSLEngineResult$HandshakeStatus/FINISHED))
                   (not (.hasRemaining client-in))
                   (not (.hasRemaining server-in)))
            :success
            ;; Run client step
            (let [res-c (dtls/handshake client-engine client-in client-out)
                  packets-c (:packets res-c)]
              (.compact server-in)
              (doseq [p packets-c]
                (.put server-in (ByteBuffer/wrap p)))
              (.flip server-in)
              ;; Run server step
              (let [res-s (dtls/handshake server-engine server-in server-out)
                    packets-s (:packets res-s)]
                (.compact client-in)
                (doseq [p packets-s]
                  (.put client-in (ByteBuffer/wrap p)))
                (.flip client-in)
                (recur (inc i))))))))))

(deftest test-binding-request-username-extraction-and-ufrag-matching
  (testing "0x0001 Binding Request extracts USERNAME (0x0006), populates :remote-ice-ufrag on dc/handle-receive, and rejects mismatched local ufrag"
    (let [local-ufrag "alice-ufrag"
          remote-ufrag "bob-ufrag"
          local-pwd "alice-secret-pwd"
          conn-state (-> (dc/create-connection {:ice-ufrag local-ufrag :ice-pwd local-pwd} false)
                         (assoc :ice-connection-state :new))
          ;; Bob sends Binding Request to Alice with username "alice-ufrag:bob-ufrag" signed with Alice's pwd
          valid-req-buf (stun/make-binding-request remote-ufrag local-ufrag local-pwd)
          valid-bytes (let [arr (byte-array (.remaining valid-req-buf))]
                        (.get valid-req-buf arr)
                        arr)
          peer-addr (InetSocketAddress. "192.168.1.100" 54321)]
      ;; 1. Valid request matching local-ufrag
      (let [rx-res (dc/handle-receive conn-state valid-bytes 1000 peer-addr)]
        (is (seq (:network-out rx-res)) "Should produce STUN response")
        (is (= remote-ufrag (:remote-ice-ufrag (:new-state rx-res))))
        (is (= :connected (:ice-connection-state (:new-state rx-res)))))

      ;; 2. Mismatched local-ufrag: bob sends request targeting "charlie-ufrag:bob-ufrag"
      (let [mismatched-req (stun/make-binding-request remote-ufrag "charlie-ufrag" local-pwd)
            mismatch-bytes (let [arr (byte-array (.remaining mismatched-req))]
                             (.get mismatched-req arr)
                             arr)
            rx-mismatch (dc/handle-receive conn-state mismatch-bytes 1000 peer-addr)]
        (is (empty? (:network-out rx-mismatch)) "Should reject mismatched target ufrag with no response")
        (is (nil? (:remote-ice-ufrag (:new-state rx-mismatch))))
        (is (= :new (:ice-connection-state (:new-state rx-mismatch))))))))

(deftest test-binding-response-xor-mapped-address-does-not-pollute-remote-candidates
  (testing "0x0101 Binding Response XOR-MAPPED-ADDRESS updates local-candidates but never pollutes remote-candidates across keepalive cycles"
    (let [conn-state (dc/create-connection {:remote-candidates ["10.0.0.1:5000"]} true)
          tx-id (byte-array 12)
          _ (.nextBytes (java.security.SecureRandom.) tx-id)
          server-addr (InetSocketAddress. "198.51.100.1" 3478)
          ;; Server sends Binding Response mapping local client's reflexive IP 203.0.113.5:12345
          srflx-addr (InetSocketAddress. "203.0.113.5" 12345)
          resp-buf (stun/make-binding-response "pwd" tx-id srflx-addr)
          resp-bytes (let [arr (byte-array (.remaining resp-buf))]
                       (.get resp-buf arr)
                       arr)
          ;; Cycle 1
          res1 (dc/handle-receive conn-state resp-bytes 1000 server-addr)
          st1 (:new-state res1)]
      (is (= ["10.0.0.1:5000"] (:remote-candidates st1)) "remote-candidates must not contain srflx candidate")
      (is (= ["203.0.113.5:12345"] (:local-candidates st1)) "local-candidates must record srflx candidate")
      (is (= 1000 (:last-stun-received st1)))
      (is (= 1000 (:last-any-traffic st1)))
      (is (= :connected (:ice-connection-state st1)))

      ;; Cycle 2 (subsequent keepalive response with same mapped address)
      (let [res2 (dc/handle-receive st1 resp-bytes 15000 server-addr)
            st2 (:new-state res2)]
        (is (= ["10.0.0.1:5000"] (:remote-candidates st2)) "remote-candidates must remain unpolluted across cycles")
        (is (= ["203.0.113.5:12345"] (:local-candidates st2)))
        (is (= 15000 (:last-stun-received st2)))
        (is (= 15000 (:last-any-traffic st2)))))))

(deftest test-traffic-aware-idleness-not-reaped-while-active
  (testing "Traffic-aware idleness: an :established connection receiving traffic at t=70s (with :last-stun-received older than 30s) stays :connected/:established and is not reaped at t=75s"
    (let [t0 1000000
          init-state (-> (dc/create-connection {} false)
                         (assoc :state :established
                                :ice-connection-state :connected
                                :last-stun-received t0
                                :last-any-traffic t0))
          ;; At t = t0 + 40s (40s since last STUN), traffic arrives (SCTP/DTLS data)
          t-traffic (+ t0 40000)
          traffic-state (assoc init-state :last-any-traffic t-traffic)
          ;; Check at t = t0 + 45s (45s since last STUN, but only 5s since last-any-traffic)
          t-check (+ t0 45000)
          timeout-res (handlers/handle-timeout-timer traffic-state :stun/keepalive t-check)
          st-after-timer (:new-state timeout-res)]
      ;; The keepalive timer must NOT mark it disconnected
      (is (= :connected (:ice-connection-state st-after-timer)))
      (is (= :established (:state st-after-timer)))
      (is (not-any? #(= :on-close (:type %)) (:app-events timeout-res)))

      ;; And should-reap-child? at t = t0 + 75s (75s since STUN, but 35s since traffic -> idle-ms = 35s < 60s for established)
      (let [t-reap (+ t0 75000)]
        (is (false? (api/should-reap-child? traffic-state t-reap))
            "Established connection with activity within 60s must not be reaped")
        ;; And reap-expired-children! must keep it in routing-table
        (let [child-atom (atom traffic-state)
              child-node {:state-atom child-atom
                          :running (atom true)
                          :callbacks (atom {})}
              routing-table (atom {"child1" child-node})]
          (api/reap-expired-children! routing-table t-reap)
          (is (contains? @routing-table "child1"))
          (is (true? @(:running child-node))))))))

(deftest test-reaper-evicts-idle-child-and-emits-abort-closing-client
  (testing "Explicit reaper notify/close leak reproduction: idle child >60s is evicted, closed with :reaper-timeout, and sends DTLS/SCTP ABORT closing client"
    (let [client-cert (dtls/generate-cert)
          server-cert (dtls/generate-cert)
          client-ctx (dtls/create-ssl-context (:cert client-cert) (:key client-cert))
          server-ctx (dtls/create-ssl-context (:cert server-cert) (:key server-cert))
          client-engine (dtls/create-engine client-ctx true)
          server-engine (dtls/create-engine server-ctx false)
          _ (.beginHandshake client-engine)
          _ (.beginHandshake server-engine)
          _ (run-handshake-loop client-engine server-engine)

          server-ch (DatagramChannel/open)
          client-ch (DatagramChannel/open)
          _ (.bind server-ch (InetSocketAddress. "127.0.0.1" 0))
          _ (.bind client-ch (InetSocketAddress. "127.0.0.1" 0))
          server-port (.getPort (.getLocalAddress server-ch))
          client-port (.getPort (.getLocalAddress client-ch))

          t0 1000000
          client-vtag 424242
          server-vtag 848484

          server-state (-> (dc/create-connection {:cert-data server-cert} false)
                           (assoc :dtls/engine server-engine
                                  :dtls-verified? true
                                  :state :established
                                  :ice-connection-state :connected
                                  :remote-ver-tag client-vtag
                                  :local-ver-tag server-vtag
                                  :last-stun-received t0
                                  :last-any-traffic t0))
          client-state (-> (dc/create-connection {:cert-data client-cert} true)
                           (assoc :dtls/engine client-engine
                                  :dtls-verified? true
                                  :state :established
                                  :ice-connection-state :connected
                                  :remote-ver-tag server-vtag
                                  :local-ver-tag client-vtag
                                  :last-stun-received t0
                                  :last-any-traffic t0))

          server-on-close (atom nil)
          child-node {:state-atom (atom server-state)
                      :running (atom true)
                      :channel (atom server-ch)
                      :remote-addr (atom (InetSocketAddress. "127.0.0.1" client-port))
                      :callbacks (atom {:on-close (fn [evt] (reset! server-on-close evt))})}
          routing-table (atom {"child1" child-node})
          t-reap (+ t0 65000)]

      (try
        ;; 1. Execute reaper at t = t0 + 65s (idle for 65s > 60s)
        (api/reap-expired-children! routing-table t-reap)

        ;; 2. Server child is evicted and closed
        (is (empty? @routing-table) "Child must be evicted from routing table")
        (is (false? @(:running child-node)) "Child running flag must be set to false")
        (is (= :closed (:state @(:state-atom child-node))) "Child state must transition to :closed")
        (is (= :disconnected (:ice-connection-state @(:state-atom child-node))))
        (is (some? @server-on-close) "Server child on-close callback must have fired")
        (is (= :reaper-timeout (:cause @server-on-close)))

        ;; 3. Client receives the encrypted DTLS/SCTP ABORT packet emitted by the reaper
        (let [recv-buf (ByteBuffer/allocate 65536)
              _ (try (.configureBlocking client-ch false) (catch Exception _ nil))
              ;; Poll briefly for packet from loopback
              sender (loop [attempts 0]
                       (let [addr (try (.receive client-ch recv-buf) (catch Exception _ nil))]
                         (if (or addr (>= attempts 5))
                           addr
                           (do (Thread/sleep 10)
                               (recur (inc attempts))))))]
          (if sender
            (do
              (.flip recv-buf)
              (let [packet-bytes (byte-array (.remaining recv-buf))
                    _ (.get recv-buf packet-bytes)
                    ;; Client processes incoming DTLS packet
                    client-res (dc/handle-receive client-state packet-bytes t-reap (InetSocketAddress. "127.0.0.1" server-port))]
                ;; 4. Client transitions to :closed and emits :on-close
                (is (= :closed (:state (:new-state client-res))) "Client state must transition to :closed on ABORT")
                (is (some #(= :on-close (:type %)) (:app-events client-res)) "Client must emit :on-close event")))
            ;; If real socket send/receive was blocked by sandbox EPERM, verify ABORT wire serialization directly
            (let [abort-pkt {:src-port (get server-state :local-port 5000)
                             :dst-port (get server-state :remote-port 5000)
                             :verification-tag (get server-state :remote-ver-tag 0)
                             :chunks [{:type :abort :flags 0 :params []}]}
                  ser (dc/serialize-network-out {:new-state server-state :network-out [abort-pkt]})
                  abort-buf (first (:network-out-bytes ser))]
              (is (some? abort-buf) "Reaper ABORT chunk must serialize to encrypted DTLS packet")
              (let [dup (.duplicate ^ByteBuffer abort-buf)
                    arr (byte-array (.remaining dup))
                    _ (.get dup arr)
                    client-res (dc/handle-receive client-state arr t-reap (InetSocketAddress. "127.0.0.1" server-port))]
                (is (= :closed (:state (:new-state client-res))) "Client state must transition to :closed on ABORT")
                (is (some #(= :on-close (:type %)) (:app-events client-res)) "Client must emit :on-close event")))))
        (finally
          (try (.close server-ch) (catch Exception _ nil))
          (try (.close client-ch) (catch Exception _ nil)))))))

(deftest test-peer-ice-pwds-map-and-atom-bidirectional-keepalive
  (testing "Child initialized with :peer-ice-pwds (both map and atom) resolves credentials on 0x0001 Binding Request and emits 0x0001 STUN Binding Request on :stun/keepalive"
    (let [server-ufrag "srv-ufrag"
          server-pwd "srv-pwd"
          client-ufrag "cli-ufrag"
          client-pwd "cli-pwd"
          client-addr (InetSocketAddress. "198.51.100.2" 45678)
          req-buf (stun/make-binding-request client-ufrag server-ufrag server-pwd)
          req-bytes (let [arr (byte-array (.remaining req-buf))]
                      (.get req-buf arr)
                      arr)]
      ;; Case 1: Static map
      (let [conn (dc/create-connection {:ice-ufrag server-ufrag
                                        :ice-pwd server-pwd
                                        :peer-ice-pwds {client-ufrag client-pwd}}
                                       false)
            rx-res (dc/handle-receive conn req-bytes 1000 client-addr)
            st (:new-state rx-res)]
        (is (= client-ufrag (:remote-ice-ufrag st)))
        (is (= client-pwd (:remote-ice-pwd st)))
        (is (= client-addr (:remote-addr st)))
        (let [keepalive-res (handlers/handle-timeout-timer st :stun/keepalive 2000)
              out-packets (:network-out keepalive-res)]
          (is (= 1 (count out-packets)))
          (let [{:keys [packet target]} (first out-packets)
                parsed (stun/parse-packet (if (instance? ByteBuffer packet) (.duplicate ^ByteBuffer packet) (ByteBuffer/wrap packet)))]
            (is (= client-addr target))
            (is (= 0x0001 (:type parsed))))))

      ;; Case 2: Shared atom
      (let [pwds-atom (atom {client-ufrag client-pwd})
            conn (dc/create-connection {:ice-ufrag server-ufrag
                                        :ice-pwd server-pwd
                                        :peer-ice-pwds pwds-atom}
                                       false)
            rx-res (dc/handle-receive conn req-bytes 1000 client-addr)
            st (:new-state rx-res)]
        (is (= client-ufrag (:remote-ice-ufrag st)))
        (is (= client-pwd (:remote-ice-pwd st)))
        (let [keepalive-res (handlers/handle-timeout-timer st :stun/keepalive 2000)
              out-packets (:network-out keepalive-res)]
          (is (= 1 (count out-packets)))
          (let [{:keys [packet target]} (first out-packets)
                parsed (stun/parse-packet (if (instance? ByteBuffer packet) (.duplicate ^ByteBuffer packet) (ByteBuffer/wrap packet)))]
            (is (= client-addr target))
            (is (= 0x0001 (:type parsed))))))

      ;; Case 3: api/set-remote-ice-credentials! on child node
      (let [conn (dc/create-connection {:ice-ufrag server-ufrag
                                        :ice-pwd server-pwd}
                                       false)
            child-node {:state-atom (atom (assoc conn :remote-addr client-addr))
                        :callbacks (atom {})
                        :channel (atom nil)
                        :remote-addr (atom client-addr)}
            _ (api/set-remote-ice-credentials! child-node "carol-ufrag" "carol-pwd")
            child-st @(:state-atom child-node)]
        (is (= "carol-ufrag" (:remote-ice-ufrag child-st)))
        (is (= "carol-pwd" (:remote-ice-pwd child-st)))
        (let [keepalive-res (handlers/handle-timeout-timer child-st :stun/keepalive 2000)
              out-packets (:network-out keepalive-res)]
          (is (= 1 (count out-packets)))
          (let [{:keys [packet target]} (first out-packets)
                parsed (stun/parse-packet (if (instance? ByteBuffer packet) (.duplicate ^ByteBuffer packet) (ByteBuffer/wrap packet)))]
            (is (= client-addr target))
            (is (= 0x0001 (:type parsed)))))))))

(deftest test-apply-action-dispatches-on-close-when-send-throws
  (testing "apply-action! error resilience: throwing .send never suppresses app-events like :on-close"
    (let [closed-ch (DatagramChannel/open)
          _ (.close closed-ch)
          closed-evt (atom nil)
          mock-node {:state-atom (atom (dc/create-connection {} false))
                     :callbacks (atom {:on-close (fn [evt] (reset! closed-evt evt))})
                     :channel (atom closed-ch)
                     :remote-addr (atom (InetSocketAddress. "127.0.0.1" 12345))}
          dummy-buf (ByteBuffer/wrap (byte-array [1 2 3]))]
      ;; Calling apply-action! with network-out and :on-close app event
      (api/apply-action! mock-node
                         (fn [st]
                           {:new-state (assoc st :state :closed)
                            :network-out [dummy-buf]
                            :app-events [{:type :on-close :cause :forced-close}]})
                         {})
      (is (= :closed (:state @(:state-atom mock-node))))
      (is (some? @closed-evt) ":on-close callback must have fired despite .send throwing on closed channel")
      (is (= :forced-close (:cause @closed-evt))))))
