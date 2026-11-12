(ns datachannel.determinism-test
  "Generative determinism and O(1) multiverse forking tests for clj-datachannel.
   Verifies bit-for-bit seed reproducibility, pure SimulatedDtlsEngine tamper-resistance,
   anti-replay, certificate fingerprint pinning, and branch isolation."
  (:require [clojure.test :refer [deftest is testing]]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.buffer :as b]
            [datachannel.core :as dc]
            [datachannel.dtls :as dtls]))

;; =============================================================================
;; Helpers
;; =============================================================================

(defn- to-raw-bytes [pkt]
  (cond
    (b/byte-array? pkt) pkt
    (satisfies? b/IBinaryBuffer pkt) (b/buf->bytes pkt)
    (and (map? pkt) (:packet pkt)) (to-raw-bytes (:packet pkt))
    :else (b/to-bytes pkt)))

(defn- bytes-vec [bs]
  (when bs
    (mapv #(b/bget-u8 bs %) (range (b/blength bs)))))

;; =============================================================================
;; 1. SplitMix64 Determinism & Forking Generative Tests
;; =============================================================================

(defspec prop-splitmix64-seed-reproducibility 50
  (prop/for-all [seed gen/large-integer]
                (let [rng1 (b/make-rng seed)
                      rng2 (b/make-rng seed)
                      u64-1 (vec (repeatedly 20 #(b/random-u64 rng1)))
                      u64-2 (vec (repeatedly 20 #(b/random-u64 rng2)))
                      i32-1 (vec (repeatedly 20 #(b/random-int 10000 rng1)))
                      i32-2 (vec (repeatedly 20 #(b/random-int 10000 rng2)))
                      bs1 (vec (repeatedly 10 #(bytes-vec (b/random-bytes 16 rng1))))
                      bs2 (vec (repeatedly 10 #(bytes-vec (b/random-bytes 16 rng2))))]
                  (and (= u64-1 u64-2)
                       (= i32-1 i32-2)
                       (= bs1 bs2)))))

(defspec prop-splitmix64-snapshot-restore 50
  (prop/for-all [seed gen/large-integer]
                (let [rng1 (b/make-rng seed)
                      _ (dotimes [_ 15] (b/random-u64 rng1))
                      snapshot-state (b/rng-state rng1)
                      rng-restored (b/make-rng snapshot-state)
                      seq-original (vec (repeatedly 25 #(b/random-u64 rng1)))
                      seq-restored (vec (repeatedly 25 #(b/random-u64 rng-restored)))]
                  (= seq-original seq-restored))))

(defspec prop-splitmix64-fork-isolation 50
  (prop/for-all [seed gen/large-integer]
                (let [parent (b/make-rng seed)
                      _ (dotimes [_ 5] (b/random-u64 parent))
                      child-a (b/fork-rng parent "branch-a")
                      child-b (b/fork-rng parent "branch-b")
                      child-a2 (b/fork-rng parent "branch-a")
                      seq-a (vec (repeatedly 15 #(b/random-u64 child-a)))
                      seq-b (vec (repeatedly 15 #(b/random-u64 child-b)))
                      seq-a2 (vec (repeatedly 15 #(b/random-u64 child-a2)))]
                  (and (= seq-a seq-a2)
                       (not= seq-a seq-b)))))

;; =============================================================================
;; 2. SimulatedDtlsEngine Unit & Tamper Tests
;; =============================================================================

(deftest test-simulated-dtls-tamper-and-fingerprint
  (testing "SimulatedDtlsEngine handshake, AEAD wrap/unwrap, and bit-flip rejection"
    (let [rng (b/make-rng 1337)
          cert-client (dtls/generate-simulated-cert rng)
          cert-server (dtls/generate-simulated-cert rng)
          c-engine (dtls/create-simulated-engine {:client-mode? true
                                                  :cert-data cert-client
                                                  :remote-fingerprint (:fingerprint cert-server)
                                                  :rng rng})
          s-engine (dtls/create-simulated-engine {:client-mode? false
                                                  :cert-data cert-server
                                                  :remote-fingerprint (:fingerprint cert-client)
                                                  :rng rng})

          ;; Begin handshake role check
          bh-client (dtls/begin-handshake! c-engine)
          bh-server (dtls/begin-handshake! s-engine)
          _ (do (is (seq (:packets bh-client)) "Client begin-handshake! must immediately return non-empty packets")
                (is (empty? (:packets bh-server)) "Server begin-handshake! must return empty packets"))

          ;; Handshake exchange
          ;; Flight 1: ClientHello
          step1 (dtls/handshake-step c-engine b/empty-bytes)
          c-engine1 (:engine step1)
          pkts1 (:packets step1)
          _ (do (is (seq pkts1) "Client should emit ClientHello")
                (is (not (dtls/handshake-finished? c-engine1))))

          ;; Flight 2: Server HelloVerifyRequest (stateless HMAC cookie)
          step2 (dtls/handshake-step s-engine (first pkts1))
          s-engine2 (:engine step2)
          pkts2 (:packets step2)
          _ (do (is (seq pkts2) "Server should respond with HelloVerifyRequest")
                (is (not (dtls/handshake-finished? s-engine2))))

          ;; Flight 3: ClientHello with Cookie
          step3 (dtls/handshake-step c-engine1 (first pkts2))
          c-engine3 (:engine step3)
          pkts3 (:packets step3)
          _ (is (seq pkts3) "Client should respond with ClientHello + Cookie")

          ;; Flight 4: ServerHello + Certificate + Finished
          step4 (dtls/handshake-step s-engine2 (first pkts3))
          s-engine4 (:engine step4)
          pkts4 (:packets step4)
          _ (is (seq pkts4) "Server should send ServerHello+Certificate+Finished")

          ;; Flight 5: Client receives Server flight, sends ClientFinished, marks finished
          step5 (dtls/handshake-step c-engine3 (first pkts4))
          c-engine5 (:engine step5)
          pkts5 (:packets step5)
          _ (do (is (true? (:finished? step5)) "Client handshake should be finished")
                (is (true? (dtls/handshake-finished? c-engine5)))
                (is (seq pkts5) "Client should send ClientFinished"))

          ;; Server receives ClientFinished, marks finished
          step6 (dtls/handshake-step s-engine4 (first pkts5))
          s-engine6 (:engine step6)
          _ (do (is (true? (:finished? step6)) "Server handshake should be finished")
                (is (true? (dtls/handshake-finished? s-engine6))))]

      ;; Mutual certificate fingerprint verification
      (is (true? (dtls/verify-peer-fingerprint c-engine5 (:fingerprint cert-server))))
      (is (true? (dtls/verify-peer-fingerprint s-engine6 (:fingerprint cert-client))))
      (is (false? (dtls/verify-peer-fingerprint c-engine5 "00:11:22:33:44:55")))

      ;; AEAD wrap and unwrap
      (let [plaintext (b/utf8->bytes "Super secret WebRTC payload")
            wrap-res (dtls/wrap-app-data c-engine5 plaintext)
            ciphertext (:bytes wrap-res)
            _c-engine6 (:engine wrap-res)]
        (is (some? ciphertext))
        (is (> (b/blength ciphertext) (b/blength plaintext)))

        ;; Valid unwrap
        (let [unwrap-res (dtls/unwrap-packet s-engine6 ciphertext)]
          (is (= :ok (:status unwrap-res)))
          (is (b/bytes= plaintext (:bytes unwrap-res))))

        ;; Bit-flip corruption detection
        (let [corrupted (b/bslice ciphertext 0 (b/blength ciphertext))
              flip-idx 25
              orig-b (b/bget-u8 corrupted flip-idx)]
          (b/bset-u8! corrupted flip-idx (bit-xor orig-b 0x01))
          (let [unwrap-corrupt (dtls/unwrap-packet s-engine6 corrupted)]
            (is (not= :ok (:status unwrap-corrupt)) "Tampered packet must not succeed")
            (is (nil? (:bytes unwrap-corrupt)) "Tampered packet must fail closed with nil bytes")))

        ;; Truncation corruption detection
        (let [truncated (b/bslice ciphertext 0 (- (b/blength ciphertext) 5))
              unwrap-trunc (dtls/unwrap-packet s-engine6 truncated)]
          (is (not= :ok (:status unwrap-trunc)) "Truncated packet must fail closed")
          (is (nil? (:bytes unwrap-trunc)) "Truncated bytes must be nil"))

        ;; Invalid epoch detection
        (let [bad-epoch (b/bslice ciphertext 0 (b/blength ciphertext))]
          (b/bset-u8! bad-epoch 3 0)
          (b/bset-u8! bad-epoch 4 0) ;; Epoch 0 instead of epoch 1
          (let [unwrap-epoch (dtls/unwrap-packet s-engine6 bad-epoch)]
            (is (= :invalid-epoch (:status unwrap-epoch)) "Mismatched epoch must return :invalid-epoch")
            (is (nil? (:bytes unwrap-epoch)) "Mismatched epoch must return nil bytes")))))))

(deftest test-simulated-dtls-forged-cookie-rejected
  (testing "Forged or corrupted cookie in Flight 3 is rejected by the server (does not advance to ServerHello)"
    (let [rng (b/make-rng 2026)
          cert-client (dtls/generate-simulated-cert rng)
          cert-server (dtls/generate-simulated-cert rng)
          c-engine (dtls/create-simulated-engine {:client-mode? true
                                                  :cert-data cert-client
                                                  :remote-fingerprint (:fingerprint cert-server)
                                                  :rng rng})
          s-engine (dtls/create-simulated-engine {:client-mode? false
                                                  :cert-data cert-server
                                                  :remote-fingerprint (:fingerprint cert-client)
                                                  :rng rng})
          ;; Flight 1
          step1 (dtls/handshake-step c-engine b/empty-bytes)
          pkts1 (:packets step1)
          ;; Flight 2
          step2 (dtls/handshake-step s-engine (first pkts1))
          pkts2 (:packets step2)
          ;; Flight 3: Client generates valid ClientHello with cookie
          step3 (dtls/handshake-step (:engine step1) (first pkts2))
          f3-pkt (first (:packets step3))
          ;; Corrupt cookie bytes in Flight 3 packet
          corrupted-f3 (b/bslice f3-pkt 0 (b/blength f3-pkt))
          _ (b/bset-u8! corrupted-f3 48 (bit-xor (b/bget-u8 corrupted-f3 48) 0xFF))
          ;; Deliver corrupted Flight 3 to server
          server-res (dtls/handshake-step (:engine step2) corrupted-f3)
          server-engine (:engine server-res)]
      (is (= :wait-client-hello-cookie (:phase server-engine)) "Server must not advance to ServerHello on forged cookie")
      (is (false? (:finished? server-res)))
      (is (seq (:packets server-res)) "Server replies with another HelloVerifyRequest")
      (let [reply (first (:packets server-res))]
        (is (= 22 (b/bget-u8 reply 0)))
        (is (= 3 (b/bget-u8 reply 13)))))))

(deftest test-simulated-dtls-finished-verify-data-tamper
  (testing "Corrupted Finished verify_data payload is rejected and fails closed with :handshake-failed"
    (let [rng (b/make-rng 4242)
          cert-client (dtls/generate-simulated-cert rng)
          cert-server (dtls/generate-simulated-cert rng)
          c-engine (dtls/create-simulated-engine {:client-mode? true
                                                  :cert-data cert-client
                                                  :remote-fingerprint (:fingerprint cert-server)
                                                  :rng rng})
          s-engine (dtls/create-simulated-engine {:client-mode? false
                                                  :cert-data cert-server
                                                  :remote-fingerprint (:fingerprint cert-client)
                                                  :rng rng})
          ;; Flight 1..4 normal
          s1 (dtls/handshake-step c-engine b/empty-bytes)
          s2 (dtls/handshake-step s-engine (first (:packets s1)))
          s3 (dtls/handshake-step (:engine s1) (first (:packets s2)))
          s4 (dtls/handshake-step (:engine s2) (first (:packets s3)))
          server-flight (first (:packets s4))

          ;; 1. Corrupt ServerFinished payload received by Client
          corrupted-flight (b/bslice server-flight 0 (b/blength server-flight))
          last-idx (dec (b/blength corrupted-flight))
          _ (b/bset-u8! corrupted-flight last-idx (bit-xor (b/bget-u8 corrupted-flight last-idx) 0xFF))
          client-tamper-res (dtls/handshake-step (:engine s3) corrupted-flight)]
      (is (= :handshake-failed (:status client-tamper-res)) "Client must reject tampered ServerFinished")
      (is (= :failed (:phase (:engine client-tamper-res))))
      (is (false? (:finished? client-tamper-res)))

      ;; 2. Corrupt ClientFinished payload received by Server
      (let [valid-client-step (dtls/handshake-step (:engine s3) server-flight)
            client-fin-pkt (first (:packets valid-client-step))
            corrupted-fin (b/bslice client-fin-pkt 0 (b/blength client-fin-pkt))
            fin-last-idx (dec (b/blength corrupted-fin))
            _ (b/bset-u8! corrupted-fin fin-last-idx (bit-xor (b/bget-u8 corrupted-fin fin-last-idx) 0xFF))
            server-tamper-res (dtls/handshake-step (:engine s4) corrupted-fin)]
        (is (= :handshake-failed (:status server-tamper-res)) "Server must reject tampered ClientFinished")
        (is (= :failed (:phase (:engine server-tamper-res))))
        (is (false? (:finished? server-tamper-res)))))))

;; =============================================================================
;; 3. Full WebRTC Sans-IO Network Pump Simulation
;; =============================================================================

(defn- run-pump
  "Drives two Sans-IO peer connection maps in simulated lockstep time."
  [init-a init-b {:keys [max-iterations start-time loss-fn bitflip-fn
                         initial-a-out initial-b-out]
                  :or {max-iterations 200 start-time 1000}}]
  (let [init-a-ser (dc/serialize-network-out init-a)
        init-b-ser (dc/serialize-network-out init-b)]
    (loop [a (:new-state init-a-ser)
           b (:new-state init-b-ser)
           a-out-bytes (or initial-a-out (vec (:network-out-bytes init-a-ser [])))
           b-out-bytes (or initial-b-out (vec (:network-out-bytes init-b-ser [])))
           all-a-packets []
           all-b-packets []
           tick 0]
      (let [now (+ start-time (* tick 50))]
        (if (or (>= tick max-iterations)
                (and (= :established (:state a))
                     (= :established (:state b))
                     (empty? a-out-bytes)
                     (empty? b-out-bytes)))
          {:state-a a
           :state-b b
           :a-out-bytes a-out-bytes
           :b-out-bytes b-out-bytes
           :a-packets all-a-packets
           :b-packets all-b-packets
           :ticks tick}

          ;; Process in flight packets
          (let [;; A -> B
                [b-after-rx b-replies captured-a-pkts]
                (reduce (fn [[st-b acc-replies cap-pkts] item]
                          (let [raw (to-raw-bytes item)
                                drop? (and loss-fn (loss-fn :a->b tick raw))
                                corrupted (if (and bitflip-fn (not drop?))
                                            (bitflip-fn :a->b tick raw)
                                            raw)]
                            (if drop?
                              [st-b acc-replies (conj cap-pkts {:tick tick :dropped true :bytes (bytes-vec raw)})]
                              (let [rx (-> (dc/handle-receive st-b corrupted now "127.0.0.1:5000")
                                           (dc/serialize-network-out))]
                                [(:new-state rx)
                                 (into acc-replies (:network-out-bytes rx []))
                                 (conj cap-pkts {:tick tick :bytes (bytes-vec raw)})]))))
                        [b [] []]
                        a-out-bytes)

                ;; B -> A
                [a-after-rx a-replies captured-b-pkts]
                (reduce (fn [[st-a acc-replies cap-pkts] item]
                          (let [raw (to-raw-bytes item)
                                drop? (and loss-fn (loss-fn :b->a tick raw))
                                corrupted (if (and bitflip-fn (not drop?))
                                            (bitflip-fn :b->a tick raw)
                                            raw)]
                            (if drop?
                              [st-a acc-replies (conj cap-pkts {:tick tick :dropped true :bytes (bytes-vec raw)})]
                              (let [rx (-> (dc/handle-receive st-a corrupted now "127.0.0.1:5001")
                                           (dc/serialize-network-out))]
                                [(:new-state rx)
                                 (into acc-replies (:network-out-bytes rx []))
                                 (conj cap-pkts {:tick tick :bytes (bytes-vec raw)})]))))
                        [a [] []]
                        b-out-bytes)

                ;; Timers on A
                [a-after-timers a-timer-pkts]
                (reduce (fn [[st acc] [tid timer]]
                          (if (>= now (:expires-at timer))
                            (let [res (-> (dc/handle-timeout st tid now (:dtls/engine st))
                                          (dc/serialize-network-out))]
                              [(:new-state res) (into acc (:network-out-bytes res []))])
                            [st acc]))
                        [a-after-rx []]
                        (get a-after-rx :timers {}))

                ;; Timers on B
                [b-after-timers b-timer-pkts]
                (reduce (fn [[st acc] [tid timer]]
                          (if (>= now (:expires-at timer))
                            (let [res (-> (dc/handle-timeout st tid now (:dtls/engine st))
                                          (dc/serialize-network-out))]
                              [(:new-state res) (into acc (:network-out-bytes res []))])
                            [st acc]))
                        [b-after-rx []]
                        (get b-after-rx :timers {}))

                next-a-out (into a-replies a-timer-pkts)
                next-b-out (into b-replies b-timer-pkts)]

            (recur a-after-timers
                   b-after-timers
                   next-a-out
                   next-b-out
                   (into all-a-packets captured-a-pkts)
                   (into all-b-packets captured-b-pkts)
                   (inc tick))))))))

(defn- create-simulated-peers
  [seed]
  (let [rng-a (b/make-rng seed)
        rng-b (b/make-rng (b/fork-rng rng-a "peer-b"))
        cert-a (dtls/generate-simulated-cert rng-a)
        cert-b (dtls/generate-simulated-cert rng-b)
        base-time 100000

        client-a (dc/create-connection {:seed seed
                                        :now-ms base-time
                                        :simulated-dtls? true
                                        :cert-data cert-a
                                        :remote-fingerprint (:fingerprint cert-b)
                                        :ice-ufrag "AliceUfrag"
                                        :ice-pwd "AlicePwd"
                                        :remote-ice-ufrag "BobUfrag"
                                        :remote-ice-pwd "BobPwd"
                                        :remote-candidates ["127.0.0.1:5001"]}
                                       true)

        client-b (dc/create-connection {:seed (b/random-u64 rng-b)
                                        :now-ms base-time
                                        :simulated-dtls? true
                                        :cert-data cert-b
                                        :remote-fingerprint (:fingerprint cert-a)
                                        :ice-ufrag "BobUfrag"
                                        :ice-pwd "BobPwd"
                                        :remote-ice-ufrag "AliceUfrag"
                                        :remote-ice-pwd "AlicePwd"
                                        :remote-candidates ["127.0.0.1:5000"]}
                                       false)

        ;; Trigger DTLS handshake on Client
        bh-a (dtls/begin-handshake! (:dtls/engine client-a))
        bh-b (dtls/begin-handshake! (:dtls/engine client-b))
        client-a (assoc client-a :dtls/engine (:engine bh-a))
        client-b (assoc client-b :dtls/engine (:engine bh-b))

        ;; Trigger STUN / connect init
        init-a (-> (dc/handle-timeout client-a :stun/keepalive base-time nil)
                   (update :network-out into (:packets bh-a))
                   (assoc-in [:new-state :timers :dtls/flight-timeout] {:expires-at (+ base-time 1000)}))
        init-b (dc/handle-timeout client-b :stun/keepalive base-time nil)]
    [init-a init-b]))

;; =============================================================================
;; 4. Bit-for-Bit Seed Reproducibility Test (Run1 == Run2)
;; =============================================================================

(deftest test-bit-for-bit-seed-reproducibility
  (testing "Two WebRTC Sans-IO runs with identical seed produce 100% byte-for-byte identical packets"
    (let [seed 0xCAFEBABE12345678
          [init-a1 init-b1] (create-simulated-peers seed)
          [init-a2 init-b2] (create-simulated-peers seed)

          res1 (run-pump init-a1 init-b1 {:max-iterations 80 :start-time 200000})
          res2 (run-pump init-a2 init-b2 {:max-iterations 80 :start-time 200000})]

      (is (= :established (:state (:state-a res1))))
      (is (= :established (:state (:state-b res1))))
      (is (= :established (:state (:state-a res2))))
      (is (= :established (:state (:state-b res2))))

      (is (= (:a-packets res1) (:a-packets res2)) "Outbound packets from A must match bit-for-bit")
      (is (= (:b-packets res1) (:b-packets res2)) "Outbound packets from B must match bit-for-bit")
      (is (= (:ticks res1) (:ticks res2)) "Execution steps must match exactly"))))

;; =============================================================================
;; 5. O(1) Multiverse Branch Isolation Test
;; =============================================================================

(defn- clone-peer-state [st]
  (let [rng-copy (when (:rng st) (b/make-rng (b/rng-state (:rng st))))]
    (cond-> (assoc st :rng rng-copy)
      (:turn-client st)
      (assoc-in [:turn-client :rng] (when-let [trng (get-in st [:turn-client :rng])]
                                      (b/make-rng (b/rng-state trng)))))))

(defn- fork-peer-state [st branch-id]
  (let [rng-fork (when (:rng st) (b/fork-rng (:rng st) branch-id))]
    (cond-> (assoc st :rng rng-fork)
      (:turn-client st)
      (assoc-in [:turn-client :rng] (when-let [trng (get-in st [:turn-client :rng])]
                                      (b/fork-rng trng branch-id))))))

(deftest test-multiverse-branch-isolation
  (testing "Forking a mid-handshake state into Branch A and Branch B leaves Branch A 100% unaffected by Branch B mutations"
    (let [seed 0x1122334455667788
          [init-a init-b] (create-simulated-peers seed)

          ;; Run partially to reach mid-handshake
          mid-run (run-pump init-a init-b {:max-iterations 3 :start-time 300000})
          mid-a (:state-a mid-run)
          mid-b (:state-b mid-run)
          mid-a-out (:a-out-bytes mid-run)
          mid-b-out (:b-out-bytes mid-run)

          ;; Fork into Branch A (clone RNG) and Branch B (fork RNG with perturbations)
          branch-a-init {:new-state (clone-peer-state mid-a)}
          branch-b-init {:new-state (fork-peer-state mid-a "branch-b")}

          peer-b-a {:new-state (clone-peer-state mid-b)}
          peer-b-b {:new-state (fork-peer-state mid-b "branch-b")}

          ;; Branch B experiences packet drops and bitflips
          _res-b (run-pump branch-b-init peer-b-b
                           {:max-iterations 40
                            :start-time (+ 300000 (* 3 50))
                            :initial-a-out mid-a-out
                            :initial-b-out mid-b-out
                            :loss-fn (fn [_dir tick _raw] (= tick 1))
                            :bitflip-fn (fn [_dir tick raw]
                                          (if (= tick 2)
                                            (let [cp (b/bslice raw 0 (b/blength raw))]
                                              (b/bset-u8! cp 10 (bit-xor (b/bget-u8 cp 10) 0xAA))
                                              cp)
                                            raw))})

          ;; Branch A continues normally
          res-a (run-pump branch-a-init peer-b-a
                          {:max-iterations 40
                           :start-time (+ 300000 (* 3 50))
                           :initial-a-out mid-a-out
                           :initial-b-out mid-b-out})

          ;; Reference run with zero branching from the same mid-state
          ref-init-a {:new-state (clone-peer-state mid-a)}
          ref-init-b {:new-state (clone-peer-state mid-b)}
          res-ref (run-pump ref-init-a ref-init-b
                            {:max-iterations 40
                             :start-time (+ 300000 (* 3 50))
                             :initial-a-out mid-a-out
                             :initial-b-out mid-b-out})]

      (is (= :established (:state (:state-a res-a))))
      (is (= :established (:state (:state-b res-a))))
      (is (= (:a-packets res-a) (:a-packets res-ref)) "Branch A packets must match non-branched reference run exactly")
      (is (= (:b-packets res-a) (:b-packets res-ref)) "Branch A peer packets must match reference run exactly"))))
