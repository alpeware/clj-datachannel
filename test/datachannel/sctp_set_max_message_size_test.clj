(ns datachannel.sctp-set-max-message-size-test
  (:require [clojure.test :refer [deftest is testing]]
            [datachannel.core :as core]
            [datachannel.sdp :as sdp]))

(deftest set-max-message-size-test
  (testing "Default max message size and a-rwnd are 262144 (256 KiB)"
    (let [state (core/create-connection {} true)]
      (is (= 262144 core/default-max-message-size))
      (is (= 262144 sdp/default-max-message-size))
      (is (= 262144 (:max-message-size state)))
      (is (= 262144 (:a-rwnd state)))))
  (testing "Can set max message size and cap by remote-max-message-size"
    (let [state (core/create-connection {:remote-max-message-size 100000} true)
          _ (is (= 100000 (:max-message-size state)))
          res (core/set-max-message-size state 150000)
          new-state (:new-state res)]
      (is (= 150000 (:max-message-size new-state)))))
  (testing "SDP format-offer, format-answer, and parse-max-message-size"
    (let [offer (sdp/format-offer {:ice-ufrag "u1" :ice-pwd "p1" :fingerprint "AA:BB" :ip "127.0.0.1" :port 5000})
          answer (sdp/format-answer {:ice-ufrag "u2" :ice-pwd "p2" :fingerprint "CC:DD" :ip "127.0.0.1" :port 5001})]
      (is (.contains ^String offer "a=max-message-size:262144\r\n"))
      (is (.contains ^String answer "a=max-message-size:262144\r\n"))
      (is (= 262144 (sdp/parse-max-message-size offer)))
      (is (= 100000 (sdp/parse-max-message-size "v=0\r\na=max-message-size:100000\r\n")))
      (is (nil? (sdp/parse-max-message-size "v=0\r\ns=-\r\n")))))
  (testing "Can send and reassemble a 200 KiB (204,800-byte) message with default 256 KiB max-message-size"
    (let [now-ms 1000
          sender (-> (core/create-connection {} true)
                     (assoc :state :established :remote-ver-tag 2222 :local-ver-tag 1111 :cwnd 1000000))
          receiver (-> (core/create-connection {} false)
                       (assoc :state :established :remote-ver-tag 1111 :local-ver-tag 2222 :remote-tsn -1))
          payload (byte-array 204800)
          _ (dotimes [i 204800]
              (aset-byte payload i (unchecked-byte (mod i 251))))
          send-res (core/send-data sender payload 0 :webrtc/binary now-ms)]
      (loop [s-state (:new-state send-res)
             r-state receiver
             pkts (:network-out send-res)
             delivered []
             iters 0]
        (if (or (seq delivered) (> iters 500))
          (do
            (is (= 1 (count delivered)) "Receiver should reassemble and deliver the 200 KiB message")
            (when (seq delivered)
              (is (= 204800 (alength ^bytes (:payload (first delivered)))))
              (is (java.util.Arrays/equals ^bytes payload ^bytes (:payload (first delivered))))))
          (let [[r-state' s-pkts new-evts]
                (reduce (fn [[rs out-pkts evts] pkt]
                          (let [res (@#'core/handle-sctp-packet rs pkt now-ms)
                                msg-evts (filter #(= :on-message (:type %)) (:app-events res))]
                            [(:new-state res) (into out-pkts (:network-out res)) (into evts msg-evts)]))
                        [r-state [] []]
                        pkts)
                [s-state' next-pkts]
                (reduce (fn [[ss out-pkts] pkt]
                          (let [res (@#'core/handle-sctp-packet ss pkt now-ms)]
                            [(:new-state res) (into out-pkts (:network-out res))]))
                        [s-state []]
                        s-pkts)]
            (recur s-state' r-state' next-pkts (into delivered new-evts) (inc iters))))))))
