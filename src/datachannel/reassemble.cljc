(ns datachannel.reassemble
  "Cross-platform SCTP stream reassembler and DCEP frame interceptor."
  (:require [datachannel.buffer :as b]
            [datachannel.dcep :as dcep]))

(defn assemble-payload
  "Concatenates the payloads of a sequence of ordered SCTP fragments into a single contiguous byte array."
  [chunks]
  (b/bconcat (map :payload chunks)))

(defn reassemble-stream
  "Processes the receive queue of an SCTP stream according to RFC 4960, un-fragmenting and ordering inbound data chunks based on Stream Sequence Numbers and U/B/E bits."
  [stream-data]
  (let [q (:recv-queue stream-data [])
        sorted-q (sort #(b/s32-diff (:tsn %1) (:tsn %2)) q)]
    (loop [remaining sorted-q
           current-msg []
           new-q []
           app-events []
           next-ssn (get stream-data :next-ssn 0)]
      (if (empty? remaining)
        (let [final-q (if (seq current-msg) (into new-q current-msg) new-q)]
          {:new-stream (assoc stream-data :recv-queue final-q :next-ssn next-ssn) :app-events app-events})
        (let [chunk (first remaining)
              flags (or (:flags chunk) 0)
              u-bit? (pos? (bit-and flags 4))
              b-bit? (pos? (bit-and flags 2))
              e-bit? (pos? (bit-and flags 1))]
          (if u-bit?
            ;; Unordered
            (if (and b-bit? e-bit?)
              (recur (rest remaining)
                     current-msg
                     new-q
                     (conj app-events {:type :on-message :payload (:payload chunk) :stream-id (:stream-id chunk) :protocol (:protocol chunk)})
                     next-ssn)
              (if b-bit?
                (recur (rest remaining)
                       [chunk]
                       new-q
                       app-events
                       next-ssn)
                (if (seq current-msg)
                  (let [last-chunk (last current-msg)
                        expected-tsn (bit-and (inc (:tsn last-chunk)) 0xFFFFFFFF)]
                    (if (= (:tsn chunk) expected-tsn)
                      (if e-bit?
                        (let [full-msg (conj current-msg chunk)]
                          (recur (rest remaining)
                                 []
                                 new-q
                                 (conj app-events {:type :on-message :payload (assemble-payload full-msg) :stream-id (:stream-id chunk) :protocol (:protocol chunk)})
                                 next-ssn))
                        (recur (rest remaining)
                               (conj current-msg chunk)
                               new-q
                               app-events
                               next-ssn))
                      (recur (rest remaining)
                             current-msg
                             (conj new-q chunk)
                             app-events
                             next-ssn)))
                  (recur (rest remaining)
                         current-msg
                         (conj new-q chunk)
                         app-events
                         next-ssn))))
            ;; Ordered
            (if (= (:seq-num chunk) next-ssn)
              (if (and b-bit? e-bit?)
                (recur (rest remaining)
                       []
                       new-q
                       (conj app-events {:type :on-message :payload (:payload chunk) :stream-id (:stream-id chunk) :protocol (:protocol chunk)})
                       (bit-and (inc next-ssn) 0xFFFF))
                (if b-bit?
                  (recur (rest remaining)
                         [chunk]
                         new-q
                         app-events
                         next-ssn)
                  (if (empty? current-msg)
                    (recur (rest remaining)
                           current-msg
                           (conj new-q chunk)
                           app-events
                           next-ssn)
                    (let [last-chunk (last current-msg)
                          expected-tsn (bit-and (inc (:tsn last-chunk)) 0xFFFFFFFF)]
                      (if (= (:tsn chunk) expected-tsn)
                        (if e-bit?
                          (let [full-msg (conj current-msg chunk)]
                            (recur (rest remaining)
                                   []
                                   new-q
                                   (conj app-events {:type :on-message :payload (assemble-payload full-msg) :stream-id (:stream-id chunk) :protocol (:protocol chunk)})
                                   (bit-and (inc next-ssn) 0xFFFF)))
                          (recur (rest remaining)
                                 (conj current-msg chunk)
                                 new-q
                                 app-events
                                 next-ssn))
                        (recur (rest remaining)
                               current-msg
                               (conj new-q chunk)
                               app-events
                               next-ssn))))))
              (recur (rest remaining)
                     current-msg
                     (conj new-q chunk)
                     app-events
                     next-ssn))))))))

(defn reassemble
  "Iterates over all stream queues in the state machine, running `reassemble-stream` to construct application messages, intercepting DCEP control frames (PPID 50) and emitting the rest to user space."
  [state app-events]
  (let [streams (:streams state)]
    (loop [stream-ids (keys streams)
           current-state state
           current-events app-events]
      (if (empty? stream-ids)
        {:new-state current-state :app-events current-events}
        (let [stream-id (first stream-ids)
              stream-data (get-in current-state [:streams stream-id])
              {:keys [new-stream app-events]} (reassemble-stream stream-data)
              app-events-stream app-events
              dcep-events (filter #(= (:protocol %) :webrtc/dcep) app-events-stream)
              non-dcep-events (filter #(not= (:protocol %) :webrtc/dcep) app-events-stream)

              dcep-results (reduce (fn [acc evt]
                                     (let [st (:state acc)
                                           events (:events acc)
                                           payload (:payload evt)
                                           decoded (dcep/decode-message payload)]
                                       (if (= (:type decoded) :open)
                                         (let [ack-tsn (:next-tsn st)
                                               s2 (update st :next-tsn #(bit-and (inc (long (or % 0))) 0xFFFFFFFF))
                                               sid (:stream-id evt)
                                               ack-ssn (get-in s2 [:streams sid :next-tx-ssn] 0)
                                               s3 (-> s2
                                                      (assoc-in [:streams sid :next-tx-ssn] (bit-and (inc (long ack-ssn)) 0xFFFF))
                                                      (update :ssn (fnil inc 0)))
                                               ack-chunk {:type :data
                                                          :flags 3 ;; B and E bits
                                                          :tsn ack-tsn
                                                          :stream-id sid
                                                          :seq-num ack-ssn
                                                          :protocol :webrtc/dcep
                                                          :payload (dcep/encode-message {:type :ack})}
                                               s4 (assoc-in s3 [:streams sid :send-queue]
                                                            (conj (get-in s3 [:streams sid :send-queue] [])
                                                                  {:tsn ack-tsn :chunk ack-chunk :sent-at 0 :retries 0 :sent? false}))
                                               channel-opts {:ordered (:ordered decoded)
                                                             :max-retransmits (:max-retransmits decoded)
                                                             :max-packet-life-time (:max-packet-life-time decoded)
                                                             :protocol (:protocol decoded)
                                                             :negotiated false
                                                             :label (:label decoded)
                                                             :state :open}
                                               s5 (assoc-in s4 [:data-channels sid] channel-opts)
                                               new-evt {:type :on-data-channel
                                                        :channel (assoc channel-opts :id sid)}]
                                           {:state s5 :events (conj events new-evt)})
                                         (if (= (:type decoded) :ack)
                                           (let [s2 (assoc-in st [:data-channels (:stream-id evt) :state] :open)
                                                 new-evt {:type :on-open :channel-id (:stream-id evt)}]
                                             {:state s2 :events (conj events new-evt)})
                                           acc))))
                                   {:state (assoc-in current-state [:streams stream-id] new-stream)
                                    :events []}
                                   dcep-events)]
          (recur (rest stream-ids)
                 (:state dcep-results)
                 (into current-events (concat non-dcep-events (:events dcep-results)))))))))
