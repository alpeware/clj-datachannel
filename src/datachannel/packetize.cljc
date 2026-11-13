(ns datachannel.packetize
  "Cross-platform SCTP packetizer combining control chunks and stream data within MTU/cwnd/max-burst bounds."
  (:require [datachannel.buffer :as b]))

(defn- build-network-out [state bundled-chunks]
  (if (seq bundled-chunks)
    (let [first-chunk (first bundled-chunks)
          v-tag (if (and (= (:type first-chunk) :init-ack) (:dest-ver-tag first-chunk))
                  (:dest-ver-tag first-chunk)
                  (get state :remote-ver-tag 0))]
      [{:src-port (get state :local-port 5000)
        :dst-port (get state :remote-port 5000)
        :verification-tag v-tag
        :chunks bundled-chunks}])
    []))

(defn- process-control-chunks
  [remaining-ctrl current-streams bundled-chunks current-size current-flight-size max-payload-size state app-events]
  (let [chunk (first remaining-ctrl)
        chunk-size 16] ;; Approximate size
    (if (or (empty? bundled-chunks) (<= (+ current-size chunk-size) max-payload-size))
      {:action :recur
       :args [(rest remaining-ctrl)
              current-streams
              (conj bundled-chunks chunk)
              (+ current-size chunk-size)
              current-flight-size
              app-events
              state]}
      (let [net-out (build-network-out state bundled-chunks)
            new-state (-> state
                          (assoc :pending-control-chunks remaining-ctrl :streams current-streams :flight-size current-flight-size)
                          (cond-> (seq net-out) (update-in [:metrics :tx-packets] (fnil + 0) (count net-out))))]
        {:action :return
         :result {:new-state new-state
                  :network-out net-out
                  :app-events app-events}}))))

(defn- process-stream-data
  [remaining-ctrl current-streams bundled-chunks current-size current-flight-size max-payload-size state app-events now-ms]
  (let [can-send-data? (contains? #{:established :shutdown-pending :shutdown-sent} (:state state))
        eligible-stream-ids (when can-send-data?
                              (->> current-streams
                                   (filter (fn [[_k v]] (some (fn [item] (not (:sent? item))) (:send-queue v))))
                                   (map first)
                                   sort
                                   vec))
        last-id (get state :last-scheduled-stream-id -1)
        chosen-stream-id (when (seq eligible-stream-ids)
                           (or (first (filter #(> % last-id) eligible-stream-ids))
                               (first eligible-stream-ids)))
        active-stream-entry (when chosen-stream-id
                              [chosen-stream-id (get current-streams chosen-stream-id)])]
    (if active-stream-entry
      (let [[stream-id stream-data] active-stream-entry
            cur-state (assoc state :last-scheduled-stream-id chosen-stream-id)
            q (:send-queue stream-data)
            data-idx (first (keep-indexed #(when-not (:sent? %2) %1) q))
            data-item (nth q data-idx)
            data-chunk (:chunk data-item)
            max-lifetime (:max-packet-life-time data-item)
            sent-time (let [sa (:sent-at data-item 0)]
                        (if (and (zero? sa) (pos? now-ms) (not (:sent? data-item)) (zero? (get data-item :retries 0)))
                          (or (:enqueued-at data-item) now-ms)
                          sa))
            expired? (and max-lifetime
                          (if (:enqueued-at data-item)
                            (>= (- now-ms (:enqueued-at data-item)) max-lifetime)
                            (>= now-ms (+ sent-time max-lifetime))))]
        (if expired?
          ;; Drop this fragment (and any others in the same message) and send FORWARD-TSN (RFC 3758 §3.5)
          (let [start-idx (loop [i data-idx]
                            (let [flags (get-in (nth q i) [:chunk :flags] 3)]
                              (if (or (pos? (bit-and flags 2)) (zero? i))
                                i
                                (recur (dec i)))))
                end-idx (loop [i data-idx]
                          (let [flags (get-in (nth q i) [:chunk :flags] 3)]
                            (if (or (pos? (bit-and flags 1)) (>= i (dec (count q))))
                              i
                              (recur (inc i)))))
                dropped-items (subvec q start-idx (inc end-idx))
                new-q (into (subvec q 0 start-idx) (subvec q (inc end-idx)))
                last-dropped-tsn (:tsn (last dropped-items))
                abandoned-bytes (reduce + (map #(if (:sent? %) (+ 16 (b/blength (:payload (:chunk %)))) 0) dropped-items))
                new-flight-size (max 0 (- current-flight-size abandoned-bytes))
                stream-id-to-fwd (get-in (first dropped-items) [:chunk :stream-id] stream-id)
                seq-num-to-fwd (get-in (first dropped-items) [:chunk :seq-num] 0)
                forward-tsn-chunk {:type :forward-tsn :new-cumulative-tsn last-dropped-tsn :streams [{:stream-id stream-id-to-fwd :stream-sequence seq-num-to-fwd}]}
                new-streams (assoc-in current-streams [stream-id :send-queue] new-q)
                new-pending-ctrl (conj remaining-ctrl forward-tsn-chunk)
                old-buffered (reduce + (map #(b/blength (:payload (:chunk %))) q))
                new-buffered (reduce + (map #(b/blength (:payload (:chunk %))) new-q))
                low-threshold (get cur-state :buffered-amount-low-threshold 0)
                new-app-events (if (and (> old-buffered low-threshold) (<= new-buffered low-threshold))
                                 (conj app-events {:type :on-buffered-amount-low :stream-id stream-id})
                                 app-events)]
            {:action :recur
             :args [new-pending-ctrl
                    new-streams
                    bundled-chunks
                    current-size
                    new-flight-size
                    new-app-events
                    cur-state]})
          (let [chunk-size (+ 16 (b/blength (:payload data-chunk)))
                cwnd (get cur-state :cwnd 1000000)]
            (if (and (> current-flight-size 0) (> (+ current-flight-size chunk-size) cwnd))
              ;; Congestion window full
              (let [net-out (build-network-out cur-state bundled-chunks)
                    new-state (-> cur-state
                                  (assoc :pending-control-chunks remaining-ctrl :streams current-streams :flight-size current-flight-size)
                                  (cond-> (seq net-out) (update-in [:metrics :tx-packets] (fnil + 0) (count net-out))))]
                {:action :return
                 :result {:new-state new-state
                          :network-out net-out
                          :app-events app-events}})
              (if (or (empty? bundled-chunks) (<= (+ current-size chunk-size) max-payload-size))
                (let [new-q (assoc q data-idx (assoc data-item :sent? true))
                      new-streams (assoc-in current-streams [stream-id :send-queue] new-q)
                      new-flight-size (if (= (:retries data-item) 0)
                                        (+ current-flight-size chunk-size)
                                        current-flight-size)]
                  {:action :recur
                   :args [remaining-ctrl
                          new-streams
                          (conj bundled-chunks data-chunk)
                          (+ current-size chunk-size)
                          new-flight-size
                          app-events
                          cur-state]})
                ;; Halting when MTU is reached
                (let [net-out (build-network-out cur-state bundled-chunks)
                      new-state (-> cur-state
                                    (assoc :pending-control-chunks remaining-ctrl :streams current-streams :flight-size current-flight-size)
                                    (cond-> (seq net-out) (update-in [:metrics :tx-packets] (fnil + 0) (count net-out))))]
                  {:action :return
                   :result {:new-state new-state
                            :network-out net-out
                            :app-events app-events}}))))))
      ;; No more data in streams
      (let [net-out (build-network-out state bundled-chunks)
            new-state (-> state
                          (assoc :pending-control-chunks remaining-ctrl :streams current-streams :flight-size current-flight-size)
                          (cond-> (seq net-out) (update-in [:metrics :tx-packets] (fnil + 0) (count net-out))))]
        {:action :return
         :result {:new-state new-state
                  :network-out net-out
                  :app-events app-events}}))))

(defn- packetize-step [state app-events now-ms]
  (let [mtu (get state :mtu 1200)
        max-payload-size (- mtu 12)
        pending-ctrl (:pending-control-chunks state)
        streams (:streams state)]
    (if (and (empty? pending-ctrl) (every? empty? (map :send-queue (vals streams))))
      {:new-state state :network-out [] :app-events app-events}
      (loop [remaining-ctrl pending-ctrl
             current-streams streams
             bundled-chunks []
             current-size 0
             current-flight-size (get state :flight-size 0)
             current-app-events app-events
             cur-state state]
        (let [step-result (if (seq remaining-ctrl)
                            (process-control-chunks remaining-ctrl current-streams bundled-chunks current-size current-flight-size max-payload-size cur-state current-app-events)
                            (process-stream-data remaining-ctrl current-streams bundled-chunks current-size current-flight-size max-payload-size cur-state current-app-events now-ms))]
          (if (= (:action step-result) :recur)
            (let [[args-rem-ctrl args-cur-streams args-bundled args-cur-size args-cur-flight args-app-events args-cur-state] (:args step-result)]
              (recur args-rem-ctrl args-cur-streams args-bundled args-cur-size args-cur-flight args-app-events (or args-cur-state cur-state)))
            (:result step-result)))))))

(defn packetize
  "Recursively generates outgoing network packets by combining pending control chunks and active stream data into SCTP packet wrappers bounded by `mtu`, `cwnd`, and `max-burst` congestion parameters defined in RFC 4960."
  [state app-events now-ms]
  (let [max-burst (get state :max-burst 4)]
    (loop [current-state state
           all-pkts []
           current-events app-events
           data-pkts-count 0
           passes 0]
      (if (or (> passes 100) (>= data-pkts-count max-burst))
        {:new-state current-state :network-out all-pkts :app-events current-events}
        (let [step-res (packetize-step current-state current-events now-ms)
              pkts (:network-out step-res)]
          (if (empty? pkts)
            {:new-state current-state :network-out all-pkts :app-events current-events}
            (let [new-data-pkts (count (filter (fn [pkt] (some #(= (:type %) :data) (:chunks pkt))) pkts))]
              (if (and (> data-pkts-count 0) (> (+ data-pkts-count new-data-pkts) max-burst))
                {:new-state current-state :network-out all-pkts :app-events current-events}
                (recur (:new-state step-res) (into all-pkts pkts) (:app-events step-res) (+ data-pkts-count new-data-pkts) (inc passes))))))))))
