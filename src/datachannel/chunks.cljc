(ns datachannel.chunks
  "Cross-platform SCTP chunk processor (DATA, INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK, SACK, HEARTBEAT, SHUTDOWN, FORWARD-TSN)."
  (:require [datachannel.buffer :as b]))

(defn- generate-cookie
  "Generates an HMAC-SHA256 signed cookie encapsulating the TCB parameters to prevent SYN-flood state exhaustion."
  [secret remote-ver-tag remote-tsn negotiated-outbound-streams negotiated-inbound-streams]
  (let [buf (b/allocate-buffer 16)
        _ (b/buf-put-u32! buf remote-ver-tag)
        _ (b/buf-put-u32! buf remote-tsn)
        _ (b/buf-put-u32! buf negotiated-outbound-streams)
        _ (b/buf-put-u32! buf negotiated-inbound-streams)
        _ (b/buf-flip! buf)
        payload (b/buf->bytes buf)
        signature (b/hmac-sha256 secret payload)]
    (b/bconcat [payload signature])))

(defn- verify-and-extract-cookie
  "Verifies the HMAC-SHA256 signature of a received cookie and returns the encapsulated TCB parameters if valid."
  [secret cookie]
  (if (or (nil? cookie) (< (b/blength cookie) 48)) ; 16 bytes payload + 32 bytes SHA256 signature
    nil
    (let [payload (b/bslice cookie 0 16)
          received-sig (b/bslice cookie 16 (b/blength cookie))
          expected-sig (b/hmac-sha256 secret payload)]
      (if (b/bytes= expected-sig received-sig)
        (let [buf (b/wrap-buffer payload)
              remote-ver-tag (b/buf-get-u32! buf)
              remote-tsn (b/buf-get-u32! buf)
              negotiated-outbound-streams (b/buf-get-u32! buf)
              negotiated-inbound-streams (b/buf-get-u32! buf)]
          {:remote-ver-tag remote-ver-tag
           :remote-tsn remote-tsn
           :negotiated-outbound-streams negotiated-outbound-streams
           :negotiated-inbound-streams negotiated-inbound-streams})
        nil))))

(defmulti process-chunk
  "The primary multimethod dispatcher for handling incoming SCTP chunks (DATA, INIT, SACK, HEARTBEAT). Returns state transitions."
  (fn [_state chunk _packet _now-ms] (:type chunk)))

(defn compute-gap-blocks
  "Calculates the offset arrays for SCTP Selective Acknowledgment (SACK) chunks based on the cumulative `remote-tsn` and the set of `out-of-order-tsns`."
  [remote-tsn out-of-order-tsns]
  (if (empty? out-of-order-tsns)
    []
    (let [tsns (seq out-of-order-tsns)]
      (loop [remaining (rest tsns)
             current-start (- (first tsns) remote-tsn)
             current-end (- (first tsns) remote-tsn)
             blocks []]
        (if (empty? remaining)
          (conj blocks [current-start current-end])
          (let [tsn (first remaining)
                offset (- tsn remote-tsn)]
            (if (= offset (inc current-end))
              (recur (rest remaining) current-start offset blocks)
              (recur (rest remaining) offset offset (conj blocks [current-start current-end])))))))))

(defmethod process-chunk :data [state chunk _packet now-ms]
  (let [tsn (:tsn chunk)
        remote-tsn (get state :remote-tsn -1)
        ooo-tsns (get state :out-of-order-tsns (sorted-set))
        diff (b/s32-diff tsn remote-tsn)
        is-newer? (or (= remote-tsn -1) (pos? diff))
        is-duplicate? (and (not is-newer?) (not= remote-tsn -1))]
    (if is-duplicate?
      (let [sack-chunk {:type :sack
                        :cum-tsn-ack remote-tsn
                        :a-rwnd (get state :a-rwnd 262144)
                        :gap-blocks (compute-gap-blocks remote-tsn ooo-tsns)
                        :duplicate-tsns [tsn]}
            s1 (-> state
                   (update :pending-control-chunks conj sack-chunk)
                   (update :timers dissoc :sctp/t-delayed-sack)
                   (assoc :unacked-data-chunks 0))]
        {:next-state s1 :next-events []})
      (let [expected-tsn (if (= remote-tsn -1) tsn (if (= remote-tsn 4294967295) 0 (inc remote-tsn)))
            is-contiguous? (= tsn expected-tsn)
            s1 (if is-contiguous?
                 (loop [curr-tsn tsn
                        curr-ooo ooo-tsns]
                   (let [next-tsn (if (= curr-tsn 4294967295) 0 (inc curr-tsn))]
                     (if (contains? curr-ooo next-tsn)
                       (recur next-tsn (disj curr-ooo next-tsn))
                       (assoc state :remote-tsn curr-tsn :out-of-order-tsns curr-ooo))))
                 (assoc state :out-of-order-tsns (conj ooo-tsns tsn)))

            unacked-chunks (if is-contiguous? (inc (get s1 :unacked-data-chunks 0)) 2)
            send-sack-now? (>= unacked-chunks 2)

            s2 (if send-sack-now?
                 (let [sack-chunk {:type :sack
                                   :cum-tsn-ack (:remote-tsn s1)
                                   :a-rwnd (get s1 :a-rwnd 262144)
                                   :gap-blocks (compute-gap-blocks (:remote-tsn s1) (:out-of-order-tsns s1))
                                   :duplicate-tsns []}]
                   (-> s1
                       (update :pending-control-chunks conj sack-chunk)
                       (update :timers dissoc :sctp/t-delayed-sack)
                       (assoc :unacked-data-chunks 0)))
                 (let [s-timers (if (contains? (:timers s1) :sctp/t-delayed-sack)
                                  s1
                                  (assoc-in s1 [:timers :sctp/t-delayed-sack] {:expires-at (+ now-ms 200) :delay 200}))]
                   (assoc s-timers :unacked-data-chunks unacked-chunks)))

            stream-id (:stream-id chunk)
            recv-q (get-in s2 [:streams stream-id :recv-queue] [])
            max-recv-q (get state :max-receive-queue-size)
            new-chunk-len (b/blength (:payload chunk))
            recv-q-size (reduce + (map #(b/blength (:payload %)) recv-q))
            new-recv-q (if (and max-recv-q (> (+ recv-q-size new-chunk-len) max-recv-q))
                         recv-q
                         (if (some #(= (:tsn %) tsn) recv-q) recv-q (conj recv-q chunk)))
            s3 (assoc-in s2 [:streams stream-id :recv-queue] new-recv-q)]
        {:next-state s3 :next-events []}))))

(defmethod process-chunk :init [state chunk _packet _now-ms]
  (let [local-out (get state :local-outbound-streams 65535)
        local-in (get state :local-inbound-streams 65535)
        remote-out (:outbound-streams chunk 65535)
        remote-in (:inbound-streams chunk 65535)
        negotiated-out (min local-out remote-in)
        negotiated-in (min local-in remote-out)
        remote-ver-tag (:init-tag chunk)
        remote-tsn (if (:initial-tsn chunk) (dec (:initial-tsn chunk)) -1)
        cookie-secret (:cookie-secret state (b/alloc-bytes 32))
        cookie-bytes (generate-cookie cookie-secret remote-ver-tag remote-tsn negotiated-out negotiated-in)
        init-ack-chunk {:type :init-ack
                        :dest-ver-tag remote-ver-tag
                        :init-tag (:local-ver-tag state)
                        :a-rwnd (get state :a-rwnd 262144)
                        :outbound-streams negotiated-out
                        :inbound-streams negotiated-in
                        :initial-tsn (:next-tsn state)
                        :params {:cookie cookie-bytes}}
        s1 (update state :pending-control-chunks conj init-ack-chunk)]
    {:next-state s1 :next-events []}))

(defmethod process-chunk :init-ack [state chunk packet now-ms]
  (let [local-out (get state :local-outbound-streams 65535)
        local-in (get state :local-inbound-streams 65535)
        remote-out (:outbound-streams chunk 65535)
        remote-in (:inbound-streams chunk 65535)
        negotiated-out (min local-out remote-in)
        negotiated-in (min local-in remote-out)
        s1 (assoc state :remote-ver-tag (:init-tag chunk)
                  :remote-tsn (if (:initial-tsn chunk) (dec (:initial-tsn chunk)) -1)
                  :negotiated-outbound-streams negotiated-out
                  :negotiated-inbound-streams negotiated-in)]
    (if-let [cookie (get-in chunk [:params :cookie])]
      (let [cookie-echo-chunk {:type :cookie-echo :cookie cookie}
            out-packet {:src-port (:dst-port packet)
                        :dst-port (:src-port packet)
                        :verification-tag (:init-tag chunk)
                        :chunks [cookie-echo-chunk]}
            s2 (-> s1
                   (assoc :state :cookie-echoed)
                   (update :timers dissoc :sctp/t1-init)
                   (assoc-in [:timers :sctp/t1-cookie] {:expires-at (+ now-ms 3000)
                                                        :delay 3000
                                                        :retries 0
                                                        :packet out-packet})
                   (update :pending-control-chunks conj cookie-echo-chunk))]
        {:next-state s2 :next-events []})
      (let [s2 (assoc state :state :closed
                      :remote-ver-tag (:init-tag chunk))
            abort-chunk {:type :abort}
            s3 (update s2 :pending-control-chunks conj abort-chunk)]
        {:next-state s3 :next-events [{:type :on-error :cause :protocol-violation} {:type :on-close}]}))))

(defmethod process-chunk :cookie-echo [state chunk _packet now-ms]
  (if-let [tcb (verify-and-extract-cookie (:cookie-secret state (b/alloc-bytes 32)) (:cookie chunk))]
    (let [interval (get state :heartbeat-interval 30000)
          s1 (-> state
                 (assoc :state :established
                        :remote-ver-tag (:remote-ver-tag tcb)
                        :remote-tsn (:remote-tsn tcb)
                        :ssn 0
                        :negotiated-outbound-streams (:negotiated-outbound-streams tcb)
                        :negotiated-inbound-streams (:negotiated-inbound-streams tcb))
                 (update :timers dissoc :sctp/t1-init)
                 (update :timers dissoc :sctp/t1-cookie))
          s2 (if (pos? interval)
               (assoc-in s1 [:timers :sctp/t-heartbeat] {:expires-at (+ now-ms interval)})
               s1)
          cookie-ack-chunk {:type :cookie-ack}
          s3 (update s2 :pending-control-chunks conj cookie-ack-chunk)
          has-buffered-data? (some #(seq (:send-queue (val %))) (:streams s3))
          was-established? (= (:state state) :established)
          just-established? (and (not was-established?) (= (:state s3) :established))
          s4 (if (and just-established? has-buffered-data?)
               (assoc-in s3 [:timers :sctp/t3-rtx] {:expires-at (+ now-ms 1000) :delay 1000})
               s3)
          tx-bytes (reduce + (map (fn [st]
                                    (reduce + (map (fn [item]
                                                     (b/blength (:payload (:chunk item))))
                                                   (:send-queue (val st)))))
                                  (:streams s4)))
          s5 (if (and just-established? has-buffered-data?)
               (update-in s4 [:metrics :tx-bytes] (fnil + 0) tx-bytes)
               s4)]
      {:next-state s5 :next-events (if was-established? [] [{:type :on-open}])})
    {:next-state state :next-events []}))

(defmethod process-chunk :cookie-ack [state _chunk packet now-ms]
  (let [interval (get state :heartbeat-interval 30000)
        s1 (-> state
               (update :timers dissoc :sctp/t1-init)
               (update :timers dissoc :sctp/t1-cookie))
        s2 (if (pos? interval)
             (assoc-in s1 [:timers :sctp/t-heartbeat] {:expires-at (+ now-ms interval)})
             s1)
        s3 (if (= (:state s2) :shutdown-pending)
             (let [s-shut (assoc s2 :state :shutdown-sent)
                   shutdown-chunk {:type :shutdown}
                   p {:src-port (:dst-port packet)
                      :dst-port (:src-port packet)
                      :verification-tag (:remote-ver-tag s-shut)
                      :chunks [shutdown-chunk]}
                   s-shut-t (assoc-in s-shut [:timers :sctp/t2-shutdown]
                                      {:expires-at (+ now-ms 3000)
                                       :delay 3000
                                       :retries 0
                                       :packet p})]
               (update s-shut-t :pending-control-chunks conj shutdown-chunk))
             s2)
        s4 (if-not (= (:state s3) :shutdown-sent)
             (assoc s3 :state :established)
             s3)
        has-buffered-data? (some #(seq (:send-queue (val %))) (:streams s4))
        s5 (if (and (contains? #{:cookie-wait :cookie-echoed} (:state state)) (= (:state s4) :established) has-buffered-data?)
             (assoc-in s4 [:timers :sctp/t3-rtx] {:expires-at (+ now-ms 1000) :delay 1000})
             s4)
        tx-bytes (reduce + (map (fn [st]
                                  (reduce + (map (fn [item]
                                                   (b/blength (:payload (:chunk item))))
                                                 (:send-queue (val st)))))
                                (:streams s5)))
        s6 (if (and (contains? #{:cookie-wait :cookie-echoed} (:state state)) (= (:state s4) :established) has-buffered-data?)
             (update-in s5 [:metrics :tx-bytes] (fnil + 0) tx-bytes)
             s5)]
    {:next-state s6 :next-events [{:type :on-open}]}))

(defmethod process-chunk :heartbeat [state chunk _packet _now-ms]
  (let [heartbeat-ack-chunk {:type :heartbeat-ack :params (:params chunk)}
        s1 (update state :pending-control-chunks conj heartbeat-ack-chunk)]
    {:next-state s1 :next-events []}))

(defmethod process-chunk :sack [state chunk _packet _now-ms]
  (let [cum-tsn-ack (:cum-tsn-ack chunk)
        streams (:streams state)
        mtu (get state :mtu 1200)
        old-total-buffered (reduce + (map (fn [[_ v]] (reduce + (map #(b/blength (:payload (:chunk %))) (:send-queue v)))) streams))
        res (reduce-kv
             (fn [acc k v]
               (let [q (:send-queue v)
                     old-buffered (reduce + (map #(b/blength (:payload (:chunk %))) q))
                     acked-items (filter (fn [{:keys [tsn sent?]}]
                                           (and sent? (not (pos? (b/s32-diff tsn cum-tsn-ack)))))
                                         q)
                     acked-bytes (reduce + (map #(+ 16 (b/blength (:payload (:chunk %)))) acked-items))
                     new-q (vec (remove (fn [{:keys [tsn]}]
                                          (not (pos? (b/s32-diff tsn cum-tsn-ack))))
                                        q))
                     new-buffered (reduce + (map #(b/blength (:payload (:chunk %))) new-q))
                     low-threshold (get state :buffered-amount-low-threshold 0)
                     evt (when (and (> old-buffered low-threshold) (<= new-buffered low-threshold))
                           {:type :on-buffered-amount-low :stream-id k})

                     max-gap-tsn (if (empty? (:gap-blocks chunk))
                                   cum-tsn-ack
                                   (+ cum-tsn-ack (second (last (:gap-blocks chunk)))))

                     fast-rtx-count (atom 0)
                     new-q-with-missing (mapv (fn [item]
                                                (let [tsn (:tsn item)
                                                      in-gap? (some (fn [[start end]] (<= (+ cum-tsn-ack start) tsn (+ cum-tsn-ack end))) (:gap-blocks chunk))]
                                                  (if (and (:sent? item) (<= tsn max-gap-tsn) (not in-gap?))
                                                    (let [missing (inc (get item :missing-reports 0))
                                                          fast-rtx? (and (= missing 3) (:sent? item))]
                                                      (when fast-rtx? (swap! fast-rtx-count inc))
                                                      (assoc item :missing-reports missing :sent? (not fast-rtx?) :retries (if fast-rtx? (inc (get item :retries 0)) (get item :retries 0))))
                                                    (assoc item :missing-reports 0))))
                                              new-q)]
                 (-> acc
                     (update :acked-bytes + acked-bytes)
                     (update :fast-retransmits + @fast-rtx-count)
                     (update :new-streams (fn [m]
                                            (if (empty? new-q-with-missing)
                                              (assoc m k (dissoc v :send-queue))
                                              (assoc m k (assoc v :send-queue new-q-with-missing)))))
                     (cond-> evt (update :app-events conj evt)))))
             {:acked-bytes 0 :fast-retransmits 0 :new-streams {} :app-events []}
             streams)
        acked-bytes (:acked-bytes res)
        fast-retransmits (:fast-retransmits res)
        new-streams (:new-streams res)
        new-total-buffered (reduce + (map (fn [[_ v]] (reduce + (map #(b/blength (:payload (:chunk %))) (:send-queue v)))) new-streams))
        total-low-threshold (get state :total-buffered-amount-low-threshold 0)
        total-evt (when (and (> old-total-buffered total-low-threshold) (<= new-total-buffered total-low-threshold))
                    {:type :on-total-buffered-amount-low})
        app-events (if total-evt (conj (:app-events res) total-evt) (:app-events res))
        flight-size (max 0 (- (get state :flight-size 0) acked-bytes))
        cwnd (get state :cwnd 0)
        ssthresh (get state :ssthresh 65535)

        ;; Congestion Control algorithm
        new-cwnd (if (> acked-bytes 0)
                   (if (<= cwnd ssthresh)
                     (+ cwnd (min acked-bytes mtu))
                     (let [partial (+ (get state :partial-bytes-acked 0) acked-bytes)]
                       (if (>= partial cwnd)
                         (+ cwnd mtu)
                         cwnd)))
                   cwnd)
        new-partial (if (> acked-bytes 0)
                      (if (<= cwnd ssthresh)
                        0
                        (let [partial (+ (get state :partial-bytes-acked 0) acked-bytes)]
                          (if (>= partial cwnd)
                            (- partial cwnd)
                            partial)))
                      (get state :partial-bytes-acked 0))

        all-empty? (every? #(empty? (:send-queue (val %))) new-streams)
        total-unacked (reduce + (map (fn [s] (reduce + (map #(+ 16 (b/blength (:payload (:chunk %)))) (:send-queue s)))) (vals new-streams)))

        s1 (-> state
               (assoc :streams new-streams)
               (assoc :flight-size flight-size)
               (assoc :cwnd new-cwnd)
               (update-in [:metrics :retransmissions] (fnil + 0) fast-retransmits)
               (assoc :partial-bytes-acked new-partial)
               (assoc :heartbeat-error-count 0)
               (assoc-in [:metrics :unacked-data] total-unacked))
        s2 (if all-empty?
             (update s1 :timers dissoc :sctp/t3-rtx)
             s1)]
    {:next-state s2 :next-events app-events}))

(defmethod process-chunk :heartbeat-ack [state _chunk _packet _now-ms]
  (let [s1 (-> state
               (assoc :heartbeat-error-count 0)
               (update :timers dissoc :sctp/t-heartbeat-rtx))]
    {:next-state s1 :next-events []}))

(defmethod process-chunk :shutdown [state _chunk packet now-ms]
  (let [was-established? (= (:state state) :established)
        s1 (assoc state :state :shutdown-ack-sent)
        shutdown-ack-chunk {:type :shutdown-ack}
        out-packet {:src-port (:dst-port packet)
                    :dst-port (:src-port packet)
                    :verification-tag (:remote-ver-tag s1)
                    :chunks [shutdown-ack-chunk]}
        s2 (-> s1
               (assoc-in [:timers :sctp/t2-shutdown]
                         {:expires-at (+ now-ms 3000)
                          :delay 3000
                          :retries 0
                          :packet out-packet})
               (update :pending-control-chunks conj shutdown-ack-chunk))
        evts (if was-established? [{:type :on-closing}] [])]
    {:next-state s2 :next-events evts}))

(defmethod process-chunk :shutdown-ack [state _chunk _packet _now-ms]
  (let [s1 (update state :timers dissoc :sctp/t2-shutdown)
        s2 (assoc s1 :state :closed)
        shutdown-complete-chunk {:type :shutdown-complete}
        s3 (update s2 :pending-control-chunks conj shutdown-complete-chunk)]
    {:next-state s3 :next-events [{:type :on-close}]}))

(defmethod process-chunk :shutdown-complete [state _chunk _packet _now-ms]
  (let [s1 (update state :timers dissoc :sctp/t2-shutdown)
        s2 (assoc s1 :state :closed)]
    {:next-state s2 :next-events [{:type :on-close}]}))

(defmethod process-chunk :error [state chunk _packet _now-ms]
  {:next-state state :next-events [{:type :on-error :causes (:causes chunk)}]})

(defmethod process-chunk :abort [state _chunk _packet _now-ms]
  (let [s1 (assoc state :state :closed)]
    {:next-state s1 :next-events [{:type :on-close}]}))

(defmethod process-chunk :forward-tsn [state chunk _packet _now-ms]
  (let [new-cum-tsn (:new-cumulative-tsn chunk)
        remote-tsn (get state :remote-tsn -1)
        ooo-tsns (get state :out-of-order-tsns (sorted-set))
        diff (b/s32-diff new-cum-tsn remote-tsn)
        is-newer? (or (= remote-tsn -1) (pos? diff))]
    (if-not is-newer?
      (let [sack-chunk {:type :sack
                        :cum-tsn-ack remote-tsn
                        :a-rwnd (get state :a-rwnd 262144)
                        :gap-blocks (compute-gap-blocks remote-tsn ooo-tsns)
                        :duplicate-tsns []}]
        {:next-state (-> state
                         (update :pending-control-chunks conj sack-chunk)
                         (update :timers dissoc :sctp/t-delayed-sack)
                         (assoc :unacked-data-chunks 0))
         :next-events []})
      (let [pruned-ooo (into (sorted-set)
                             (filter #(pos? (b/s32-diff % new-cum-tsn))
                                     ooo-tsns))
            s1 (loop [curr-tsn new-cum-tsn
                      curr-ooo pruned-ooo]
                 (let [next-tsn (if (= curr-tsn 4294967295) 0 (inc curr-tsn))]
                   (if (contains? curr-ooo next-tsn)
                     (recur next-tsn (disj curr-ooo next-tsn))
                     (assoc state :remote-tsn curr-tsn :out-of-order-tsns curr-ooo))))
            s2 (reduce (fn [st {:keys [stream-id stream-sequence]}]
                         (let [cur-ssn (get-in st [:streams stream-id :next-ssn] 0)
                               target-ssn (bit-and (inc stream-sequence) 0xffff)
                               ssn-diff (b/s16-diff target-ssn cur-ssn)
                               new-ssn (if (pos? ssn-diff) target-ssn cur-ssn)
                               recv-q (get-in st [:streams stream-id :recv-queue] [])
                               new-recv-q (vec (filter #(pos? (b/s32-diff (:tsn %) new-cum-tsn))
                                                       recv-q))]
                           (-> st
                               (assoc-in [:streams stream-id :next-ssn] new-ssn)
                               (assoc-in [:streams stream-id :recv-queue] new-recv-q))))
                       s1
                       (:streams chunk []))
            sack-chunk {:type :sack
                        :cum-tsn-ack (:remote-tsn s2)
                        :a-rwnd (get s2 :a-rwnd 262144)
                        :gap-blocks (compute-gap-blocks (:remote-tsn s2) (:out-of-order-tsns s2))
                        :duplicate-tsns []}]
        {:next-state (-> s2
                         (update :pending-control-chunks conj sack-chunk)
                         (update :timers dissoc :sctp/t-delayed-sack)
                         (assoc :unacked-data-chunks 0))
         :next-events []}))))

(defmethod process-chunk :default [state chunk _packet _now-ms]
  (let [type-val (:type chunk)]
    (if (number? type-val)
      (let [upper-bits (bit-shift-right (bit-and type-val 0xC0) 6)]
        (cond
          (= upper-bits 1)
          (let [error-chunk {:type :error
                             :causes [{:cause-code 6
                                       :chunk-data (:body chunk)}]}
                s1 (update state :pending-control-chunks conj error-chunk)]
            {:next-state s1 :next-events []})
          :else
          {:next-state state :next-events []}))
      {:next-state state :next-events []})))
