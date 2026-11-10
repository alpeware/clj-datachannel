(ns datachannel.handlers
  (:require [datachannel.buffer :as b]
            [datachannel.chunks :as chunks]
            [datachannel.dtls :as dtls]
            [datachannel.packetize :as packetize]
            [datachannel.stun :as stun]
            [datachannel.turn :as turn]))

(defn resolve-candidate-target
  "Resolves a candidate (InetSocketAddress, 'ip:port' string, or {:ip :port} map)
   into a platform socket address (`InetSocketAddress` on JVM, `{:ip :port}` on CLJS)."
  [cand]
  (b/to-socket-address cand))

(defn wrap-turn-packets
  "Targets TURN control packets to `turn-server-addr` when configured."
  [packets turn-server-addr]
  (let [srv (resolve-candidate-target turn-server-addr)]
    (if srv
      (mapv (fn [pkt] {:packet pkt :target srv}) packets)
      (vec packets))))

(defmulti handle-timeout-timer
  "Multimethod dispatching timeouts for specific timers like `:sctp/t-delayed-sack`, `:sctp/t1-init`, and `:dtls/flight-timeout`. Returns the resulting core state transitions."
  (fn [_state timer-id _now-ms] timer-id))

(defmethod handle-timeout-timer :sctp/t-delayed-sack [state _timer-id _now-ms]
  (let [sack-chunk {:type :sack
                    :cum-tsn-ack (:remote-tsn state)
                    :a-rwnd (get state :a-rwnd 262144)
                    :gap-blocks (chunks/compute-gap-blocks (:remote-tsn state) (:out-of-order-tsns state))
                    :duplicate-tsns []}]
    {:new-state (-> state
                    (update :pending-control-chunks conj sack-chunk)
                    (update :timers dissoc :sctp/t-delayed-sack)
                    (assoc :unacked-data-chunks 0))
     :app-events []}))

(defmethod handle-timeout-timer :sctp/t2-shutdown [state _timer-id now-ms]
  (let [timer (get-in state [:timers :sctp/t2-shutdown])]
    (if-not timer
      {:new-state state :app-events []}
      (let [retries (:retries timer)]
        (if (>= retries 8)
          (let [abort-chunk {:type :abort}]
            {:new-state (-> state
                            (assoc :state :closed)
                            (update :timers dissoc :sctp/t2-shutdown)
                            (update :pending-control-chunks conj abort-chunk))
             :app-events [{:type :on-error :cause :max-retransmissions} {:type :on-close}]})
          (let [new-delay (* (:delay timer) 2)
                new-delay (min new-delay 60000)
                packet (:packet timer)]
            {:new-state (-> state
                            (assoc-in [:timers :sctp/t2-shutdown]
                                      {:expires-at (+ now-ms new-delay)
                                       :delay new-delay
                                       :retries (inc retries)
                                       :packet packet})
                            (update :pending-control-chunks into (:chunks packet)))
             :app-events []}))))))

(defmethod handle-timeout-timer :sctp/t1-init [state _timer-id now-ms]
  (let [timer (get-in state [:timers :sctp/t1-init])
        retries (:retries timer)]
    (if (>= retries 8)
      {:new-state (-> state
                      (assoc :state :closed)
                      (update :timers dissoc :sctp/t1-init))
       :app-events [{:type :on-error :cause :max-retransmissions} {:type :on-close}]}
      (let [new-delay (* (:delay timer) 2)
            new-delay (min new-delay 60000) ;; Cap delay
            packet (:packet timer)]
        {:new-state (-> state
                        (assoc-in [:timers :sctp/t1-init]
                                  {:expires-at (+ now-ms new-delay)
                                   :delay new-delay
                                   :retries (inc retries)
                                   :packet packet})
                        (update :pending-control-chunks into (:chunks packet)))
         :app-events []}))))

(defmethod handle-timeout-timer :sctp/t1-cookie [state _timer-id now-ms]
  (let [timer (get-in state [:timers :sctp/t1-cookie])
        retries (:retries timer)]
    (if (>= retries 8)
      {:new-state (-> state
                      (assoc :state :closed)
                      (update :timers dissoc :sctp/t1-cookie))
       :app-events [{:type :on-error :cause :max-retransmissions} {:type :on-close}]}
      (let [new-delay (* (:delay timer) 2)
            new-delay (min new-delay 60000) ;; Cap delay
            packet (:packet timer)]
        {:new-state (-> state
                        (assoc-in [:timers :sctp/t1-cookie]
                                  {:expires-at (+ now-ms new-delay)
                                   :delay new-delay
                                   :retries (inc retries)
                                   :packet packet})
                        (update :pending-control-chunks into (:chunks packet)))
         :app-events []}))))

(defmethod handle-timeout-timer :sctp/t3-rtx [state _timer-id now-ms]
  (let [timer (get-in state [:timers :sctp/t3-rtx])
        active-streams (filter #(seq (:send-queue (val %))) (:streams state))]
    (if (empty? active-streams)
      ;; If queue is empty, stop the timer
      {:new-state (update state :timers dissoc :sctp/t3-rtx) :app-events []}
      (let [[stream-id stream-data] (first active-streams)
            q (:send-queue stream-data)
            first-item (first q)
            retries (:retries first-item)
            global-max-retries (get state :max-retransmissions 10)
            item-max-retries (:max-retransmits first-item)
            max-retries (if item-max-retries item-max-retries global-max-retries)]
        (if (>= retries max-retries)
          (if item-max-retries
            ;; Partial reliability: abandon message and send FORWARD-TSN
            (let [;; Find all chunks belonging to the same user message (until we see ending flag)
                  dropped-items (loop [items []
                                       rem-q q]
                                  (if (empty? rem-q)
                                    items
                                    (let [it (first rem-q)
                                          flags (get-in it [:chunk :flags] 3)]
                                      (if (pos? (bit-and flags 1)) ; ending flag set
                                        (conj items it)
                                        (recur (conj items it) (rest rem-q))))))
                  new-q (vec (drop (count dropped-items) q))
                  last-dropped-tsn (:tsn (last dropped-items))
                  abandoned-bytes (reduce + (map #(if (:sent? %) (+ 16 (b/blength (:payload (:chunk %)))) 0) dropped-items))
                  new-flight-size (max 0 (- (get state :flight-size 0) abandoned-bytes))
                  stream-id-to-fwd (get-in (first dropped-items) [:chunk :stream-id] stream-id)
                  seq-num-to-fwd (get-in (first dropped-items) [:chunk :seq-num] 0)
                  forward-tsn-chunk {:type :forward-tsn :new-cumulative-tsn last-dropped-tsn :streams [{:stream-id stream-id-to-fwd :stream-sequence seq-num-to-fwd}]}
                  s1 (-> state
                         (assoc-in [:streams stream-id :send-queue] new-q)
                         (assoc :flight-size new-flight-size)
                         (update-in [:metrics :unacked-data] #(max 0 (- (or % 0) (reduce + (map (fn [item] (+ 16 (b/blength (:payload (:chunk item))))) dropped-items)))))
                         (update :pending-control-chunks conj forward-tsn-chunk))
                  s2 (if (empty? new-q)
                       (update s1 :timers dissoc :sctp/t3-rtx)
                       s1)
                  old-buffered (reduce + (map #(b/blength (:payload (:chunk %))) q))
                  new-buffered (reduce + (map #(b/blength (:payload (:chunk %))) new-q))
                  low-threshold (get state :buffered-amount-low-threshold 0)
                  app-events (if (and (> old-buffered low-threshold) (<= new-buffered low-threshold))
                               [{:type :on-buffered-amount-low :stream-id stream-id}]
                               [])]
              {:new-state s2 :app-events app-events})
            ;; Standard SCTP: abort connection
            (let [abort-chunk {:type :abort}]
              {:new-state (-> state
                              (assoc :state :closed)
                              (update :timers dissoc :sctp/t3-rtx)
                              (update :pending-control-chunks conj abort-chunk))
               :app-events [{:type :on-error :cause :max-retransmissions} {:type :on-close}]}))
          (let [new-delay (* (:delay timer) 2)
                new-delay (min new-delay 60000)
                ;; Mark sent? false so packetize will re-transmit it
                updated-item (assoc first-item :retries (inc retries) :sent? false)
                new-q (assoc q 0 updated-item)

                ;; CC backoff
                cwnd (get state :cwnd 1000000)
                mtu (get state :mtu 1200)
                new-ssthresh (max (quot cwnd 2) (* 4 mtu))
                new-cwnd (* 1 mtu)

                ;; flight-size logic: decrease flight-size because we mark it sent?=false
                chunk-size (+ 16 (b/blength (:payload (:chunk first-item))))
                flight-size (max 0 (- (get state :flight-size 0) chunk-size))]
            {:new-state (-> state
                            (assoc-in [:timers :sctp/t3-rtx] {:expires-at (+ now-ms new-delay) :delay new-delay})
                            (update-in [:metrics :retransmissions] (fnil inc 0))
                            (assoc-in [:streams stream-id :send-queue] new-q)
                            (assoc :ssthresh new-ssthresh)
                            (assoc :cwnd (max new-cwnd (+ flight-size chunk-size)))
                            (assoc :flight-size flight-size))
             :app-events []}))))))

(defmethod handle-timeout-timer :sctp/t-heartbeat [state _timer-id now-ms]
  (let [interval (get state :heartbeat-interval 30000)
        rto (get state :rto-initial 1000)
        hb-chunk {:type :heartbeat
                  :params {:heartbeat (b/alloc-bytes 8)}}]
    {:new-state (-> state
                    (assoc-in [:timers :sctp/t-heartbeat] {:expires-at (+ now-ms interval)})
                    (assoc-in [:timers :sctp/t-heartbeat-rtx] {:expires-at (+ now-ms rto)})
                    (update :pending-control-chunks conj hb-chunk))
     :app-events []}))

(defmethod handle-timeout-timer :sctp/t-heartbeat-rtx [state _timer-id _now-ms]
  (let [errors (get state :heartbeat-error-count 0)
        max-retries (get state :max-retransmissions 10)
        new-errors (inc errors)]
    (if (> new-errors max-retries)
      (let [abort-chunk {:type :abort}]
        {:new-state (-> state
                        (assoc :state :closed)
                        (update :timers dissoc :sctp/t-heartbeat :sctp/t-heartbeat-rtx)
                        (update :pending-control-chunks conj abort-chunk))
         :app-events [{:type :on-error :cause :max-retransmissions} {:type :on-close}]})
      {:new-state (-> state
                      (assoc :heartbeat-error-count new-errors)
                      (update :timers dissoc :sctp/t-heartbeat-rtx))
       :app-events []})))

(defmethod handle-timeout-timer :stun/keepalive [state _timer-id now-ms]
  (let [gathering-complete? (= (:ice-gathering-state state) :complete)
        last-activity (max (long (or (:last-any-traffic state) 0))
                           (long (or (:last-stun-received state) now-ms)))
        idle-timeout-ms (if (= (:state state) :established) 60000 30000)
        disconnected? (and (= (:ice-connection-state state) :connected)
                           (> (- now-ms last-activity) idle-timeout-ms))
        new-state (-> state
                      (assoc-in [:timers :stun/keepalive] {:expires-at (+ now-ms 15000)})
                      (cond-> (not gathering-complete?) (assoc :ice-gathering-state :complete))
                      (cond-> disconnected? (assoc :ice-connection-state :disconnected
                                                   :state :closed)))
        app-events (cond-> []
                     (not gathering-complete?) (conj {:type :on-ice-gathering-state-change :state :complete})
                     disconnected? (conj {:type :on-ice-connection-state-change :state :disconnected}
                                         {:type :on-close :cause :ice-keepalive-timeout}))
        stun-opts {:role (or (:ice-role state) (if (:client-mode? state) :controlling :controlled))
                   :tie-breaker (:ice-tie-breaker state)
                   :priority (:local-priority state)
                   :use-candidate? (and (= (or (:ice-role state) (if (:client-mode? state) :controlling :controlled)) :controlling)
                                        (or (= (:nomination-policy state :aggressive) :aggressive)
                                            (boolean (:nominate-on-next-check? state))))}
        network-out (if (:ice-lite? state)
                      []
                      (if (and (:remote-ice-ufrag state) (:remote-ice-pwd state))
                        (let [candidates (:remote-candidates state)]
                          (if (seq candidates)
                            (mapv (fn [cand]
                                    (let [target (resolve-candidate-target cand)
                                          req (stun/make-binding-request (:ice-ufrag state) (:remote-ice-ufrag state) (:remote-ice-pwd state) stun-opts)]
                                      {:packet req :target target}))
                                  candidates)
                            (if (:remote-addr state)
                              (let [req (stun/make-binding-request (:ice-ufrag state) (:remote-ice-ufrag state) (:remote-ice-pwd state) stun-opts)]
                                [{:packet req :target (:remote-addr state)}])
                              [])))
                        []))]
    {:new-state new-state
     :network-out network-out
     :app-events app-events}))

(defmethod handle-timeout-timer :turn/refresh [state _timer-id now-ms]
  (if-let [tc (:turn-client state)]
    (let [turn-srv (or (:turn-server-addr state) (:server-addr tc))
          res (cond
                (= (:state tc) :idle)
                (turn/start-allocation tc)

                (#{:allocated :channel-bound} (:state tc))
                (turn/check-turn-expiry tc now-ms)

                :else
                {:new-state tc :network-out [] :events []})
          tc-new (:new-state res)
          next-state (if (#{:expired :error :closed} (:state tc-new))
                       (-> state
                           (assoc :turn-client tc-new)
                           (update :timers dissoc :turn/refresh))
                       (let [next-exp (if (and (#{:allocated :channel-bound} (:state tc-new))
                                               (:refresh-at-ms tc-new)
                                               (> (long (:refresh-at-ms tc-new)) (+ now-ms 1000)))
                                        (long (:refresh-at-ms tc-new))
                                        (+ now-ms 1000))]
                         (-> state
                             (assoc :turn-client tc-new)
                             (assoc-in [:timers :turn/refresh] {:expires-at next-exp}))))]
      {:new-state next-state
       :network-out (wrap-turn-packets (:network-out res) turn-srv)
       :app-events (vec (:events res))})
    {:new-state (update state :timers dissoc :turn/refresh)
     :network-out []
     :app-events []}))

(defmethod handle-timeout-timer :dtls/flight-timeout [state _timer-id now-ms]
  (if-let [engine (:dtls/engine state)]
    (if (dtls/handshake-finished? engine)
      {:new-state (update state :timers dissoc :dtls/flight-timeout)
       :network-out []
       :app-events []}
      (let [{:keys [packets]} (dtls/handshake-step engine b/empty-bytes)]
        {:new-state (assoc-in state [:timers :dtls/flight-timeout] {:expires-at (+ now-ms 1000)})
         :network-out (vec packets)
         :app-events []}))
    {:new-state (update state :timers dissoc :dtls/flight-timeout)
     :network-out []
     :app-events []}))

(defmethod handle-timeout-timer :default [state _timer-id _now-ms]
  {:new-state state :app-events []})

(defn handle-timeout
  "Routes timer expiries to `handle-timeout-timer` and feeds the resulting state transitions through the `packetize` network generation pipeline."
  [state timer-id now-ms & [_engine]]
  (let [res (handle-timeout-timer state timer-id now-ms)]
    (if (or (seq (:pending-control-chunks (:new-state res)))
            (= "sctp" (namespace timer-id)))
      (packetize/packetize (:new-state res) (:app-events res) now-ms)
      res)))

(defmulti handle-event-type
  "Multimethod dispatching application events like `:connect` and `:shutdown` to trigger SCTP state transitions."
  (fn [_state event _now-ms] (:type event)))

(defmethod handle-event-type :connect [state _event now-ms]
  (let [{:keys [local-ver-tag initial-tsn next-tsn local-outbound-streams local-inbound-streams]} state
        init-tsn (or initial-tsn next-tsn 0)
        init-chunk {:type :init
                    :init-tag local-ver-tag
                    :a-rwnd (get state :a-rwnd 262144)
                    :outbound-streams (or local-outbound-streams 65535)
                    :inbound-streams (or local-inbound-streams 65535)
                    :initial-tsn init-tsn
                    :params []}
        init-packet {:src-port 5000
                     :dst-port 5000
                     :verification-tag 0
                     :chunks [init-chunk]}]
    {:new-state (-> state
                    (assoc :state :cookie-wait)
                    (assoc :next-tsn init-tsn)
                    (assoc-in [:timers :sctp/t1-init] {:expires-at (+ now-ms 3000) :delay 3000 :retries 0 :packet init-packet})
                    (update :pending-control-chunks conj init-chunk))
     :app-events []}))

(defmethod handle-event-type :shutdown [state _event now-ms]
  (if (= (:state state) :established)
    (if (every? empty? (map :send-queue (vals (:streams state))))
      (let [shutdown-chunk {:type :shutdown}
            shutdown-packet {:src-port (get state :local-port 5000)
                             :dst-port (get state :remote-port 5000)
                             :verification-tag (:remote-ver-tag state)
                             :chunks [shutdown-chunk]}
            new-state (-> state
                          (assoc :state :shutdown-sent)
                          (assoc-in [:timers :sctp/t2-shutdown] {:expires-at (+ now-ms 3000) :delay 3000 :retries 0 :packet shutdown-packet})
                          (update :pending-control-chunks conj shutdown-chunk))]
        {:new-state new-state :app-events [{:type :on-closing}]})
      {:new-state (assoc state :state :shutdown-pending) :app-events [{:type :on-closing}]})
    {:new-state state :app-events []}))

(defmethod handle-event-type :set-remote-ice-credentials [state event _now-ms]
  {:new-state (cond-> state
                (:remote-ice-ufrag event) (assoc :remote-ice-ufrag (:remote-ice-ufrag event))
                (:remote-ice-pwd event) (assoc :remote-ice-pwd (:remote-ice-pwd event)))
   :app-events []})

(defmethod handle-event-type :add-remote-candidate [state event _now-ms]
  (let [cand (if (and (:ip event) (:port event))
               {:ip (:ip event) :port (:port event)}
               (:candidate event))
        st1 (cond-> state
              cand (update :remote-candidates (fnil conj []) cand))]
    (if-let [tc (:turn-client st1)]
      (let [turn-srv (or (:turn-server-addr st1) (:server-addr tc))
            relay-res (turn/ensure-peer-relay tc (resolve-candidate-target (or cand event)))]
        {:new-state (assoc st1 :turn-client (:new-state relay-res))
         :network-out (wrap-turn-packets (:network-out relay-res) turn-srv)
         :app-events (vec (:events relay-res))})
      {:new-state st1 :network-out [] :app-events []})))

(defmethod handle-event-type :nominate-candidate [state event _now-ms]
  (let [st1 (assoc state :nominate-on-next-check? true)
        target (or (when-let [c (:candidate event)] (resolve-candidate-target c))
                   (when-let [c (first (:remote-candidates st1))] (resolve-candidate-target c))
                   (:remote-addr st1))
        stun-opts {:role (or (:ice-role st1) :controlling)
                   :tie-breaker (:ice-tie-breaker st1)
                   :priority (:local-priority st1)
                   :use-candidate? true}
        network-out (if (and target (:remote-ice-ufrag st1) (:remote-ice-pwd st1))
                      [{:packet (stun/make-binding-request (:ice-ufrag st1) (:remote-ice-ufrag st1) (:remote-ice-pwd st1) stun-opts)
                        :target target}]
                      [])]
    {:new-state st1
     :network-out network-out
     :app-events []}))

(defmethod handle-event-type :default [state _event _now-ms]
  {:new-state state :app-events []})

(defn handle-event
  "Routes application events to `handle-event-type` and feeds the resulting state transitions through the `packetize` network generation pipeline."
  [state event now-ms]
  (let [res (handle-event-type state event now-ms)
        pkt-res (packetize/packetize (:new-state res) (:app-events res) now-ms)]
    (if (seq (:network-out res))
      (update pkt-res :network-out #(into (vec (:network-out res)) %))
      pkt-res)))
