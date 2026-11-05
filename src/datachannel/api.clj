(ns datachannel.api
  (:require [clojure.string :as str]
            [datachannel.core :as dc]
            [datachannel.dtls :as dtls]
            [datachannel.nio :as nio]
            [datachannel.sdp :as sdp]
            [datachannel.tcp :as tcp])
  (:import [java.net InetSocketAddress StandardSocketOptions]
           [java.nio ByteBuffer]
           [java.nio.channels DatagramChannel SelectionKey Selector ServerSocketChannel SocketChannel]))

(defn set-callbacks!
  "Sets the callbacks for a given node dynamically."
  [node callbacks]
  (reset! (:callbacks node) callbacks))

(defn create-node
  "Prepares a node without starting the network loop.
  `opts` should contain `:port` and optionally `:setup` (e.g. \"active\" or \"passive\")."
  [opts]
  (let [ice-creds (sdp/generate-ice-credentials)
        cert-data (dtls/generate-cert)
        port (get opts :port 5000)
        setup (get opts :setup "passive")
        local-sdp-params {:port port
                          :ice-ufrag (:ufrag ice-creds)
                          :ice-pwd (:pwd ice-creds)
                          :fingerprint (:fingerprint cert-data)
                          :setup setup}]
    {:opts opts
     :cert-data cert-data
     :ice-creds ice-creds
     :local-sdp-params local-sdp-params
     :running (atom false)
     :state-atom (atom nil)
     :channel (atom nil)
     :selector (atom nil)
     :loop-future (atom nil)
     :remote-addr (atom nil)
     :shared-channel? false
     :callbacks (atom nil)}))

(defn apply-action!
  "Applies a pure action function to the state atom sequentially using a lock, extracts effects, and executes them."
  [node action-fn default-callbacks]
  (let [callbacks (or @(:callbacks node) default-callbacks)
        state-atom (:state-atom node)
        effects (locking state-atom
                  (let [st @state-atom
                        res (action-fn st)
                        res-ser (dc/serialize-network-out res)
                        new-st (:new-state res-ser)
                        was-established? (:established-notified? new-st)
                        is-established? (= (:state new-st) :established)
                        should-notify? (and is-established? (not was-established?))
                        final-st (if should-notify? (assoc new-st :established-notified? true) new-st)]
                    (reset! state-atom final-st)
                    (assoc res-ser :should-notify-open? should-notify?)))
        {:keys [network-out-bytes app-events should-notify-open? new-state]} effects
        channel @(:channel node)]
    (let [pure-remote-addr (:remote-addr new-state)]
      (when (and pure-remote-addr (not= pure-remote-addr @(:remote-addr node)))
        (reset! (:remote-addr node) pure-remote-addr)))
    (when channel
      (if (or (:tcp? node) (instance? java.nio.channels.SocketChannel channel))
        (doseq [buf network-out-bytes]
          (try
            (let [pkt-bytes (cond
                              (and (map? buf) (:packet buf))
                              (let [p (:packet buf)]
                                (if (instance? ByteBuffer p)
                                  (let [dup (.duplicate ^ByteBuffer p)
                                        arr (byte-array (.remaining dup))]
                                    (.get dup arr)
                                    arr)
                                  p))
                              (instance? ByteBuffer buf)
                              (let [dup (.duplicate ^ByteBuffer buf)
                                    arr (byte-array (.remaining dup))]
                                (.get dup arr)
                                arr)
                              :else buf)]
              (tcp/write-framed-packet! channel pkt-bytes))
            (catch Exception e
              (when state-atom
                (swap! state-atom
                       (fn [st]
                         (-> (or st {})
                             (update :send-errors (fnil inc 0))
                             (assoc :last-send-error (or (.getMessage e) (.getName (class e)))))))))))
        (doseq [buf network-out-bytes]
          (try
            (if (and (map? buf) (:packet buf))
              (let [{:keys [packet target]} buf
                    dest-addr (cond
                                (instance? java.net.SocketAddress target) target
                                (string? target)
                                (let [[ip port] (str/split target #":")]
                                  (InetSocketAddress. ^String ip (Integer/parseInt port)))
                                (and (map? target) (:ip target) (:port target))
                                (InetSocketAddress. ^String (:ip target) (Integer/parseInt (str (:port target))))
                                :else @(:remote-addr node))
                    wrapped-packet (if (instance? ByteBuffer packet) packet (ByteBuffer/wrap packet))]
                (when dest-addr
                  (.send ^DatagramChannel channel ^ByteBuffer wrapped-packet dest-addr)))
              (let [dest-addr @(:remote-addr node)]
                (when dest-addr
                  (let [wrapped (if (instance? ByteBuffer buf) buf (ByteBuffer/wrap buf))]
                    (.send ^DatagramChannel channel ^ByteBuffer wrapped dest-addr)))))
            (catch Exception e
              (when state-atom
                (swap! state-atom
                       (fn [st]
                         (-> (or st {})
                             (update :send-errors (fnil inc 0))
                             (assoc :last-send-error (or (.getMessage e) (.getName (class e)))))))))))))
    (doseq [evt app-events]
      (case (:type evt)
        :on-message (when-let [cb (:on-message callbacks)]
                      (cb (assoc evt :is-string? (= (:protocol evt) :webrtc/string))))
        :on-error   (when-let [cb (:on-error callbacks)]
                      (cb evt))
        :on-closing (when-let [cb (:on-closing callbacks)]
                      (cb evt))
        :on-close   (when-let [cb (:on-close callbacks)]
                      (cb evt))
        :on-data-channel (when-let [cb (:on-data-channel callbacks)]
                           (cb evt))
        :on-open    (when-let [cb (:on-open callbacks)]
                      (when (:channel-id evt)
                        (cb evt)))
        :on-buffered-amount-low (when-let [cb (:on-buffered-amount-low callbacks)]
                                  (cb evt))
        :on-buffered-amount-high (when-let [cb (:on-buffered-amount-high callbacks)]
                                   (cb evt))
        :on-total-buffered-amount-low (when-let [cb (:on-total-buffered-amount-low callbacks)]
                                        (cb evt))
        :on-ice-candidate (when-let [cb (:on-ice-candidate callbacks)]
                            (cb evt))
        :on-ice-candidate-nominated (when-let [cb (:on-ice-candidate-nominated callbacks)]
                                      (cb evt))
        :on-ice-connection-state-change (when-let [cb (:on-ice-connection-state-change callbacks)]
                                          (cb evt))
        :on-ice-gathering-state-change (when-let [cb (:on-ice-gathering-state-change callbacks)]
                                         (cb evt))
        (:turn-allocated :turn-refreshed :turn-closed :turn-expired
                         :turn-permission-created :turn-channel-bound :turn-challenge-retry :turn-refresh-scheduled)
        (when-let [cb (:on-turn-event callbacks)]
          (cb evt))
        (:turn-error :turn-auth-failed :turn-drop)
        (do
          (when-let [cb (:on-turn-event callbacks)]
            (cb evt))
          (when-let [cb (:on-error callbacks)]
            (cb evt)))
        nil))
    (when should-notify-open?
      (when-let [cb (:on-open callbacks)]
        (cb {})))))

(defn start!
  "Ignites the node. Connects via NIO, starts the loop, and triggers callbacks.
  `remote-sdp-params` must contain `:ip`, `:port`."
  [node remote-sdp-params callbacks]
  (let [local-port (get-in node [:local-sdp-params :port])
        local-setup (get-in node [:local-sdp-params :setup])
        client-mode? (= local-setup "active")

        ;; Initialize pure connection state
        conn-state (dc/create-connection
                    (merge (:opts node)
                           {:cert-data (:cert-data node)
                            :ice-ufrag (:ufrag (:ice-creds node))
                            :ice-pwd (:pwd (:ice-creds node))
                            :remote-ice-ufrag (:remote-ice-ufrag remote-sdp-params)
                            :remote-ice-pwd (:remote-ice-pwd remote-sdp-params)
                            :remote-fingerprint (:fingerprint remote-sdp-params)
                            :remote-max-message-size (or (:remote-max-message-size remote-sdp-params)
                                                         (:max-message-size remote-sdp-params)
                                                         (when-let [rsdp (:remote-sdp remote-sdp-params)]
                                                           (sdp/parse-max-message-size rsdp)))
                            :remote-candidates (if (and (:ip remote-sdp-params) (:port remote-sdp-params))
                                                 [{:ip (:ip remote-sdp-params) :port (:port remote-sdp-params)}]
                                                 [])})
                    client-mode?)

        ;; Set up networking
        ^DatagramChannel channel (nio/create-non-blocking-channel local-port)
        ^Selector selector (nio/create-selector)
        remote-ip (:ip remote-sdp-params)
        remote-port (:port remote-sdp-params)
        remote-addr (if (and remote-ip remote-port)
                      (InetSocketAddress. ^String remote-ip (int remote-port))
                      nil)]

    (nio/register-for-read channel selector)

    (reset! (:channel node) channel)
    (reset! (:selector node) selector)
    (reset! (:state-atom node) conn-state)
    (reset! (:running node) true)
    (reset! (:remote-addr node) remote-addr)

    ;; Start the loop
    (let [fut
          (future
            (let [recv-buf (ByteBuffer/allocateDirect 65536)]
              (while @(:running node)
                (try
                  (let [ready-channels (.select selector 10)
                        now-ms (System/currentTimeMillis)]

                    ;; Process I/O
                    (when (> ready-channels 0)
                      (let [selected-keys (.selectedKeys selector)
                            iter (.iterator selected-keys)]
                        (while (.hasNext iter)
                          (let [^SelectionKey key (.next iter)]
                            (.remove iter)
                            (when (.isReadable key)
                              (.clear recv-buf)
                              (let [sender-addr (.receive channel recv-buf)]
                                (when sender-addr
                                  (.flip recv-buf)
                                  (let [len (.remaining recv-buf)
                                        bytes-arr (byte-array len)]
                                    (.get recv-buf bytes-arr)
                                    (apply-action! node
                                                   (fn [st]
                                                     (dc/handle-receive st bytes-arr now-ms sender-addr))
                                                   callbacks)))))))))

                    ;; Process timeouts
                    (let [current-state @(:state-atom node)
                          timers (:timers current-state)]
                      (doseq [[timer-id timer] timers]
                        (when (>= now-ms (:expires-at timer))
                          (apply-action! node
                                         (fn [st]
                                           (dc/handle-timeout st timer-id now-ms (:dtls/engine st)))
                                         callbacks)))))
                  (catch Exception e
                    (println "Error in api loop:" (.getMessage e))
                    (when-let [cb (:on-error callbacks)]
                      (cb {:type :on-error :cause e})))))))]
      (reset! (:loop-future node) fut)

      ;; If TURN is configured, kick off TURN allocation immediately
      (when (:turn-config (:opts node))
        (apply-action! node
                       (fn [st]
                         (dc/handle-timeout st :turn/refresh (System/currentTimeMillis) nil))
                       callbacks))

      ;; If we are the active side, we should initiate connection
      (when client-mode?
        (future
          (if (:turn-config (:opts node))
            (loop [waited 0]
              (when (and (< waited 1000)
                         (not (#{:allocated :channel-bound}
                               (get-in @(:state-atom node) [:turn-client :state]))))
                (Thread/sleep 20)
                (recur (+ waited 20))))
            (Thread/sleep 100))
          (apply-action! node
                         (fn [st]
                           (dc/handle-timeout st :stun/keepalive (System/currentTimeMillis) nil))
                         callbacks)
          (apply-action! node
                         (fn [st]
                           (when-let [engine (:dtls/engine st)]
                             (.beginHandshake ^javax.net.ssl.SSLEngine engine))
                           (dc/handle-timeout st :dtls/flight-timeout (System/currentTimeMillis) (:dtls/engine st)))
                         callbacks)))
      node)))

(defn get-buffered-amount
  "Returns the current size (in bytes) of the send queue for a given stream."
  [node stream-id]
  (let [state @(:state-atom node)]
    (dc/get-buffered-amount state stream-id)))

(defn get-state
  "Returns the current state of the connection (e.g., :established, :closed)."
  [node]
  (:state @(:state-atom node)))

(defn get-stats
  "Returns the :metrics map from the state atom."
  [node]
  (:metrics @(:state-atom node)))

(defn add-remote-candidate!
  "Adds a remote ICE candidate to the pure connection state for active probing."
  [node ip port]
  (apply-action! node
                 (fn [st]
                   (datachannel.core/handle-event st {:type :add-remote-candidate :ip ip :port port} (System/currentTimeMillis)))
                 {}))

(defn set-remote-ice-credentials!
  "Populates remote ICE credentials (:remote-ice-ufrag and :remote-ice-pwd) on a connected or listener child node."
  [node ufrag pwd]
  (apply-action! node
                 (fn [st]
                   (dc/handle-event st {:type :set-remote-ice-credentials
                                        :remote-ice-ufrag ufrag
                                        :remote-ice-pwd pwd}
                                    (System/currentTimeMillis)))
                 {}))

(defn create-data-channel!
  "Creates a new data channel matching the W3C RTCDataChannel specification.
  Returns the assigned channel id."
  [node label options]
  (let [id-box (atom nil)]
    (apply-action! node
                   (fn [st]
                     (let [res (dc/create-data-channel st label options)]
                       (reset! id-box (:channel-id res))
                       res))
                   {})
    @id-box))

(defn set-max-message-size!
  "Sets the maximum message size that can be sent over the connection.
   Defaults to `dc/default-max-message-size` (262144 bytes / 256 KiB) when `max-size` is omitted."
  ([node]
   (set-max-message-size! node dc/default-max-message-size))
  ([node max-size]
   (apply-action! node
                  (fn [st]
                    (dc/set-max-message-size st max-size))
                  {})))

(defn send!
  "Sends a message (string or byte array) to the connected peer over the given channel-id."
  [node message channel-id]
  (let [payload (if (string? message)
                  (.getBytes ^String message "UTF-8")
                  message)
        protocol (if (string? message) :webrtc/string :webrtc/binary)]
    (apply-action! node
                   (fn [st]
                     (dc/send-data st payload channel-id protocol (System/currentTimeMillis)))
                   {})))

(defn close!
  "Gracefully shuts down the background loop, the socket, and the selector."
  [node]
  (when @(:running node)
    (reset! (:running node) false)
    (when (:state-atom node)
      (apply-action! node
                     (fn [st]
                       (dc/handle-event st {:type :shutdown} (System/currentTimeMillis)))
                     {}))
    (when-let [fut @(:loop-future node)]
      (future-cancel fut))
    (when-let [rt-atom (:routing-table node)]
      (doseq [[_ child] @rt-atom]
        (try (close! child) (catch Exception _ nil)))
      (reset! rt-atom {}))
    (when-not (:shared-channel? node)
      (when-let [^java.io.Closeable channel @(:channel node)]
        (try
          (when (or (not (instance? java.nio.channels.Channel channel))
                    (.isOpen ^java.nio.channels.Channel channel))
            (.close channel))
          (catch Exception _ nil)))
      (when-let [^Selector selector @(:selector node)]
        (try
          (when (.isOpen selector)
            (.close selector))
          (catch Exception _ nil))))
    (reset! (:channel node) nil)
    (reset! (:selector node) nil)
    (reset! (:loop-future node) nil)))

(defn should-reap-child?
  "Pure predicate evaluating whether a child connection should be reaped based on state and activity."
  [st now-ms]
  (let [last-activity (max (long (or (:last-any-traffic st) 0))
                           (long (or (:last-stun-received st) 0)))
        established? (= (:state st) :established)
        idle-ms (- now-ms last-activity)]
    (boolean
     (or (= (:state st) :closed)
         (= (:ice-connection-state st) :failed)
         (and (= (:ice-connection-state st) :disconnected)
              (not established?))
         (and (not established?)
              (not= (:ice-connection-state st) :connected)
              (> idle-ms 30000))
         (> idle-ms 60000)))))

(defn reap-expired-children!
  "Reaps inactive, closed, or dead child nodes from the routing table and executes explicit on-close notification and abort."
  [routing-table now-ms]
  (let [to-reap (keep (fn [[k child]]
                        (when (should-reap-child? @(:state-atom child) now-ms)
                          [k child]))
                      @routing-table)]
    (when (seq to-reap)
      (swap! routing-table
             (fn [rt]
               (apply dissoc rt (map first to-reap))))
      (doseq [[_ child] to-reap]
        (try
          (reset! (:running child) false)
          (let [curr-st @(:state-atom child)]
            (when (not= (:state curr-st) :closed)
              (apply-action! child
                             (fn [st]
                               (let [abort-pkt (when (:dtls-verified? st)
                                                 {:src-port (:local-port st 5000)
                                                  :dst-port (:remote-port st 5000)
                                                  :verification-tag (:remote-ver-tag st 0)
                                                  :chunks [{:type :abort :flags 0 :params []}]})]
                                 {:new-state (-> st
                                                 (assoc :state :closed
                                                        :ice-connection-state :disconnected)
                                                 (assoc :timers {}))
                                  :network-out (if abort-pkt [abort-pkt] [])
                                  :app-events [{:type :on-close :cause :reaper-timeout}]}))
                             @(:callbacks child))))
          (catch Exception _ nil))))))

(defn- listen-loop-body
  "Processes a single iteration of the multiplexed listen loop, handling IO, pure core logic, and routing to callbacks."
  [opts cert-data ice-creds channel selector routing-table listener-callbacks]
  (let [recv-buf (ByteBuffer/allocateDirect 65536)
        last-reap-time (atom (System/currentTimeMillis))]
    (while @(:running listener-callbacks)
      (try
        (let [ready-channels (.select selector 10)
              now-ms (System/currentTimeMillis)]

          ;; Background reaper for routing-table (every 10 seconds)
          (when (> (- now-ms @last-reap-time) 10000)
            (reap-expired-children! routing-table now-ms)
            (reset! last-reap-time now-ms))

          (when (> ready-channels 0)
            (let [selected-keys (.selectedKeys selector)
                  iter (.iterator selected-keys)]
              (while (.hasNext iter)
                (let [^SelectionKey key (.next iter)]
                  (.remove iter)
                  (when (.isReadable key)
                    (.clear recv-buf)
                    (let [sender-addr (.receive channel recv-buf)]
                      (when sender-addr
                        (.flip recv-buf)
                        (let [len (.remaining recv-buf)
                              bytes-arr (byte-array len)]
                          (.get recv-buf bytes-arr)
                          (let [child-node (or (get @routing-table sender-addr)
                                               (let [port (get opts :port 5000)
                                                     new-node {:opts opts
                                                               :cert-data cert-data
                                                               :ice-creds ice-creds
                                                               :local-sdp-params {:port port
                                                                                  :ice-ufrag (:ufrag ice-creds)
                                                                                  :ice-pwd (:pwd ice-creds)
                                                                                  :fingerprint (:fingerprint cert-data)
                                                                                  :setup "passive"}
                                                               :running (atom true)
                                                               :state-atom (atom (dc/create-connection
                                                                                  (merge opts
                                                                                         {:cert-data cert-data
                                                                                          :ice-ufrag (:ufrag ice-creds)
                                                                                          :ice-pwd (:pwd ice-creds)})
                                                                                  false))
                                                               :channel (atom channel)
                                                               :selector (atom selector)
                                                               :loop-future (atom nil)
                                                               :remote-addr (atom sender-addr)
                                                               :shared-channel? true
                                                               :callbacks (atom {})}]
                                                 (swap! routing-table assoc sender-addr new-node)
                                                 (when-let [cb (:on-connection listener-callbacks)]
                                                   (cb new-node))
                                                 new-node))]
                            (apply-action! child-node
                                           (fn [st]
                                             (dc/handle-receive st bytes-arr now-ms sender-addr))
                                           @(:callbacks child-node)))))))))))
          (doseq [[_ child-node] @routing-table]
            (let [current-state @(:state-atom child-node)]
              (when-not (= (:state current-state) :closed)
                (let [timers (:timers current-state)]
                  (doseq [[timer-id timer] timers]
                    (when (>= now-ms (:expires-at timer))
                      (apply-action! child-node
                                     (fn [st]
                                       (dc/handle-timeout st timer-id now-ms (:dtls/engine st)))
                                     @(:callbacks child-node)))))))))
        (catch Exception e
          (println "Error in api listen loop:" (.getMessage e))
          (.printStackTrace e)
          (when-let [cb (:on-error listener-callbacks)]
            (cb {:type :on-error :cause e})))))))

(defn listen!
  "Starts a UDP listener on the given port that can multiplex multiple incoming connections.
  `opts` should contain `:port`.
  `listener-callbacks` should contain `:on-connection` which receives a new child node."
  [opts listener-callbacks]
  (let [port (get opts :port 5000)
        ice-creds (or (:ice-creds opts) (sdp/generate-ice-credentials))
        cert-data (or (:cert-data opts) (dtls/generate-cert))
        ^DatagramChannel channel (nio/create-non-blocking-channel port)
        ^Selector selector (nio/create-selector)
        routing-table (atom {})
        running (atom true)
        listener-node {:opts opts
                       :running running
                       :channel (atom channel)
                       :selector (atom selector)
                       :routing-table routing-table
                       :loop-future (atom nil)
                       :shared-channel? false
                       :ice-creds ice-creds
                       :cert-data cert-data}
        ;; Ensure listener-callbacks tracks running so we can inject
        listener-callbacks (assoc listener-callbacks :running running)]
    (nio/register-for-read channel selector)
    (let [fut (future
                (listen-loop-body opts cert-data ice-creds channel selector routing-table listener-callbacks))]
      (reset! (:loop-future listener-node) fut)
      listener-node)))

;; -----------------------------------------------------------------------------
;; TCP Active Client (RFC 4571 Framing)
;; -----------------------------------------------------------------------------

(defn- start-tcp-io-loop!
  "Runs the NIO selector read loop for a TCP client socket channel."
  [node callbacks]
  (let [^Selector selector @(:selector node)
        ^SocketChannel socket-ch @(:channel node)
        remote-addr @(:remote-addr node)
        deframer-atom (:deframer-atom node)]
    (future
      (let [recv-buf (ByteBuffer/allocateDirect 65536)]
        (while @(:running node)
          (try
            (let [ready (.select selector 10)
                  now-ms (System/currentTimeMillis)]
              (when (pos? ready)
                (let [selected-keys (.selectedKeys selector)
                      iter (.iterator selected-keys)]
                  (while (.hasNext iter)
                    (let [^SelectionKey key (.next iter)]
                      (.remove iter)
                      (when (.isReadable key)
                        (.clear recv-buf)
                        (let [n (try (.read socket-ch recv-buf) (catch Exception _ -1))]
                          (cond
                            (neg? n)
                            (do
                              (reset! (:running node) false)
                              (when-let [cb (:on-close callbacks)]
                                (cb {:type :on-close})))

                            (pos? n)
                            (do
                              (.flip recv-buf)
                              (let [len (.remaining recv-buf)
                                    bytes-arr (byte-array len)]
                                (.get recv-buf bytes-arr)
                                (let [{:keys [frames remaining]} (tcp/decode-rfc4571-stream @deframer-atom bytes-arr)]
                                  (reset! deframer-atom remaining)
                                  (doseq [frame frames]
                                    (apply-action! node
                                                   (fn [st]
                                                     (dc/handle-receive st frame now-ms remote-addr))
                                                   callbacks))))))))))))
              (let [current-state @(:state-atom node)
                    timers (:timers current-state)]
                (doseq [[timer-id timer] timers]
                  (when (>= now-ms (:expires-at timer))
                    (apply-action! node
                                   (fn [st]
                                     (dc/handle-timeout st timer-id now-ms (:dtls/engine st)))
                                   callbacks)))))
            (catch Exception e
              (when @(:running node)
                (when-let [cb (:on-error callbacks)]
                  (cb {:type :on-error :cause e}))))))))))

(defn- start-tcp-client-kickoff!
  "Kicks off active client STUN and DTLS handshake sequence."
  [node callbacks]
  (future
    (Thread/sleep 100)
    (apply-action! node
                   (fn [st]
                     (dc/handle-timeout st :stun/keepalive (System/currentTimeMillis) nil))
                   callbacks)
    (apply-action! node
                   (fn [st]
                     (when-let [engine (:dtls/engine st)]
                       (.beginHandshake ^javax.net.ssl.SSLEngine engine))
                     (dc/handle-timeout st :dtls/flight-timeout (System/currentTimeMillis) (:dtls/engine st)))
                   callbacks)))

(defn start-tcp!
  "Connects to a remote peer via TCP (RFC 4571 framing), starts loop, and triggers callbacks.
  `remote-sdp-params` must contain `:ip`, `:port`. Supports optional `:proxy` in `remote-sdp-params`."
  [node remote-sdp-params callbacks]
  (let [local-setup (get-in node [:local-sdp-params :setup] "active")
        client-mode? (= local-setup "active")
        remote-ip (:ip remote-sdp-params)
        remote-port (int (:port remote-sdp-params))
        remote-addr (InetSocketAddress. ^String remote-ip remote-port)
        conn-state (dc/create-connection
                    (merge (:opts node)
                           {:cert-data (:cert-data node)
                            :ice-ufrag (:ufrag (:ice-creds node))
                            :ice-pwd (:pwd (:ice-creds node))
                            :remote-ice-ufrag (:remote-ice-ufrag remote-sdp-params)
                            :remote-ice-pwd (:remote-ice-pwd remote-sdp-params)
                            :remote-fingerprint (:fingerprint remote-sdp-params)
                            :remote-candidates (if (and remote-ip remote-port)
                                                 [{:ip remote-ip :port remote-port}]
                                                 [])})
                    client-mode?)
        proxy-opts (:proxy remote-sdp-params)
        proxy-res (when (and client-mode? proxy-opts)
                    (tcp/connect-via-proxy-socket-channel proxy-opts remote-ip remote-port 5000))
        socket-ch (if proxy-res
                    (:channel proxy-res)
                    (tcp/connect-socket-channel remote-ip remote-port 5000))
        initial-rem (when proxy-res (:remaining proxy-res))
        ^Selector selector (nio/create-selector)
        deframer-atom (atom (if (and initial-rem (pos? (alength ^bytes initial-rem)))
                              initial-rem
                              (byte-array 0)))]
    (.register socket-ch selector SelectionKey/OP_READ)
    (reset! (:channel node) socket-ch)
    (reset! (:selector node) selector)
    (reset! (:state-atom node) conn-state)
    (reset! (:running node) true)
    (reset! (:remote-addr node) remote-addr)
    (let [tcp-node (assoc node :tcp? true :deframer-atom deframer-atom)
          fut (start-tcp-io-loop! tcp-node callbacks)]
      (reset! (:loop-future node) fut)
      (when client-mode?
        (start-tcp-client-kickoff! tcp-node callbacks))
      tcp-node)))

;; -----------------------------------------------------------------------------
;; TCP Multiplexed Listener (RFC 4571 Framing)
;; -----------------------------------------------------------------------------

(defn- handle-tcp-accept!
  "Accepts incoming client SocketChannel, initializes child node and registers for read."
  [listener-node listener-callbacks]
  (let [server-ch ^ServerSocketChannel @(:channel listener-node)
        selector ^Selector @(:selector listener-node)
        client-ch (.accept server-ch)]
    (when client-ch
      (.setOption client-ch StandardSocketOptions/TCP_NODELAY true)
      (.configureBlocking client-ch false)
      (.register client-ch selector SelectionKey/OP_READ)
      (let [opts (:opts listener-node)
            cert-data (:cert-data listener-node)
            ice-creds (:ice-creds listener-node)
            port (get opts :port 5000)
            remote-addr (.getRemoteAddress client-ch)
            child-node {:opts opts
                        :tcp? true
                        :cert-data cert-data
                        :ice-creds ice-creds
                        :local-sdp-params {:port port
                                           :ice-ufrag (:ufrag ice-creds)
                                           :ice-pwd (:pwd ice-creds)
                                           :fingerprint (:fingerprint cert-data)
                                           :setup "passive"}
                        :running (atom true)
                        :state-atom (atom (dc/create-connection
                                           (merge opts
                                                  {:cert-data cert-data
                                                   :ice-ufrag (:ufrag ice-creds)
                                                   :ice-pwd (:pwd ice-creds)})
                                           false))
                        :channel (atom client-ch)
                        :selector (atom selector)
                        :loop-future (atom nil)
                        :remote-addr (atom remote-addr)
                        :deframer-atom (atom (byte-array 0))
                        :shared-channel? false
                        :callbacks (atom {})}]
        (swap! (:routing-table listener-node) assoc client-ch child-node)
        (when-let [cb (:on-connection listener-callbacks)]
          (cb child-node))))))

(defn- handle-tcp-read!
  "Reads from client SocketChannel, deframes RFC 4571 packets, and feeds to child node."
  [^SelectionKey key routing-table ^ByteBuffer recv-buf now-ms]
  (let [client-ch ^SocketChannel (.channel key)]
    (if-let [child-node (get @routing-table client-ch)]
      (do
        (.clear recv-buf)
        (let [n (try (.read client-ch recv-buf) (catch Exception _ -1))]
          (cond
            (neg? n)
            (do
              (swap! routing-table dissoc client-ch)
              (try (.close client-ch) (catch Exception _ nil))
              (reset! (:running child-node) false)
              (when-let [cb (:on-close @(:callbacks child-node))]
                (cb {:type :on-close})))

            (pos? n)
            (do
              (.flip recv-buf)
              (let [len (.remaining recv-buf)
                    bytes-arr (byte-array len)]
                (.get recv-buf bytes-arr)
                (let [{:keys [frames remaining]} (tcp/decode-rfc4571-stream @(:deframer-atom child-node) bytes-arr)]
                  (reset! (:deframer-atom child-node) remaining)
                  (doseq [frame frames]
                    (apply-action! child-node
                                   (fn [st]
                                     (dc/handle-receive st frame now-ms @(:remote-addr child-node)))
                                   @(:callbacks child-node)))))))))
      (try (.cancel key) (.close client-ch) (catch Exception _ nil)))))

(defn- reap-tcp-connections!
  "Reaps inactive or closed client connections from routing table."
  [routing-table now-ms]
  (let [to-reap (keep (fn [[ch child]]
                        (let [st @(:state-atom child)
                              dead? (or (not (.isOpen ^SocketChannel ch))
                                        (should-reap-child? st now-ms))]
                          (when dead?
                            [ch child])))
                      @routing-table)]
    (when (seq to-reap)
      (swap! routing-table
             (fn [rt]
               (apply dissoc rt (map first to-reap))))
      (doseq [[ch child] to-reap]
        (try
          (reset! (:running child) false)
          (let [curr-st @(:state-atom child)]
            (when (not= (:state curr-st) :closed)
              (apply-action! child
                             (fn [st]
                               (let [abort-pkt (when (:dtls-verified? st)
                                                 {:src-port (:local-port st 5000)
                                                  :dst-port (:remote-port st 5000)
                                                  :verification-tag (:remote-ver-tag st 0)
                                                  :chunks [{:type :abort :flags 0 :params []}]})]
                                 {:new-state (-> st
                                                 (assoc :state :closed
                                                        :ice-connection-state :disconnected)
                                                 (assoc :timers {}))
                                  :network-out (if abort-pkt [abort-pkt] [])
                                  :app-events [{:type :on-close :cause :reaper-timeout}]}))
                             @(:callbacks child))))
          (catch Exception _ nil)
          (finally
            (try (.close ^SocketChannel ch) (catch Exception _ nil))))))))

(defn- tcp-listen-loop-body
  "Processes TCP multiplexed listen loop, accepting clients, deframing packets, and firing timers."
  [listener-node listener-callbacks]
  (let [selector ^Selector @(:selector listener-node)
        routing-table (:routing-table listener-node)
        recv-buf (ByteBuffer/allocateDirect 65536)
        last-reap (atom (System/currentTimeMillis))]
    (while @(:running listener-callbacks)
      (try
        (let [ready (.select selector 10)
              now-ms (System/currentTimeMillis)]
          (when (> (- now-ms @last-reap) 10000)
            (reap-tcp-connections! routing-table now-ms)
            (reset! last-reap now-ms))
          (when (pos? ready)
            (let [selected-keys (.selectedKeys selector)
                  iter (.iterator selected-keys)]
              (while (.hasNext iter)
                (let [^SelectionKey key (.next iter)]
                  (.remove iter)
                  (cond
                    (.isAcceptable key)
                    (handle-tcp-accept! listener-node listener-callbacks)

                    (.isReadable key)
                    (handle-tcp-read! key routing-table recv-buf now-ms))))))
          (doseq [[_ child-node] @routing-table]
            (let [current-state @(:state-atom child-node)]
              (when-not (= (:state current-state) :closed)
                (let [timers (:timers current-state)]
                  (doseq [[timer-id timer] timers]
                    (when (>= now-ms (:expires-at timer))
                      (apply-action! child-node
                                     (fn [st]
                                       (dc/handle-timeout st timer-id now-ms (:dtls/engine st)))
                                     @(:callbacks child-node)))))))))
        (catch Exception e
          (when @(:running listener-callbacks)
            (when-let [cb (:on-error listener-callbacks)]
              (cb {:type :on-error :cause e}))))))))

(defn listen-tcp!
  "Starts a TCP listener on the given port (RFC 4571 framing) that multiplexes incoming connections.
  `opts` should contain `:port`.
  `listener-callbacks` should contain `:on-connection` which receives each new child node."
  [opts listener-callbacks]
  (let [port (get opts :port 5000)
        ice-creds (or (:ice-creds opts) (sdp/generate-ice-credentials))
        cert-data (or (:cert-data opts) (dtls/generate-cert))
        server-ch (tcp/create-server-socket-channel port)
        ^Selector selector (nio/create-selector)
        routing-table (atom {})
        running (atom true)
        listener-node {:opts opts
                       :tcp? true
                       :running running
                       :channel (atom server-ch)
                       :selector (atom selector)
                       :routing-table routing-table
                       :loop-future (atom nil)
                       :shared-channel? false
                       :ice-creds ice-creds
                       :cert-data cert-data}
        listener-callbacks (assoc listener-callbacks :running running)]
    (.register server-ch selector SelectionKey/OP_ACCEPT)
    (let [fut (future
                (tcp-listen-loop-body listener-node listener-callbacks))]
      (reset! (:loop-future listener-node) fut)
      listener-node)))
