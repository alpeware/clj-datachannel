(ns datachannel.core
  (:require [datachannel.chunks :as chunks]
            [datachannel.dcep :as dcep]
            [datachannel.dtls :as dtls]
            [datachannel.handlers :as handlers]
            [datachannel.packetize :as packetize]
            [datachannel.reassemble :as reassemble]
            [datachannel.sctp :as sctp]
            [datachannel.sdp :as sdp]
            [datachannel.stun :as stun]
            [datachannel.turn :as turn])
  (:import [java.nio ByteBuffer]
           [javax.net.ssl SSLEngineResult$HandshakeStatus]
           [java.security SecureRandom]))

(defonce ^:private secure-rand (SecureRandom.))

(def buffer-size
  "Constant used for ByteBuffer sizing representing a reasonably large standard MTU/packet limit."
  65536)

(def default-max-message-size
  "Default WebRTC SCTP maximum message size (256 KiB)."
  sdp/default-max-message-size)

(defn get-buffered-amount
  "Calculates the total byte size of all SCTP data chunks currently enqueued for a given stream ID."
  [state stream-id]
  (let [q (get-in state [:streams stream-id :send-queue] [])]
    (reduce + (map (fn [item]
                     (let [payload (get-in item [:chunk :payload])]
                       (if payload (alength ^bytes payload) 0)))
                   q))))

(defn packetize
  "Delegates to the inner `datachannel.packetize/packetize` logic, processing the connection state to yield outgoing network packets according to congestion limits."
  [state app-events now-ms]
  (packetize/packetize state app-events now-ms))

(defn handle-event
  "Delegates an application event like `:connect` to the state machine routing logic."
  [state event now-ms]
  (handlers/handle-event state event now-ms))

(defn handle-timeout
  "Delegates an expired timer event to the state machine logic."
  [state timer-id now-ms & [engine]]
  (handlers/handle-timeout state timer-id now-ms engine))

(defn reassemble
  "Delegates stream reassembly logic, processing queued inbound chunks to reconstruct application payloads."
  [state app-events]
  (reassemble/reassemble state app-events))

(defn- valid-verification-tag?
  "Checks if the incoming packet has a valid verification tag for the given state."
  [state packet]
  (let [chunks (:chunks packet)
        packet-vtag (:verification-tag packet)
        local-vtag (get state :local-ver-tag 0)
        fallback-vtag (get state :init-tag 0)
        has-init? (some #(= (:type %) :init) chunks)]
    (if has-init?
      (zero? packet-vtag)
      (or (= packet-vtag local-vtag)
          (and (not (zero? fallback-vtag)) (= packet-vtag fallback-vtag))
          (and (zero? local-vtag) (zero? fallback-vtag))))))

(defn handle-sctp-packet
  "Injects a decoded incoming SCTP packet into the unified state machine, advancing through all contained chunks."
  [state packet now-ms]
  (if-not (valid-verification-tag? state packet)
    {:new-state state :network-out [] :app-events []}
    (let [chunks (:chunks packet)
          state-with-rx (-> state
                            (update-in [:metrics :rx-packets] (fnil inc 0))
                            (assoc :remote-port (:src-port packet))
                            (assoc :local-port (:dst-port packet))
                            (assoc :last-any-traffic now-ms))
          res (loop [current-state state-with-rx
                     remaining-chunks chunks
                     app-events []]
                (if (empty? remaining-chunks)
                  {:new-state current-state
                   :app-events app-events}
                  (let [chunk (first remaining-chunks)
                        {:keys [next-state next-events]}
                        (chunks/process-chunk current-state chunk packet now-ms)]
                    (recur next-state
                           (rest remaining-chunks)
                           (into app-events next-events)))))
          ;; Only pass on events/network packets if the chunk processor didn't short-circuit the connection processing
          ;; Note: For INIT and COOKIE-ECHO chunks we now process them immutably.
          reassembled (reassemble (:new-state res) (:app-events res))]
      (packetize (:new-state reassembled) (:app-events reassembled) now-ms))))

(defn- buf->bytes ^bytes [buf-or-bytes]
  (cond
    (bytes? buf-or-bytes) buf-or-bytes
    (instance? ByteBuffer buf-or-bytes)
    (let [dup (.duplicate ^ByteBuffer buf-or-bytes)
          arr (byte-array (.remaining dup))]
      (.get dup arr)
      arr)
    :else nil))

(defn serialize-network-out
  "Encodes items in :network-out into ByteBuffers and stores them in :network-out-bytes"
  [result-map & opt-args]
  (let [opt-buf (first opt-args)
        new-state (:new-state result-map)
        zero-checksum? (get-in new-state [:metrics :uses-zero-checksum])
        engine (:dtls/engine new-state)
        tc (:turn-client new-state)
        use-turn? (and (or (:use-turn-relay? new-state)
                           (:last-rx-via-turn? new-state))
                       tc
                       (#{:allocated :channel-bound} (:state tc)))
        turn-srv (when tc
                   (handlers/resolve-candidate-target
                    (or (:turn-server-addr new-state) (:server-addr tc))))
        encoded (mapv (fn [item]
                        (cond
                          (and (map? item) (:packet item)) ; Targeted packet map
                          item
                          (map? item) ; SCTP packet
                          (let [buf (or opt-buf (ByteBuffer/allocateDirect 65536))]
                            (.clear buf)
                            (sctp/encode-packet item buf {:zero-checksum? zero-checksum?})
                            (.flip buf)
                            (if (and engine (or (= (.getHandshakeStatus engine) SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING)
                                                (= (.getHandshakeStatus engine) SSLEngineResult$HandshakeStatus/FINISHED)))
                              (let [net-out (ByteBuffer/allocateDirect 65536)
                                    {:keys [_status bytes]} (dtls/send-app-data engine buf net-out)]
                                (ByteBuffer/wrap bytes))
                              buf))
                          (instance? ByteBuffer item) ; Already encoded (STUN/DTLS)
                          item
                          (bytes? item) ; byte-array
                          (ByteBuffer/wrap item)
                          :else
                          (throw (ex-info "Unknown item type in network-out" {:item item}))))
                      (:network-out result-map []))
        [final-out final-state final-events]
        (if-not use-turn?
          [encoded new-state (vec (:app-events result-map []))]
          (reduce (fn [[out-acc st-acc evts-acc] item]
                    (let [pkt (if (and (map? item) (:packet item)) (:packet item) item)
                          target (when (map? item) (handlers/resolve-candidate-target (:target item)))]
                      (if (and turn-srv (= target turn-srv))
                        [(conj out-acc item) st-acc evts-acc]
                        (let [peer-addr (or target
                                            (handlers/resolve-candidate-target (:remote-addr st-acc))
                                            (handlers/resolve-candidate-target (first (:remote-candidates st-acc))))
                              raw (buf->bytes pkt)]
                          (if (and peer-addr raw)
                            (let [relayed (turn/send-via-turn (:turn-client st-acc) peer-addr raw)]
                              (if (:ok? relayed)
                                (let [frame (first (:network-out relayed))
                                      wrapped (if (instance? ByteBuffer frame) frame (ByteBuffer/wrap frame))
                                      out-item (if turn-srv {:packet wrapped :target turn-srv} wrapped)]
                                  [(conj out-acc out-item) st-acc evts-acc])
                                (let [reason (or (:error relayed) :turn-send-failed)
                                      st-dropped (-> st-acc
                                                     (update-in [:turn-client :dropped-frames] (fnil inc 0))
                                                     (assoc-in [:turn-client :last-error] reason))
                                      drop-evt {:type :turn-drop :reason reason :peer-address peer-addr}]
                                  [out-acc st-dropped (conj evts-acc drop-evt)])))
                            (let [st-dropped (-> st-acc
                                                 (update-in [:turn-client :dropped-frames] (fnil inc 0))
                                                 (assoc-in [:turn-client :last-error] :missing-peer-address))
                                  drop-evt {:type :turn-drop :reason :missing-peer-address :peer-address peer-addr}]
                              [out-acc st-dropped (conj evts-acc drop-evt)]))))))
                  [[] new-state (vec (:app-events result-map []))]
                  encoded))]
    (assoc result-map
           :new-state final-state
           :app-events final-events
           :network-out-bytes final-out)))

(defn- process-turn-step
  [state turn-res now-ms handle-rx-fn]
  (let [tc-0 (:new-state turn-res)
        turn-srv (or (:turn-server-addr state) (:server-addr tc-0))
        events (vec (:events turn-res))
        alloc-evt (first (filter #(= (:type %) :turn-allocated) events))
        peers (keep handlers/resolve-candidate-target
                    (distinct (concat (:remote-candidates state)
                                      (when (:remote-addr state) [(:remote-addr state)]))))
        relay-step (if (and alloc-evt (seq peers))
                     (reduce (fn [acc peer]
                               (let [r (turn/ensure-peer-relay (:tc acc) peer)]
                                 {:tc (:new-state r)
                                  :out (into (:out acc) (:network-out r))
                                  :evts (into (:evts acc) (:events r))}))
                             {:tc tc-0 :out [] :evts []}
                             peers)
                     {:tc tc-0 :out [] :evts []})
        tc-final (:tc relay-step)
        relayed-addr (:relayed-address alloc-evt)
        relay-cand (when (and (:use-turn-relay? state)
                              relayed-addr (:ip relayed-addr) (:port relayed-addr))
                     (sdp/format-candidate {:foundation "turn1"
                                            :component 1
                                            :transport "UDP"
                                            :priority (sdp/compute-candidate-priority :relay)
                                            :ip (:ip relayed-addr)
                                            :port (:port relayed-addr)
                                            :type "relay"}))
        state-with-tc (-> state
                          (assoc :turn-client tc-final)
                          (cond-> relay-cand (update :local-candidates (fnil conj []) relay-cand)))
        all-turn-out (handlers/wrap-turn-packets
                      (into (vec (:network-out turn-res)) (:out relay-step))
                      turn-srv)
        all-events (cond-> (into events (:evts relay-step))
                     relay-cand (conj {:type :on-ice-candidate :candidate relay-cand :relay? true}))
        data-evts (filter #(= (:type %) :turn-data) events)]
    (if (seq data-evts)
      (reduce (fn [acc evt]
                (let [peer-sock (handlers/resolve-candidate-target (:peer-address evt))
                      rx-state (assoc (:new-state acc) :last-rx-via-turn? true)
                      inner-res (handle-rx-fn rx-state (:data evt) now-ms peer-sock)]
                  {:new-state (:new-state inner-res)
                   :network-out (into (:network-out acc) (:network-out inner-res))
                   :app-events (into (:app-events acc) (:app-events inner-res))}))
              {:new-state state-with-tc :network-out all-turn-out :app-events all-events}
              data-evts)
      {:new-state state-with-tc :network-out all-turn-out :app-events all-events})))

(defn handle-receive
  "Primary entry point for multiplexing inbound UDP data, distinguishing STUN, DTLS, and SCTP bytes based on their first byte, running decryption or packet routing."
  [state ^bytes network-bytes now-ms & [remote-addr]]
  (if (zero? (alength network-bytes))
    {:new-state state :network-out [] :app-events []}
    (let [first-byte (bit-and (aget network-bytes 0) 0xFF)
          engine (:dtls/engine state)]
      (cond
        ;; ChannelData (first byte 64..127)
        (and (>= first-byte 64) (<= first-byte 127))
        (try
          (if-let [tc (:turn-client state)]
            (let [turn-res (turn/step-turn-client tc network-bytes now-ms)]
              (process-turn-step state turn-res now-ms handle-receive))
            (if (turn/channel-data? network-bytes)
              (if-let [cd (turn/decode-channel-data network-bytes)]
                (handle-receive state (:data cd) now-ms remote-addr)
                {:new-state state :network-out [] :app-events []})
              {:new-state state :network-out [] :app-events []}))
          (catch Exception e
            {:new-state (cond-> state
                          (:turn-client state)
                          (-> (update-in [:turn-client :dropped-frames] (fnil inc 0))
                              (assoc-in [:turn-client :last-error] (or (.getMessage e) (.getName (class e))))))
             :network-out []
             :app-events [{:type :turn-error :reason :exception :message (or (.getMessage e) (.getName (class e)))}]}))

        ;; STUN or TURN
        (and (>= first-byte 0) (<= first-byte 3))
        (let [msg-type (if (>= (alength network-bytes) 2)
                         (bit-and (short (+ (bit-shift-left (bit-and (aget network-bytes 0) 0xFF) 8)
                                            (bit-and (aget network-bytes 1) 0xFF)))
                                  0xFFFF)
                         0)]
          (if (#{:turn 0x0003 0x0103 0x0113 0x0004 0x0104 0x0114 0x0008 0x0108 0x0118 0x0009 0x0109 0x0119 0x0016 0x0017} msg-type)
            (try
              (let [tc (or (:turn-client state) (turn/init-turn-client {}))
                    turn-res (turn/step-turn-client tc network-bytes now-ms)]
                (process-turn-step state turn-res now-ms handle-receive))
              (catch Exception e
                {:new-state (-> state
                                (update-in [:turn-client :dropped-frames] (fnil inc 0))
                                (assoc-in [:turn-client :last-error] (or (.getMessage e) (.getName (class e)))))
                 :network-out []
                 :app-events [{:type :turn-error :reason :exception :message (or (.getMessage e) (.getName (class e)))}]}))
            (let [buf (ByteBuffer/wrap network-bytes)
                  stun-res (stun/handle-packet buf remote-addr state)
                  response (:response stun-res)
                  candidate (:candidate stun-res)
                  prflx-cand (:peer-reflexive-candidate stun-res)
                  eff-cand (or candidate prflx-cand)
                  binding-response? (boolean (:binding-response? stun-res))
                  valid-stun? (or (some? response) (some? candidate) (some? prflx-cand) binding-response?)
                  new-candidate? (and eff-cand (not (contains? (:seen-candidates state) eff-cand)))
                  became-connected? (and (not= (:ice-connection-state state) :connected)
                                         (or response candidate binding-response?))
                  remote-ufrag (:remote-ice-ufrag stun-res)
                  eff-ufrag (or remote-ufrag (:remote-ice-ufrag state))
                  peer-pwds-raw (:peer-ice-pwds state)
                  peer-pwds (if (instance? clojure.lang.IDeref peer-pwds-raw) @peer-pwds-raw peer-pwds-raw)
                  resolved-pwd (when (and eff-ufrag (map? peer-pwds)) (get peer-pwds eff-ufrag))
                  new-role (:new-role stun-res)
                  curr-role (or new-role (:ice-role state))
                  relay-active? (and (or (:use-turn-relay? state) (:last-rx-via-turn? state))
                                     (:turn-client state)
                                     (#{:allocated :channel-bound} (get-in state [:turn-client :state])))
                  local-prio (if relay-active?
                               (sdp/compute-candidate-priority :relay 65535 1)
                               (or (:local-priority state)
                                   (sdp/compute-candidate-priority :host 65535 1)))
                  remote-prio (or (:priority stun-res)
                                  (sdp/compute-candidate-priority (if prflx-cand :prflx (if relay-active? :relay :host)) 65535 1))
                  use-candidate? (boolean (:use-candidate? stun-res))
                  nom-policy (or (:nomination-policy state) :aggressive)
                  should-nominate? (if (= curr-role :controlling)
                                     (and binding-response?
                                          (or (= nom-policy :aggressive)
                                              (boolean (:nominate-on-next-check? state))
                                              use-candidate?))
                                     use-candidate?)
                  pair-prio (when should-nominate?
                              (sdp/compute-pair-priority local-prio remote-prio (= curr-role :controlling)))
                  existing-nom (:nominated-pair state)
                  nominate-now? (and pair-prio
                                     (or (nil? existing-nom)
                                         (> pair-prio (or (:pair-priority existing-nom) 0))))
                  nom-pair (when nominate-now?
                             {:remote-addr remote-addr
                              :candidate (or eff-cand (str remote-addr))
                              :pair-priority pair-prio
                              :nominated? true})
                  new-state (-> state
                                (cond-> valid-stun? (assoc :last-stun-received now-ms
                                                           :last-any-traffic now-ms))
                                (cond-> response (assoc :remote-addr remote-addr))
                                (cond-> new-role (assoc :ice-role new-role))
                                (cond-> (and remote-ufrag (nil? (:remote-ice-ufrag state)))
                                  (assoc :remote-ice-ufrag remote-ufrag))
                                (cond-> (and resolved-pwd (nil? (:remote-ice-pwd state)))
                                  (assoc :remote-ice-pwd resolved-pwd))
                                (cond-> new-candidate? (update :seen-candidates (fnil conj #{}) eff-cand))
                                (cond-> (and new-candidate? binding-response?)
                                  (update :local-candidates (fnil conj []) eff-cand))
                                (cond-> (and new-candidate? (not binding-response?))
                                  (update :remote-candidates (fnil conj []) eff-cand))
                                (cond-> nom-pair (assoc :nominated-pair nom-pair :nominated? true))
                                (cond-> (or nom-pair (and binding-response? (:nominate-on-next-check? state)))
                                  (assoc :nominate-on-next-check? false))
                                (cond-> became-connected? (assoc :ice-connection-state :connected)))
                  app-events (cond-> [{:type :stun-packet :payload network-bytes}]
                               new-candidate? (conj {:type :on-ice-candidate :candidate eff-cand})
                               nom-pair (conj {:type :on-ice-candidate-nominated :nominated-pair nom-pair})
                               became-connected? (conj {:type :on-ice-connection-state-change :state :connected}))
                  network-out (if response [response] [])]
              {:new-state new-state :network-out network-out :app-events app-events})))

        ;; DTLS
        (and (>= first-byte 20) (<= first-byte 63))
        (if-not engine
          {:new-state state :network-out [] :app-events [{:type :dtls-packet :payload network-bytes}]}
          (let [hs-status (.getHandshakeStatus engine)]
            (if (and (or (= hs-status SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING)
                         (= hs-status SSLEngineResult$HandshakeStatus/FINISHED))
                     (:dtls-verified? state))
              ;; Application data
              (try
                (let [in-buf (ByteBuffer/wrap network-bytes)
                      out-buf (ByteBuffer/allocateDirect 65536)
                      {:keys [_status bytes]} (dtls/receive-app-data engine in-buf out-buf)]
                  (if (and bytes (pos? (alength bytes)))
                    (let [state (assoc state :last-stun-received now-ms :last-any-traffic now-ms)
                          sctp-buf (ByteBuffer/wrap bytes)
                          packet (sctp/decode-packet sctp-buf)]
                      (if packet
                        (handle-sctp-packet state packet now-ms)
                        {:new-state state :network-out [] :app-events []}))
                    {:new-state state :network-out [] :app-events []}))
                (catch Exception _
                  {:new-state state :network-out [] :app-events []}))
              ;; Handshake
              (try
                (let [in-buf (ByteBuffer/wrap network-bytes)
                      out-buf (ByteBuffer/allocateDirect 65536)
                      {:keys [status packets app-data]} (dtls/handshake engine in-buf out-buf)
                      handshake-finished? (or (= status SSLEngineResult$HandshakeStatus/FINISHED)
                                              (= status SSLEngineResult$HandshakeStatus/NOT_HANDSHAKING))]
                  (if (and handshake-finished?
                           (not (:dtls-verified? state)))
                    (if (and (:remote-fingerprint state)
                             (not (dtls/verify-peer-fingerprint engine (:remote-fingerprint state))))
                      (let [state-closed (assoc state :state :closed)
                            abort-chunk {:type :abort
                                         :flags 0
                                         :params []}
                            packet {:src-port (:local-port state 5000)
                                    :dst-port (:remote-port state 5000)
                                    :verification-tag (:remote-ver-tag state 0)
                                    :chunks [abort-chunk]}]
                        {:new-state state-closed
                         :network-out (if (empty? packets) [packet] (conj (vec packets) packet))
                         :app-events [{:type :on-error :message "DTLS Fingerprint Mismatch"} {:type :on-close}]})
                      ;; Verification passed (or listen mode), transition to :connected normally
                      (let [state-verified (-> state
                                               (assoc :dtls-verified? true :last-stun-received now-ms :last-any-traffic now-ms)
                                               (update :timers dissoc :dtls/flight-timeout))
                            conn-res (if (and (:client-mode? state-verified) (not (#{:established :cookie-wait :cookie-echoed} (:state state-verified))))
                                       (handle-event state-verified {:type :connect} now-ms)
                                       {:new-state (assoc state-verified :state :connected) :network-out [] :app-events []})
                            state-verified (:new-state conn-res)
                            base-res {:new-state state-verified
                                      :network-out (into (vec packets) (:network-out conn-res))
                                      :app-events (into [{:type :dtls-handshake-progress}] (:app-events conn-res))}]
                        (if (and app-data (pos? (alength app-data)))
                          (let [sctp-buf (ByteBuffer/wrap app-data)
                                packet (sctp/decode-packet sctp-buf)]
                            (if packet
                              (let [sctp-res (handle-sctp-packet (:new-state base-res) packet now-ms)]
                                (-> sctp-res
                                    (update :network-out (fn [no] (into (:network-out base-res) no)))
                                    (update :app-events (fn [evts] (into (:app-events base-res) evts)))))
                              base-res))
                          (if (seq (:pending-control-chunks (:new-state base-res)))
                            (packetize (:new-state base-res) (:app-events base-res) now-ms)
                            base-res))))
                    (let [state (assoc state :last-stun-received now-ms :last-any-traffic now-ms)]
                      (if (and app-data (pos? (alength app-data)))
                        (let [sctp-buf (ByteBuffer/wrap app-data)
                              packet (sctp/decode-packet sctp-buf)]
                          (if packet
                            (let [sctp-res (handle-sctp-packet state packet now-ms)]
                              (-> sctp-res
                                  (update :network-out (fn [no] (into (vec packets) no)))
                                  (update :app-events conj {:type :dtls-handshake-progress})))
                            {:new-state state :network-out (vec packets) :app-events [{:type :dtls-handshake-progress}]}))
                        {:new-state state :network-out (vec packets) :app-events [{:type :dtls-handshake-progress}]}))))
                (catch Exception e
                  (println "DTLS HANDSHAKE EXCEPTION" (.getMessage e))
                  (let [err-msg (if (.getMessage e) (.getMessage e) "DTLS Fingerprint Mismatch")]
                    {:new-state (assoc state :state :closed)
                     :network-out []
                     :app-events [{:type :on-error :message err-msg} {:type :on-close}]}))))))

        ;; SCTP (Default, raw)
        :else
        {:new-state state :network-out [] :app-events []}))))

(defn create-connection
  "Initializes the flattened SCTP/ICE/DTLS pure state map with configured congestion parameters and cryptography contexts."
  [options client-mode?]
  (let [now-ms (System/currentTimeMillis)
        cert-data (or (:cert-data options) (dtls/generate-cert))
        ctx (dtls/create-ssl-context (:cert cert-data) (:key cert-data))
        engine (dtls/create-engine ctx client-mode?)
        local-ver-tag (.nextInt secure-rand 2147483647)
        cookie-secret (let [b (byte-array 32)] (.nextBytes secure-rand b) b)]
    {:cookie-secret cookie-secret
     :remote-ver-tag 0
     :local-ver-tag local-ver-tag
     :last-stun-received now-ms
     :last-any-traffic now-ms
     :next-tsn 0
     :ssn 0
     :timers (merge (if (seq (get options :remote-candidates [])) {:stun/check-candidates {:expires-at 0}} {})
                    (if (:turn-config options) {:turn/refresh {:expires-at now-ms}} {})
                    {:stun/keepalive {:expires-at (+ now-ms 1000)}})
     :heartbeat-interval (get options :heartbeat-interval 30000)
     :heartbeat-error-count 0
     :rto-initial (get options :rto-initial 1000)
     :max-retransmissions (get options :max-retransmissions 10)
     :mtu (get options :mtu 1200)
     :streams {}
     :pending-control-chunks []
     :metrics {:tx-packets 0
               :rx-packets 0
               :tx-bytes   0
               :rx-bytes   0
               :retransmissions 0
               :unacked-data 0
               :uses-zero-checksum (boolean (:zero-checksum? options))}
     :cwnd (let [mtu (get options :mtu 1200)]
             (min (* 4 mtu) (max (* 2 mtu) 4380)))
     :ssthresh 65535 ; Initial peer rwnd or 65535
     :flight-size 0
     :partial-bytes-acked 0
     :buffered-amount-low-threshold (get options :buffered-amount-low-threshold 0)
     :buffered-amount-high-threshold (get options :buffered-amount-high-threshold 1048576)
     :zero-checksum? (:zero-checksum? options)
     :cert-data cert-data
     :ice-ufrag (:ice-ufrag options)
     :ice-pwd (:ice-pwd options)
     :remote-ice-ufrag (:remote-ice-ufrag options)
     :remote-ice-pwd (:remote-ice-pwd options)
     :peer-ice-pwds (:peer-ice-pwds options)
     :remote-fingerprint (:remote-fingerprint options)
     :ice-lite? (boolean (:ice-lite? options))
     :ice-role (or (:ice-role options) (if client-mode? :controlling :controlled))
     :ice-tie-breaker (or (:ice-tie-breaker options) (.nextLong secure-rand))
     :nominated-pair nil
     :nominated? false
     :nomination-policy (or (:nomination-policy options) :aggressive)
     :nominate-on-next-check? false
     :local-priority (or (:local-priority options)
                         (sdp/compute-candidate-priority (or (:candidate-type options) :host) 65535 1))
     :turn-client (when-let [tc (:turn-config options)] (turn/init-turn-client tc))
     :turn-server-addr (when-let [tc (:turn-config options)]
                         (handlers/resolve-candidate-target
                          (or (:server-addr tc)
                              (when (:server-host tc)
                                {:ip (:server-host tc) :port (int (or (:server-port tc) 3478))}))))
     :use-turn-relay? (boolean (if (some? (:use-turn-relay? options))
                                 (:use-turn-relay? options)
                                 (if (some? (get-in options [:turn-config :use-turn-relay?]))
                                   (get-in options [:turn-config :use-turn-relay?])
                                   (or (boolean (:force-relay? options))
                                       (boolean (get-in options [:turn-config :force-relay?]))
                                       (some? (:turn-config options))))))
     :ice-gathering-state :new
     :ice-connection-state :new
     :seen-candidates #{}
     :local-candidates []
     :remote-candidates (or (:remote-candidates options) [])
     :data-channels {}
     :client-mode? client-mode?
     :local-outbound-streams (get options :local-outbound-streams 65535)
     :local-inbound-streams (get options :local-inbound-streams 65535)
     :max-message-size (let [local-max (long (get options :max-message-size default-max-message-size))
                             remote-max (or (:remote-max-message-size options)
                                            (when-let [rsdp (:remote-sdp options)]
                                              (sdp/parse-max-message-size rsdp)))]
                         (if (and (number? remote-max) (pos? remote-max))
                           (min local-max (long remote-max))
                           local-max))
     :a-rwnd (long (get options :a-rwnd default-max-message-size))
     :max-queue-size (get options :max-queue-size)
     :max-receive-queue-size (get options :max-receive-queue-size)
     :dtls/engine engine}))

(declare send-data)

(defn create-data-channel
  "Applies W3C WebRTC interface logic, creating a data channel stream map and dispatching a DCEP OPEN packet for unnegotiated channels."
  [state label options]
  (let [opts (merge {:ordered true
                     :max-packet-life-time nil
                     :max-retransmits nil
                     :protocol ""
                     :negotiated false}
                    options)
        provided-id (:id opts)
        client? (:client-mode? state)
        id (if provided-id
             provided-id
             (loop [potential-id (if client? 0 1)]
               (if (contains? (:data-channels state) potential-id)
                 (recur (+ potential-id 2))
                 potential-id)))
        negotiated? (:negotiated opts)
        channel-state (if negotiated? :open :connecting)
        new-state (assoc-in state [:data-channels id] (assoc opts :label label :state channel-state))]
    (if negotiated?
      {:new-state new-state
       :channel-id id
       :network-out []
       :app-events []}
      (let [open-msg {:type :open
                      :label label
                      :protocol (:protocol opts)
                      :ordered (:ordered opts)
                      :max-retransmits (:max-retransmits opts)
                      :max-packet-life-time (:max-packet-life-time opts)}
            payload (dcep/encode-message open-msg)
            now-ms (System/currentTimeMillis)
            res (send-data new-state payload id :webrtc/dcep now-ms)]
        (assoc res :channel-id id)))))

(defn set-max-message-size
  "Configures the maximum permissible size of a single application message, rejecting sends above this limit."
  [state max-size]
  (assoc state :new-state (assoc state :max-message-size max-size)))

(defn send-data
  "Accepts user application bytes, calculating fragmentation thresholds based on MTU, wrapping the sequence in correctly flagged SCTP DATA chunks, and enqueuing them to a stream's send queue."
  [state ^bytes payload stream-id protocol now-ms]
  (let [len (alength payload)
        max-size (get state :max-message-size default-max-message-size)]
    (when (zero? len)
      (throw (ex-info "Cannot send empty message" {:type :empty-payload})))
    (when (> len max-size)
      (throw (ex-info "Cannot send too large message" {:type :too-large})))
    (let [max-queue-size (get state :max-queue-size)
          old-q (get-in state [:streams stream-id :send-queue] [])
          old-buffered (reduce + (map #(if-let [p (:payload (:chunk %))] (alength ^bytes p) 0) old-q))]
      (when (and max-queue-size (> (+ old-buffered len) max-queue-size))
        (throw (ex-info "Queue limit reached" {:type :queue-limit-reached}))))
    (let [_ver-tag (:remote-ver-tag state)
          channel-opts (get-in state [:data-channels stream-id])
          ordered? (if (some? channel-opts) (:ordered channel-opts) true)
          ssn (if ordered? (get-in state [:streams stream-id :next-tx-ssn] 0) 0)
          mtu (get state :mtu 1200)
          max-payload-per-chunk (- mtu 16)
          is-established? (= (:state state) :established)
          fragments (if (<= len max-payload-per-chunk)
                      [payload]
                      (loop [offset 0
                             frags []]
                        (if (>= offset len)
                          frags
                          (let [frag-len (min max-payload-per-chunk (- len offset))
                                frag (java.util.Arrays/copyOfRange payload offset (+ offset frag-len))]
                            (recur (+ offset frag-len) (conj frags frag))))))
          old-q (get-in state [:streams stream-id :send-queue] [])
          old-buffered (reduce + (map #(if-let [p (:payload (:chunk %))] (alength ^bytes p) 0) old-q))
          result (loop [remaining-frags fragments
                        current-state state
                        current-tsn (or (:next-tsn state) 0)
                        idx 0]
                   (if (empty? remaining-frags)
                     (let [s1 (-> current-state
                                  (assoc :next-tsn current-tsn)
                                  (cond-> ordered? (assoc-in [:streams stream-id :next-tx-ssn] (inc ssn))))
                           interval (get s1 :heartbeat-interval 30000)
                           s2 (if (and (pos? interval) (contains? (:timers s1) :sctp/t-heartbeat))
                                (assoc-in s1 [:timers :sctp/t-heartbeat] {:expires-at (+ now-ms interval)})
                                s1)
                           s3 (-> s2
                                  (update-in [:metrics :unacked-data] (fnil + 0) (reduce + (map #(+ 16 (alength ^bytes %)) fragments)))
                                  (cond-> is-established?
                                    (update-in [:metrics :tx-bytes] (fnil + 0) len)))
                           s4 (if (and is-established? (nil? (get-in s3 [:timers :sctp/t3-rtx])))
                                (assoc-in s3 [:timers :sctp/t3-rtx] {:expires-at (+ now-ms 1000) :delay 1000})
                                s3)]
                       (if is-established?
                         (packetize s4 [] now-ms)
                         {:new-state s4 :network-out [] :app-events []}))
                     (let [frag (first remaining-frags)
                           total-frags (count fragments)
                           flags (if (= total-frags 1) 3
                                     (cond
                                       (= idx 0) 2
                                       (= idx (dec total-frags)) 1
                                       :else 0))
                           final-flags (if ordered? flags (bit-or flags 4))
                           data-chunk {:type :data
                                       :flags final-flags
                                       :tsn current-tsn
                                       :stream-id stream-id
                                       :seq-num ssn
                                       :protocol protocol
                                       :payload frag}
                           queue-item {:tsn current-tsn
                                       :chunk data-chunk
                                       :sent-at now-ms
                                       :retries 0
                                       :sent? false
                                       :max-packet-life-time (:max-packet-life-time channel-opts)
                                       :max-retransmits (:max-retransmits channel-opts)}
                           new-state (assoc-in current-state [:streams stream-id :send-queue]
                                               (conj (get-in current-state [:streams stream-id :send-queue] []) queue-item))]
                       (recur (rest remaining-frags) new-state (inc current-tsn) (inc idx)))))
          new-q (get-in (:new-state result) [:streams stream-id :send-queue] [])
          new-buffered (reduce + (map #(if-let [p (:payload (:chunk %))] (alength ^bytes p) 0) new-q))
          high-threshold (get state :buffered-amount-high-threshold 1048576)
          app-events (if (and (<= old-buffered high-threshold) (> new-buffered high-threshold))
                       (conj (:app-events result []) {:type :on-buffered-amount-high :stream-id stream-id})
                       (:app-events result []))]
      (assoc result :app-events app-events))))
