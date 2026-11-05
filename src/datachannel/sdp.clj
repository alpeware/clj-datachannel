(ns datachannel.sdp
  (:require [clojure.string :as str])
  (:import [java.security SecureRandom]))

(def ^:private type-preferences
  {"host" 126
   "prflx" 110
   "srflx" 100
   "relay" 0
   :host 126
   :prflx 110
   :srflx 100
   :relay 0})

(defn calculate-candidate-priority
  "Computes candidate priority per RFC 8445 §5.1.2:
   priority = (2^24)*(type-preference) + (2^8)*(local-preference) + (2^0)*(256 - component-id)"
  ([candidate-type]
   (calculate-candidate-priority candidate-type 65535 1))
  ([candidate-type local-preference]
   (calculate-candidate-priority candidate-type local-preference 1))
  ([candidate-type local-preference component-id]
   (let [type-pref (get type-preferences candidate-type 0)
         comp (max 1 (min 255 (int (or component-id 1))))
         local-pref (max 0 (min 65535 (int (or local-preference 65535))))]
     (long (+ (* type-pref 16777216)
              (* local-pref 256)
              (- 256 comp))))))

(defn calculate-pair-priority
  "Calculates candidate pair priority per RFC 8445 §6.1.2.3:
   pair-priority = 2^32 * min(G, D) + 2 * max(G, D) + (G > D ? 1 : 0)
   where G is priority of controlling agent candidate, D is priority of controlled agent candidate."
  [controlling-priority controlled-priority]
  (let [g (long controlling-priority)
        d (long controlled-priority)
        min-val (min g d)
        max-val (max g d)
        tie (if (> g d) 1 0)]
    (+ (* 4294967296 min-val) (* 2 max-val) tie)))

(defn generate-ice-credentials
  "Generates a secure ICE ufrag and pwd. The pwd must be at least 22 characters long (RFC 5245)."
  []
  (let [random (SecureRandom.)
        chars "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        len (count chars)
        gen-str (fn [n]
                  (apply str (repeatedly n #(nth chars (.nextInt random len)))))]
    {:ufrag (gen-str 8)
     :pwd   (gen-str 24)}))

(defn format-candidate
  "Formats an ICE candidate map into an RFC 5245 / RFC 8445 candidate attribute string."
  [cand]
  (let [foundation (str (or (:foundation cand) "1"))
        component (int (or (:component cand) 1))
        transport (str (or (:transport cand) "UDP"))
        cand-type (name (or (:type cand) "host"))
        priority (long (or (:priority cand) (calculate-candidate-priority cand-type 65535 component)))
        ip (str (or (:ip cand) "127.0.0.1"))
        port (int (or (:port cand) 5000))
        raddr (:raddr cand)
        rport (:rport cand)
        ufrag (:ufrag cand)]
    (str "candidate:" foundation " " component " " transport " " priority " " ip " " port
         " typ " cand-type
         (when (and raddr rport) (str " raddr " raddr " rport " rport))
         (when ufrag (str " ufrag " ufrag)))))

(defn parse-candidate
  "Extracts ICE candidate parameters (foundation, component, transport, priority,
   ip, port, type, raddr, rport, ufrag) from an RFC 5245 / RFC 8445 candidate string."
  [^String candidate-str]
  (let [cleaned (-> (str/trim candidate-str)
                    (str/replace-first #"^a=" "")
                    (str/replace-first #"^candidate:" ""))
        parts (vec (str/split cleaned #"\s+"))
        foundation (get parts 0)
        component (when-let [c (get parts 1)] (try (Integer/parseInt c) (catch Exception _ 1)))
        transport (get parts 2)
        priority (when-let [p (get parts 3)] (try (Long/parseLong p) (catch Exception _ 0)))
        ip (get parts 4)
        port (when-let [pt (get parts 5)] (try (Integer/parseInt pt) (catch Exception _ 0)))
        ;; Parse trailing keyword pairs like 'typ host', 'raddr 1.2.3.4', 'rport 1234', 'ufrag foo'
        trailing-map (loop [idx 6
                            m {}]
                       (if (>= idx (count parts))
                         m
                         (let [k (get parts idx)
                               v (get parts (inc idx))]
                           (if (and k v)
                             (recur (+ idx 2) (assoc m k v))
                             m))))
        cand-type (get trailing-map "typ")
        raddr (get trailing-map "raddr")
        rport (when-let [rp (get trailing-map "rport")] (try (Integer/parseInt rp) (catch Exception _ nil)))
        ufrag (get trailing-map "ufrag")]
    (cond-> {:ip ip
             :port port}
      foundation (assoc :foundation foundation)
      component (assoc :component component)
      transport (assoc :transport transport)
      priority (assoc :priority priority)
      cand-type (assoc :type cand-type)
      raddr (assoc :raddr raddr)
      rport (assoc :rport rport)
      ufrag (assoc :ufrag ufrag))))

(defn format-answer
  "Generates a complete SDP answer string."
  [{:keys [local-ip port ice-ufrag ice-pwd fingerprint setup ice-lite?]
    :or   {setup "passive"}}]
  (str "v=0\r\n"
       "o=- 123456789 2 IN IP4 " local-ip "\r\n"
       "s=-\r\n"
       "t=0 0\r\n"
       "a=group:BUNDLE 0\r\n"
       "m=application " port " UDP/DTLS/SCTP webrtc-datachannel\r\n"
       "c=IN IP4 " local-ip "\r\n"
       "a=setup:" setup "\r\n"
       "a=mid:0\r\n"
       "a=max-message-size:100000\r\n"
       "a=sctp-port:5000\r\n"
       "a=fingerprint:sha-256 " fingerprint "\r\n"
       "a=ice-ufrag:" ice-ufrag "\r\n"
       "a=ice-pwd:" ice-pwd "\r\n"
       (if ice-lite? "a=ice-lite\r\n" "")
       "a=rtcp-mux\r\n"))

(defn format-offer
  "Generates a complete SDP offer string."
  [{:keys [local-ip port ice-ufrag ice-pwd fingerprint setup ice-lite?]
    :or   {setup "actpass"}}]
  (str "v=0\r\n"
       "o=- 123456789 2 IN IP4 " local-ip "\r\n"
       "s=-\r\n"
       "t=0 0\r\n"
       "a=group:BUNDLE 0\r\n"
       "m=application " port " UDP/DTLS/SCTP webrtc-datachannel\r\n"
       "c=IN IP4 " local-ip "\r\n"
       "a=setup:" setup "\r\n"
       "a=mid:0\r\n"
       "a=max-message-size:100000\r\n"
       "a=sctp-port:5000\r\n"
       "a=fingerprint:sha-256 " fingerprint "\r\n"
       "a=ice-ufrag:" ice-ufrag "\r\n"
       "a=ice-pwd:" ice-pwd "\r\n"
       (if ice-lite? "a=ice-lite\r\n" "")
       "a=rtcp-mux\r\n"))
