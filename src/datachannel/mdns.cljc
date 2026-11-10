(ns datachannel.mdns
  "Cross-platform RFC 6762 Multicast DNS (`.local`) packet codec, pure Sans-IO responder/cache
   state machine, SDP ICE candidate `.local` resolver (draft-ietf-rtcweb-mdns-ice-candidates),
   and optional UDP multicast (`224.0.0.251:5353`) boundary service for JVM and Node.js."
  (:require [clojure.string :as str]
            [datachannel.buffer :as b])
  #?(:clj (:import [java.net DatagramPacket DatagramSocket InetAddress InetSocketAddress MulticastSocket])))

(def mdns-multicast-ipv4
  "RFC 6762 §3 IPv4 link-local multicast address for mDNS."
  "224.0.0.251")

(def mdns-port
  "RFC 6762 §3 standard UDP port for mDNS."
  5353)

(def qtype-a
  "DNS `A` record type (IPv4 address)."
  1)

(def qtype-aaaa
  "DNS `AAAA` record type (IPv6 address)."
  28)

(def qclass-in
  "DNS `IN` (Internet) class."
  1)

(defn normalize-mdns-hostname
  "Normalizes a `.local` or `.local.` hostname to lowercase without a trailing dot."
  [host]
  (when (string? host)
    (let [s (-> host str/trim str/lower-case)]
      (if (str/ends-with? s ".")
        (subs s 0 (dec (count s)))
        s))))

(defn mdns-hostname?
  "Returns `true` iff `host-or-ip` is a valid `.local` (or `.local.`) mDNS hostname."
  [host-or-ip]
  (if-let [norm (normalize-mdns-hostname host-or-ip)]
    (and (str/ends-with? norm ".local")
         (> (count norm) 6)
         (let [labels (str/split norm #"\.")]
           (and (>= (count labels) 2)
                (= "local" (last labels))
                (every? (fn [lbl]
                          (and (pos? (count lbl))
                               (<= (count lbl) 63)
                               (boolean (re-matches #"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" lbl))))
                        labels))))
    false))

(defn generate-mdns-hostname
  "Generates an RFC 4122 v4 UUID `.local` mDNS candidate hostname (`<uuid>.local`)."
  []
  (let [hex "0123456789abcdef"
        rhex (fn [n]
               (apply str (repeatedly n #(nth hex (b/random-int 16)))))
        v-nib (nth "89ab" (b/random-int 4))]
    (str (rhex 8) "-" (rhex 4) "-4" (rhex 3) "-" v-nib (rhex 3) "-" (rhex 12) ".local")))

(defn parse-ipv4-octets
  "Parses a dotted-quad IPv4 string into a 4-element vector of unsigned byte ints `[a b c d]`, or `nil`."
  [ip-str]
  (when (string? ip-str)
    (let [parts (str/split (str/trim ip-str) #"\.")]
      (when (= 4 (count parts))
        (let [octets (mapv #(b/parse-int % -1) parts)]
          (when (every? #(<= 0 % 255) octets)
            octets))))))

(defn format-ipv4-octets
  "Formats 4 unsigned byte integers `[a b c d]` into a dotted-quad IPv4 string."
  [[a b c d]]
  (str (bit-and (int a) 0xff) "."
       (bit-and (int b) 0xff) "."
       (bit-and (int c) 0xff) "."
       (bit-and (int d) 0xff)))

(defn encode-qname
  "Encodes a domain name into RFC 1035 wire label bytes terminated by a zero byte."
  [domain-str]
  (let [norm (or (normalize-mdns-hostname domain-str) "")
        labels (if (str/blank? norm) [] (str/split norm #"\."))
        label-bytes (mapv b/utf8->bytes labels)
        total-len (inc (reduce + 0 (map #(inc (b/blength %)) label-bytes)))
        buf (b/allocate-buffer total-len)]
    (doseq [lb label-bytes]
      (b/buf-put-u8! buf (b/blength lb))
      (b/buf-put-bytes! buf lb))
    (b/buf-put-u8! buf 0)
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn decode-qname
  "Decodes an RFC 1035 domain name starting at `offset` in `pkt-bytes` (supporting RFC 1035 §4.1.4
   pointer compression with cycle/hop bounds). Returns `{:name <lowercase-str> :next-offset <int>}` or `nil`."
  [pkt-bytes start-offset]
  (let [total (b/blength pkt-bytes)]
    (when (and (integer? start-offset) (<= 0 start-offset) (< start-offset total))
      (loop [pos (int start-offset)
             jumped-end nil
             hops 0
             labels []]
        (if (> hops 32)
          nil
          (if (>= pos total)
            nil
            (let [len-byte (b/bget-u8 pkt-bytes pos)]
              (cond
                (zero? len-byte)
                {:name (str/lower-case (str/join "." labels))
                 :next-offset (or jumped-end (inc pos))}

                (= 0xc0 (bit-and len-byte 0xc0))
                (when (< (inc pos) total)
                  (let [b2 (b/bget-u8 pkt-bytes (inc pos))
                        ptr (bit-or (bit-shift-left (bit-and len-byte 0x3f) 8) b2)]
                    (when (< ptr total)
                      (recur ptr (or jumped-end (+ pos 2)) (inc hops) labels))))

                (<= 1 len-byte 63)
                (let [end-pos (+ (inc pos) len-byte)]
                  (when (<= end-pos total)
                    (let [lbl-bs (b/bslice pkt-bytes (inc pos) end-pos)
                          lbl-str (b/bytes->utf8 lbl-bs)]
                      (recur end-pos jumped-end (inc hops) (conj labels lbl-str)))))

                :else nil))))))))

(defn encode-mdns-query
  "Encodes an RFC 6762 mDNS query packet (`ID = 0`, `QR = 0`) for `hostname`."
  ([hostname]
   (encode-mdns-query hostname {}))
  ([hostname {:keys [qtype unicast-response?]
              :or {qtype qtype-a unicast-response? false}}]
   (let [qname-bs (encode-qname hostname)
         qlen (b/blength qname-bs)
         buf (b/allocate-buffer (+ 12 qlen 4))
         qclass (if unicast-response?
                  (bit-or qclass-in 0x8000)
                  qclass-in)]
     ;; Header: ID=0, Flags=0, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
     (b/buf-put-u16! buf 0)
     (b/buf-put-u16! buf 0)
     (b/buf-put-u16! buf 1)
     (b/buf-put-u16! buf 0)
     (b/buf-put-u16! buf 0)
     (b/buf-put-u16! buf 0)
     (b/buf-put-bytes! buf qname-bs)
     (b/buf-put-u16! buf (int qtype))
     (b/buf-put-u16! buf (int qclass))
     (b/buf-flip! buf)
     (b/buf->bytes buf))))

(defn encode-mdns-response
  "Encodes an authoritative RFC 6762 mDNS `A` record response packet (`ID = 0`, `QR = 1`, `AA = 1`)."
  [{:keys [hostname ip ttl cache-flush?]
    :or {ttl 120 cache-flush? true}}]
  (let [octets (or (parse-ipv4-octets ip)
                   (throw (ex-info "Invalid IPv4 address for mDNS A response" {:ip ip})))
        qname-bs (encode-qname hostname)
        qlen (b/blength qname-bs)
        rclass (if cache-flush?
                 (bit-or qclass-in 0x8000)
                 qclass-in)
        buf (b/allocate-buffer (+ 12 qlen 10 4))]
    ;; Header: ID=0, Flags=0x8400 (QR=1, AA=1), QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    (b/buf-put-u16! buf 0)
    (b/buf-put-u16! buf 0x8400)
    (b/buf-put-u16! buf 0)
    (b/buf-put-u16! buf 1)
    (b/buf-put-u16! buf 0)
    (b/buf-put-u16! buf 0)
    ;; Answer RR
    (b/buf-put-bytes! buf qname-bs)
    (b/buf-put-u16! buf qtype-a)
    (b/buf-put-u16! buf rclass)
    (b/buf-put-u32! buf (long ttl))
    (b/buf-put-u16! buf 4)
    (doseq [o octets]
      (b/buf-put-u8! buf o))
    (b/buf-flip! buf)
    (b/buf->bytes buf)))

(defn- read-u16-be
  [pkt-bytes offset]
  (bit-or (bit-shift-left (b/bget-u8 pkt-bytes offset) 8)
          (b/bget-u8 pkt-bytes (inc offset))))

(defn- read-u32-be
  [pkt-bytes offset]
  (+ (* (b/bget-u8 pkt-bytes offset) 16777216)
     (* (b/bget-u8 pkt-bytes (+ offset 1)) 65536)
     (* (b/bget-u8 pkt-bytes (+ offset 2)) 256)
     (b/bget-u8 pkt-bytes (+ offset 3))))

(defn decode-mdns-packet
  "Purely decodes an RFC 6762 mDNS packet (`byte[]` / `Uint8Array`) into
   `{:id <int> :qr? <bool> :aa? <bool> :questions [...] :answers [...]}` or `nil` on malformed bytes."
  [pkt-bytes]
  (when (and pkt-bytes (>= (b/blength pkt-bytes) 12))
    (let [total (b/blength pkt-bytes)
          id (read-u16-be pkt-bytes 0)
          flags (read-u16-be pkt-bytes 2)
          qr? (pos? (bit-and flags 0x8000))
          aa? (pos? (bit-and flags 0x0400))
          qdcount (read-u16-be pkt-bytes 4)
          ancount (read-u16-be pkt-bytes 6)]
      (when (and (<= qdcount 64) (<= ancount 64))
        (loop [q-idx 0
               offset 12
               questions []]
          (if (< q-idx qdcount)
            (when-let [{:keys [name next-offset]} (decode-qname pkt-bytes offset)]
              (when (<= (+ next-offset 4) total)
                (let [qtype (read-u16-be pkt-bytes next-offset)
                      raw-qclass (read-u16-be pkt-bytes (+ next-offset 2))
                      unicast? (pos? (bit-and raw-qclass 0x8000))
                      qclass (bit-and raw-qclass 0x7fff)]
                  (recur (inc q-idx)
                         (+ next-offset 4)
                         (conj questions {:qname name
                                          :qtype qtype
                                          :qclass qclass
                                          :unicast-response? unicast?})))))
            (loop [a-idx 0
                   a-off offset
                   answers []]
              (if (< a-idx ancount)
                (when-let [{:keys [name next-offset]} (decode-qname pkt-bytes a-off)]
                  (when (<= (+ next-offset 10) total)
                    (let [rtype (read-u16-be pkt-bytes next-offset)
                          raw-rclass (read-u16-be pkt-bytes (+ next-offset 2))
                          flush? (pos? (bit-and raw-rclass 0x8000))
                          rclass (bit-and raw-rclass 0x7fff)
                          ttl (read-u32-be pkt-bytes (+ next-offset 4))
                          rdlength (read-u16-be pkt-bytes (+ next-offset 8))
                          rdata-start (+ next-offset 10)
                          rdata-end (+ rdata-start rdlength)]
                      (when (<= rdata-end total)
                        (let [rdata (b/bslice pkt-bytes rdata-start rdata-end)
                              ip-str (when (and (= rtype qtype-a) (= rdlength 4))
                                       (format-ipv4-octets [(b/bget-u8 rdata 0)
                                                            (b/bget-u8 rdata 1)
                                                            (b/bget-u8 rdata 2)
                                                            (b/bget-u8 rdata 3)]))]
                          (recur (inc a-idx)
                                 rdata-end
                                 (conj answers (cond-> {:name name
                                                        :type rtype
                                                        :class rclass
                                                        :cache-flush? flush?
                                                        :ttl ttl
                                                        :rdata rdata}
                                                 ip-str (assoc :ip ip-str)))))))))
                {:id id
                 :qr? qr?
                 :aa? aa?
                 :questions questions
                 :answers answers}))))))))

;; =============================================================================
;; Pure Sans-IO mDNS Responder & Cache State Machine
;; =============================================================================

(defn init-mdns-table
  "Initializes a pure Sans-IO mDNS state map tracking `:local-hosts`, `:cache`, and `:diagnostics`."
  []
  {:local-hosts {}
   :cache {}
   :diagnostics {:queries-answered 0
                 :answers-cached 0
                 :ignored-malformed 0}})

(defn register-local-host
  "Registers a local `.local` mDNS hostname -> IPv4 mapping in `table`."
  ([table hostname ip-str]
   (register-local-host table hostname ip-str 120))
  ([table hostname ip-str ttl]
   (if-let [norm (normalize-mdns-hostname hostname)]
     (assoc-in table [:local-hosts norm] {:ip ip-str :ttl (long (or ttl 120))})
     table)))

(defn lookup-cached-ip
  "Looks up `hostname` in `table` (`:local-hosts` first, then non-expired `:cache` entries at `now-ms`)."
  ([table hostname]
   (lookup-cached-ip table hostname 0))
  ([table hostname now-ms]
   (when-let [norm (normalize-mdns-hostname hostname)]
     (or (get-in table [:local-hosts norm :ip])
         (when-let [entry (get-in table [:cache norm])]
           (when (or (nil? (:expires-at-ms entry))
                     (<= (long (or now-ms 0)) (long (:expires-at-ms entry))))
             (:ip entry)))))))

(defn handle-mdns-packet
  "Pure Sans-IO reducer processing an inbound mDNS UDP packet against `table` at `now-ms`.
   Returns `{:state <new-table> :response-bytes <bytes-or-nil> :resolved <map-of-hostname->ip>}`."
  ([table pkt-bytes]
   (handle-mdns-packet table pkt-bytes 0))
  ([table pkt-bytes now-ms]
   (if-let [parsed (decode-mdns-packet pkt-bytes)]
     (if (:qr? parsed)
       ;; Inbound mDNS response: cache valid `.local` A records
       (let [a-records (filter #(and (= (:type %) qtype-a)
                                     (string? (:ip %))
                                     (mdns-hostname? (:name %)))
                               (:answers parsed))
             [new-table resolved]
             (reduce (fn [[t acc] ans]
                       (let [h (normalize-mdns-hostname (:name ans))
                             ttl-s (max 1 (long (or (:ttl ans) 120)))
                             exp (+ (long (or now-ms 0)) (* ttl-s 1000))]
                         [(-> t
                              (assoc-in [:cache h] {:ip (:ip ans) :expires-at-ms exp})
                              (update-in [:diagnostics :answers-cached] (fnil inc 0)))
                          (assoc acc h (:ip ans))]))
                     [table {}]
                     a-records)]
         {:state new-table
          :response-bytes nil
          :resolved resolved})
       ;; Inbound mDNS query: check if any question matches `:local-hosts`
       (let [matching (keep (fn [q]
                              (when (or (= (:qtype q) qtype-a) (= (:qtype q) 255))
                                (let [h (normalize-mdns-hostname (:qname q))]
                                  (when-let [local-entry (get-in table [:local-hosts h])]
                                    (assoc local-entry :hostname h)))))
                            (:questions parsed))]
         (if-let [first-match (first matching)]
           (let [resp-bs (encode-mdns-response {:hostname (:hostname first-match)
                                                :ip (:ip first-match)
                                                :ttl (:ttl first-match)
                                                :cache-flush? true})]
             {:state (update-in table [:diagnostics :queries-answered] (fnil inc 0))
              :response-bytes resp-bs
              :resolved {}})
           {:state table
            :response-bytes nil
            :resolved {}})))
     {:state (update-in table [:diagnostics :ignored-malformed] (fnil inc 0))
      :response-bytes nil
      :resolved {}})))

(defn resolve-candidate-address
  "Resolves an SDP ICE candidate map (`{:ip ... :port ...}`) whose `:ip` is a `.local` mDNS hostname
   against `resolver-or-table` (either an mDNS state table map or a `(fn [hostname] ip-str)`),
   preserving `:mdns-hostname` when resolved."
  ([cand resolver-or-table]
   (resolve-candidate-address cand resolver-or-table 0))
  ([cand resolver-or-table now-ms]
   (let [ip (:ip cand)]
     (if (and (string? ip) (mdns-hostname? ip))
       (let [norm (normalize-mdns-hostname ip)
             resolved-ip (cond
                           (fn? resolver-or-table)
                           (resolver-or-table norm)

                           (map? resolver-or-table)
                           (lookup-cached-ip resolver-or-table norm now-ms)

                           :else nil)]
         (if (and (string? resolved-ip) (not (str/blank? resolved-ip)))
           (assoc cand :ip resolved-ip :mdns-hostname norm)
           cand))
       cand))))

;; =============================================================================
;; Optional Boundary UDP Multicast Service (`224.0.0.251:5353`)
;; =============================================================================

(defn start-mdns-service!
  "Starts an optional UDP multicast mDNS responder/resolver service on LAN-capable hosts.
   Gracefully degrades to an in-memory local table if multicast socket binding is disallowed."
  ([]
   (start-mdns-service! {}))
  ([{:keys [initial-hosts port]
     :or {port mdns-port}}]
   (let [table-atom (atom (reduce-kv (fn [t k v]
                                       (register-local-host t k v))
                                     (init-mdns-table)
                                     (or initial-hosts {})))]
     #?(:clj
        (try
          (let [group (InetAddress/getByName mdns-multicast-ipv4)
                sock (try
                       (doto (MulticastSocket. (int port))
                         (.setReuseAddress true)
                         (.joinGroup group))
                       (catch Exception _
                         (doto (DatagramSocket. nil)
                           (.setReuseAddress true)
                           (.bind (InetSocketAddress. "0.0.0.0" 0)))))
                running? (atom true)
                send-pkt! (fn [^bytes bs]
                            (try
                              (let [p (DatagramPacket. bs (alength bs) group (int mdns-port))]
                                (.send sock p))
                              (catch Exception _ nil)))
                reader (Thread/startVirtualThread
                        (fn []
                          (let [buf (byte-array 1500)]
                            (while @running?
                              (try
                                (let [p (DatagramPacket. buf (alength buf))]
                                  (.receive sock p)
                                  (let [rx (java.util.Arrays/copyOf (.getData p) (.getLength p))
                                        now-ms (System/currentTimeMillis)
                                        step (handle-mdns-packet @table-atom rx now-ms)]
                                    (reset! table-atom (:state step))
                                    (when-let [resp (:response-bytes step)]
                                      (send-pkt! resp))))
                                (catch Exception _ nil))))))]
            {:table-atom table-atom
             :socket sock
             :running? running?
             :reader reader
             :send-fn send-pkt!
             :stop-fn (fn []
                        (reset! running? false)
                        (try (.close sock) (catch Exception _ nil)))})
          (catch Exception _
            {:table-atom table-atom
             :send-fn (fn [_] nil)
             :stop-fn (fn [] nil)}))
        :cljs
        (try
          (let [dgram (js/require "node:dgram")
                sock (.createSocket dgram #js {:type "udp4" :reuseAddr true})
                send-pkt! (fn [bs]
                            (try
                              (let [buf (js/Buffer.from bs)]
                                (.send sock buf 0 (.-length buf) mdns-port mdns-multicast-ipv4))
                              (catch :default _ nil)))]
            (.on sock "error" (fn [_] nil))
            (.on sock "message"
                 (fn [msg _rinfo]
                   (let [rx (js/Uint8Array. (.-buffer msg) (.-byteOffset msg) (.-byteLength msg))
                         now-ms (.now js/Date)
                         step (handle-mdns-packet @table-atom rx now-ms)]
                     (reset! table-atom (:state step))
                     (when-let [resp (:response-bytes step)]
                       (send-pkt! resp)))))
            (try
              (.bind sock port "0.0.0.0"
                     (fn []
                       (try (.addMembership sock mdns-multicast-ipv4) (catch :default _ nil))))
              (catch :default _ nil))
            {:table-atom table-atom
             :socket sock
             :send-fn send-pkt!
             :stop-fn (fn []
                        (try (.close sock) (catch :default _ nil)))})
          (catch :default _
            {:table-atom table-atom
             :send-fn (fn [_] nil)
             :stop-fn (fn [] nil)}))))))

(defn stop-mdns-service!
  "Stops a running mDNS service."
  [svc]
  (when-let [f (:stop-fn svc)]
    (f))
  svc)
