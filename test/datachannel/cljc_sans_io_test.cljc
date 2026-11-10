(ns datachannel.cljc-sans-io-test
  "Cross-platform (.cljc) generative and unit tests for the Sans-IO core of clj-datachannel:
   buffer, sdp, dcep, sctp, chunks, packetize, reassemble, stun, turn, tcp, handlers,
   dtls (IDtlsEngine), and core."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [datachannel.api :as api]
            [datachannel.buffer :as b]
            [datachannel.core :as dc]
            [datachannel.dcep :as dcep]
            [datachannel.dtls :as dtls]
            [datachannel.mdns :as mdns]
            [datachannel.sctp :as sctp]
            [datachannel.sdp :as sdp]
            [datachannel.stun :as stun]
            [datachannel.tcp :as tcp]
            [datachannel.turn :as turn]))

;; =============================================================================
;; 1. Binary Buffer, Checksum, and Crypto Primitives (`datachannel.buffer`)
;; =============================================================================

(def gen-byte-vec
  "Generator for vectors of unsigned byte integers (0..255)."
  (gen/vector (gen/choose 0 255) 0 128))

(deftest binary-buffer-primitives-roundtrip-test
  (testing "Generative roundtrip for IBinaryBuffer across u8, u16, s16, u32, s32, i64, and byte slices"
    (let [res (tc/quick-check
               50
               (prop/for-all [u8 (gen/choose 0 255)
                              u16 (gen/choose 0 65535)
                              s16 (gen/choose -32768 32767)
                              u32 (gen/choose 0 4294967295)
                              s32 (gen/choose -2147483648 2147483647)
                              i64 (gen/choose 0 1000000000000)
                              bvec gen-byte-vec
                              le? gen/boolean]
                             (let [order (if le? :little-endian :big-endian)
                                   payload (b/bytes-from-seq bvec)
                                   buf (b/allocate-buffer (+ 32 (b/blength payload)))]
                               (b/buf-set-order! buf order)
                               (b/buf-put-u8! buf u8)
                               (b/buf-put-u16! buf u16)
                               (b/buf-put-u16! buf s16)
                               (b/buf-put-u32! buf u32)
                               (b/buf-put-u32! buf s32)
                               (b/buf-put-i64! buf i64)
                               (b/buf-put-bytes! buf payload)
                               (b/buf-flip! buf)
                               (let [r-u8 (b/buf-get-u8! buf)
                                     r-u16 (b/buf-get-u16! buf)
                                     r-s16 (b/buf-get-s16! buf)
                                     r-u32 (b/buf-get-u32! buf)
                                     r-s32 (b/buf-get-s32! buf)
                                     r-i64 (b/buf-get-i64! buf)
                                     r-bytes (b/alloc-bytes (b/blength payload))]
                                 (b/buf-get-bytes! buf r-bytes)
                                 (and (= u8 r-u8)
                                      (= u16 r-u16)
                                      (= s16 r-s16)
                                      (= u32 r-u32)
                                      (= s32 r-s32)
                                      (= i64 r-i64)
                                      (b/bytes= payload r-bytes)
                                      (zero? (b/buf-remaining buf)))))))]
      (is (:pass? res) (pr-str res)))))

(deftest crc-and-crypto-vectors-test
  (testing "IEEE CRC32 and Castagnoli CRC32C match standard '123456789' test vectors for both byte[] and String (F1)"
    (let [input (b/utf8->bytes "123456789")]
      (is (= 0xCBF43926 (b/crc32-ieee input)))
      (is (= 0xCBF43926 (b/crc32-ieee "123456789")))
      (is (= 0xE3069283 (b/crc32c input)))
      (is (= 0xE3069283 (b/crc32c "123456789")))))
  (testing "UTF-8, hex, Base64, MD5, HMAC-SHA1, and HMAC-SHA256 are deterministic across JVM and Node.js"
    (let [msg (b/utf8->bytes "The quick brown fox jumps over the lazy dog")
          key-str "key"]
      (is (= "The quick brown fox jumps over the lazy dog" (b/bytes->utf8 msg)))
      (is (= "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" (b/bytes->hex (b/sha1-bytes msg))))
      (is (= "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
             (b/bytes->hex (b/sha256-bytes msg))))
      (is (= "9e107d9d372bb6826bd81d3542a419d6" (b/bytes->hex (b/md5-bytes msg))))
      (is (= "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9" (b/bytes->hex (b/hmac-sha1 key-str msg))))
      (is (= "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
             (b/bytes->hex (b/hmac-sha256 key-str msg))))
      (is (= "YWxwZXdhcmU6c2VjcmV0" (b/base64-encode (b/utf8->bytes "alpeware:secret")))))))

;; =============================================================================
;; 2. SDP & DCEP Generative Round-Trip (`datachannel.sdp`, `datachannel.dcep`)
;; =============================================================================

(deftest sdp-and-dcep-generative-roundtrip-test
  (testing "Generative roundtrip for SDP candidate formatting/parsing and offer generation"
    (let [res (tc/quick-check
               40
               (prop/for-all [port (gen/choose 1024 65535)
                              ufrag (gen/fmap #(apply str %) (gen/vector gen/char-alphanumeric 4 12))
                              pwd (gen/fmap #(apply str %) (gen/vector gen/char-alphanumeric 22 30))
                              active? gen/boolean]
                             (let [fp "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
                                   cand-str (sdp/format-candidate {:foundation "1"
                                                                   :component 1
                                                                   :transport "UDP"
                                                                   :priority (sdp/compute-candidate-priority :host)
                                                                   :ip "192.0.2.10"
                                                                   :port port
                                                                   :type "host"
                                                                   :ufrag ufrag})
                                   sdp-str (sdp/format-offer {:local-ip "192.0.2.10"
                                                              :ice-ufrag ufrag
                                                              :ice-pwd pwd
                                                              :fingerprint fp
                                                              :setup (if active? "active" "passive")
                                                              :port port})
                                   parsed-cand (sdp/parse-candidate cand-str)]
                               (and (= sdp/default-max-message-size (sdp/parse-max-message-size sdp-str))
                                    (str/includes? sdp-str (str "a=ice-ufrag:" ufrag))
                                    (str/includes? sdp-str (str "a=ice-pwd:" pwd))
                                    (= "192.0.2.10" (:ip parsed-cand))
                                    (= port (:port parsed-cand))
                                    (= "host" (:type parsed-cand))
                                    (= ufrag (:ufrag parsed-cand))))))]
      (is (:pass? res) (pr-str res))))

  (testing "Generative roundtrip for DCEP OPEN and ACK messages"
    (let [res (tc/quick-check
               50
               (prop/for-all [label gen/string-ascii
                              protocol gen/string-ascii
                              ordered? gen/boolean
                              mode (gen/elements [:reliable :rtx :lifetime])
                              param (gen/choose 0 5000)]
                             (let [open-msg {:type :open
                                             :label label
                                             :protocol protocol
                                             :ordered ordered?
                                             :max-retransmits (when (= mode :rtx) param)
                                             :max-packet-life-time (when (= mode :lifetime) param)}
                                   encoded (dcep/encode-message open-msg)
                                   decoded (dcep/decode-message encoded)
                                   ack-enc (dcep/encode-message {:type :ack})
                                   ack-dec (dcep/decode-message ack-enc)]
                               (and (= :open (:type decoded))
                                    (= label (:label decoded))
                                    (= protocol (:protocol decoded))
                                    (= ordered? (:ordered decoded))
                                    (= (:max-retransmits open-msg) (:max-retransmits decoded))
                                    (= (:max-packet-life-time open-msg) (:max-packet-life-time decoded))
                                    (= {:type :ack} ack-dec)))))]
      (is (:pass? res) (pr-str res)))))

;; =============================================================================
;; 3. SCTP Packet & Chunk Codec (`datachannel.sctp`, `datachannel.chunks`)
;; =============================================================================

(deftest sctp-packet-codec-generative-test
  (testing "Generative roundtrip for SCTP packets with SACK + DATA chunks and CRC32C/zero-checksum"
    (let [res (tc/quick-check
               40
               (prop/for-all [src-port (gen/choose 1000 65535)
                              dst-port (gen/choose 1000 65535)
                              vtag (gen/choose 1 2147483647)
                              tsn (gen/choose 0 2147483647)
                              stream-id (gen/choose 0 1024)
                              seq-num (gen/choose 0 65535)
                              proto (gen/elements [:webrtc/dcep :webrtc/string :webrtc/binary :webrtc/empty-string :webrtc/empty-binary])
                              payload-vec (gen/vector (gen/choose 0 255) 1 200)]
                             (let [payload (b/bytes-from-seq payload-vec)
                                   pkt {:src-port src-port
                                        :dst-port dst-port
                                        :verification-tag vtag
                                        :chunks [{:type :sack
                                                  :cum-tsn-ack tsn
                                                  :a-rwnd 262144
                                                  :gap-blocks [[2 4]]
                                                  :duplicate-tsns [(inc tsn)]}
                                                 {:type :data
                                                  :flags 3
                                                  :tsn tsn
                                                  :stream-id stream-id
                                                  :seq-num seq-num
                                                  :protocol proto
                                                  :payload payload}]}
                                   buf (b/allocate-buffer 4096)
                                   _ (sctp/encode-packet pkt buf {:zero-checksum? false})
                                   _ (b/buf-flip! buf)
                                   decoded (sctp/decode-packet buf)
                                   [c-sack c-data] (:chunks decoded)
                                   zero-buf (b/allocate-buffer 4096)
                                   _ (sctp/encode-packet pkt zero-buf {:zero-checksum? true})
                                   _ (b/buf-flip! zero-buf)]
                               (and (= src-port (:src-port decoded))
                                    (= dst-port (:dst-port decoded))
                                    (= vtag (:verification-tag decoded))
                                    (= :sack (:type c-sack))
                                    (= tsn (:cum-tsn-ack c-sack))
                                    (= [[2 4]] (:gap-blocks c-sack))
                                    (= :data (:type c-data))
                                    (= tsn (:tsn c-data))
                                    (= stream-id (:stream-id c-data))
                                    (= seq-num (:seq-num c-data))
                                    (= proto (:protocol c-data))
                                    (b/bytes= payload (:payload c-data))
                                    (zero? (b/buf-get-u32-at zero-buf 8))))))]
      (is (:pass? res) (pr-str res)))))

;; =============================================================================
;; 4. RFC 4571 Framing & HTTP CONNECT Codec (`datachannel.tcp`)
;; =============================================================================

(deftest rfc4571-and-http-connect-test
  (testing "Generative roundtrip for RFC 4571 stream framing across arbitrary chunk splits"
    (let [res (tc/quick-check
               40
               (prop/for-all [frames-vecs (gen/vector (gen/vector (gen/choose 0 255) 0 300) 1 8)
                              split-size (gen/choose 1 64)]
                             (let [frames (mapv b/bytes-from-seq frames-vecs)
                                   encoded-stream (b/bconcat (map tcp/encode-rfc4571-frame frames))
                                   total-len (b/blength encoded-stream)
                                   {:keys [decoded-frames remaining]}
                                   (loop [offset 0
                                          rem (b/alloc-bytes 0)
                                          acc []]
                                     (if (>= offset total-len)
                                       {:decoded-frames acc :remaining rem}
                                       (let [end (min total-len (+ offset split-size))
                                             chunk (b/bslice encoded-stream offset end)
                                             step (tcp/decode-rfc4571-stream rem chunk)]
                                         (recur end (:remaining step) (into acc (:frames step))))))]
                               (and (= (count frames) (count decoded-frames))
                                    (zero? (b/blength remaining))
                                    (every? true? (map b/bytes= frames decoded-frames))))))]
      (is (:pass? res) (pr-str res))))

  (testing "parse-proxy-url, build-connect-request, and parse-connect-response"
    (let [p (tcp/parse-proxy-url "http://agent:pass123@proxy.bitecho.org:3128")
          req-bytes (tcp/build-connect-request {:target-host "nexus.ingress.bitecho.org"
                                                :target-port 443
                                                :proxy-auth (:proxy-auth p)})
          req-str (b/bytes->utf8 req-bytes)
          trailing (tcp/encode-rfc4571-frame (b/bytes-from-seq [1 2 3 4]))
          resp-ok (b/bconcat [(b/utf8->bytes "HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n")
                              trailing])
          parsed-ok (tcp/parse-connect-response resp-ok)
          deframed (tcp/decode-rfc4571-stream (b/alloc-bytes 0) (:remaining parsed-ok))]
      (is (= {:host "proxy.bitecho.org" :port 3128 :proxy-auth "agent:pass123"} p))
      (is (str/includes? req-str "CONNECT nexus.ingress.bitecho.org:443 HTTP/1.1\r\n"))
      (is (str/includes? req-str "Proxy-Authorization: Basic YWdlbnQ6cGFzczEyMw==\r\n"))
      (is (= :ok (:status parsed-ok)))
      (is (= 200 (:http-status parsed-ok)))
      (is (= 1 (count (:frames deframed))))
      (is (b/bytes= (b/bytes-from-seq [1 2 3 4]) (first (:frames deframed)))))))

;; =============================================================================
;; 5. STUN & TURN Sans-IO Lifecycle (`datachannel.stun`, `datachannel.turn`)
;; =============================================================================

(deftest stun-and-turn-sans-io-test
  (testing "STUN Binding Request / Response with MESSAGE-INTEGRITY, FINGERPRINT, and XOR-MAPPED-ADDRESS"
    (let [req-buf (stun/make-binding-request "clientUfrag" "serverUfrag" "serverSecretPwd12345678"
                                             {:role :controlling :tie-breaker 999 :priority 1853824767 :use-candidate? true})
          srv-state {:ice-ufrag "serverUfrag"
                     :ice-pwd "serverSecretPwd12345678"
                     :ice-role :controlled
                     :ice-tie-breaker 100}
          remote-addr (b/to-socket-address {:ip "203.0.113.7" :port 54321})
          srv-res (stun/handle-packet req-buf remote-addr srv-state)
          resp-buf (:response srv-res)
          cli-state {:ice-ufrag "clientUfrag"
                     :ice-pwd "clientSecretPwd12345678"
                     :remote-ice-ufrag "serverUfrag"
                     :remote-ice-pwd "serverSecretPwd12345678"
                     :ice-role :controlling}
          cli-res (stun/handle-packet (b/wrap-buffer (b/to-bytes resp-buf))
                                      (b/to-socket-address {:ip "198.51.100.1" :port 3478})
                                      cli-state)]
      (is (some? resp-buf))
      (is (true? (:use-candidate? srv-res)))
      (is (= "clientUfrag" (:remote-ice-ufrag srv-res)))
      (is (true? (:binding-response? cli-res)))
      (is (str/includes? (str (:candidate cli-res)) "203.0.113.7"))
      (is (str/includes? (str (:candidate cli-res)) "54321"))))

  (testing "TURN allocation, 401 challenge, permission + channel bind, ChannelData framing, and counted drops"
    (let [tc0 (turn/init-turn-client {:username "agent1" :password "turnPass" :server-addr "198.51.100.2:3478"})
          s1 (turn/start-allocation tc0 {:now-ms 1000})
          alloc1-pkt (turn/parse-turn-packet (first (:network-out s1)))
          r401 (turn/make-turn-error-response turn/METHOD_ALLOCATE_ERROR (:tx-id alloc1-pkt) 401
                                              {:realm "bitecho.org" :nonce "nonce-1"})
          s2 (turn/step-turn-client (:new-state s1) r401 1100)
          alloc2-pkt (turn/parse-turn-packet (first (:network-out s2)))
          r200 (turn/make-allocate-success-response (:tx-id alloc2-pkt) "agent1" "bitecho.org" "turnPass"
                                                    {:ip "198.51.100.2" :port 50000}
                                                    {:ip "203.0.113.9" :port 60000}
                                                    600)
          s3 (turn/step-turn-client (:new-state s2) r200 1200)
          peer-addr (b/to-socket-address {:ip "192.0.2.55" :port 4444})
          s4 (turn/ensure-peer-relay (:new-state s3) peer-addr)
          [perm-raw bind-raw] (:network-out s4)
          perm-pkt (turn/parse-turn-packet perm-raw)
          bind-pkt (turn/parse-turn-packet bind-raw)
          perm-ok (turn/make-create-permission-success-response (:tx-id perm-pkt) "agent1" "bitecho.org" "turnPass")
          bind-ok (turn/make-channel-bind-success-response (:tx-id bind-pkt) "agent1" "bitecho.org" "turnPass")
          s5 (turn/step-turn-client (:new-state s4) perm-ok 1300)
          s6 (turn/step-turn-client (:new-state s5) bind-ok 1400)
          app-payload (b/utf8->bytes "hello-via-turn")
          tx-res (turn/send-via-turn (:new-state s6) peer-addr app-payload)
          cd-frame (first (:network-out tx-res))
          rx-res (turn/step-turn-client (:new-state s6) cd-frame 1500)
          bad-res (turn/step-turn-client (:new-state rx-res) (b/bytes-from-seq [1 2 3]) 1600)]
      (is (= :channel-bound (:state (:new-state s6))))
      (is (:ok? tx-res))
      (is (turn/channel-data? cd-frame))
      (is (= :turn-data (:type (first (:events rx-res)))))
      (is (b/bytes= app-payload (:data (first (:events rx-res)))))
      (is (= 1 (:dropped-frames (:new-state bad-res))))
      (is (= :parse-failed (:reason (first (:events bad-res))))))))

;; =============================================================================
;; 6. Full 2-Peer Sans-IO Connection with Mock `IDtlsEngine` (`datachannel.core`)
;; =============================================================================

(defn make-mock-dtls-engine
  "Creates a pure, deterministic in-memory `IDtlsEngine` implementation for testing
   `datachannel.core` and `datachannel.handlers` across JVM and Node.js without `SSLEngine`."
  [_local-fp peer-fp-atom]
  (let [state-atom (atom {:started? false :finished? false})]
    (reify dtls/IDtlsEngine
      (begin-handshake! [_]
        (swap! state-atom assoc :started? true)
        nil)
      (handshake-finished? [_]
        (:finished? @state-atom))
      (handshake-step [_ in-bytes]
        (let [in-len (b/blength in-bytes)]
          (if (zero? in-len)
            {:status :need-unwrap
             :finished? false
             :packets [(b/bytes-from-seq [22 3 253 0 0 0 0 0 0 0 1 0 1 1])]
             :app-data (b/alloc-bytes 0)}
            (let [was-finished? (:finished? @state-atom)]
              (swap! state-atom assoc :finished? true)
              {:status :finished
               :finished? true
               :packets (if was-finished?
                          []
                          [(b/bytes-from-seq [22 3 253 0 0 0 0 0 0 0 2 0 1 2])])
               :app-data (b/alloc-bytes 0)}))))
      (wrap-app-data [_ plain-bytes]
        (let [raw (b/to-bytes plain-bytes)
              out (b/alloc-bytes (inc (b/blength raw)))]
          (b/bset-u8! out 0 23)
          (b/bcopy! raw 0 out 1 (b/blength raw))
          {:status :ok :bytes out}))
      (unwrap-packet [_ net-bytes]
        (let [raw (b/to-bytes net-bytes)]
          (if (and (> (b/blength raw) 1) (= 23 (b/bget-u8 raw 0)))
            {:status :ok :bytes (b/bslice raw 1 (b/blength raw))}
            {:status :ok :bytes (b/alloc-bytes 0)})))
      (peer-fingerprint [_]
        @peer-fp-atom))))

(defn- pump-packets
  "Routes all serialized outbound packets between two pure Sans-IO connection states until quiescence."
  [client-state server-state now-ms & [init-c->s init-s->c]]
  (loop [c-st client-state
         s-st server-state
         c->s (vec (or init-c->s []))
         s->c (vec (or init-s->c []))
         c-evts []
         s-evts []
         steps 0]
    (if (or (> steps 64) (and (empty? c->s) (empty? s->c)))
      {:client-state c-st
       :server-state s-st
       :client-events c-evts
       :server-events s-evts}
      (if (seq c->s)
        (let [pkt (b/to-bytes (first c->s))
              res (-> (dc/handle-receive s-st pkt now-ms (b/to-socket-address "127.0.0.1:50001"))
                      (dc/serialize-network-out))
              out-pkts (mapv #(if (map? %) (:packet %) %) (:network-out-bytes res))]
          (recur c-st
                 (:new-state res)
                 (subvec c->s 1)
                 (into s->c out-pkts)
                 c-evts
                 (into s-evts (:app-events res))
                 (inc steps)))
        (let [pkt (b/to-bytes (first s->c))
              res (-> (dc/handle-receive c-st pkt now-ms (b/to-socket-address "127.0.0.1:50002"))
                      (dc/serialize-network-out))
              out-pkts (mapv #(if (map? %) (:packet %) %) (:network-out-bytes res))]
          (recur (:new-state res)
                 s-st
                 (into c->s out-pkts)
                 (subvec s->c 1)
                 (into c-evts (:app-events res))
                 s-evts
                 (inc steps)))))))

(deftest full-sans-io-connection-and-dtls-protocol-test
  (testing "2-peer Sans-IO ICE + IDtlsEngine + SCTP + DCEP + fragmented data transfer"
    (let [fp-client "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF"
          fp-server "FF:EE:DD:CC:BB:AA:00:99:88:77:66:55:44:33:22:11:FF:EE:DD:CC:BB:AA:00:99:88:77:66:55:44:33:22:11"
          c-engine (make-mock-dtls-engine fp-client (atom fp-server))
          s-engine (make-mock-dtls-engine fp-server (atom fp-client))
          c0 (dc/create-connection {:ice-ufrag "cufrag"
                                    :ice-pwd "cpwd12345678901234567890"
                                    :remote-ice-ufrag "sufrag"
                                    :remote-ice-pwd "spwd12345678901234567890"
                                    :remote-fingerprint fp-server
                                    :remote-candidates ["127.0.0.1:50002"]
                                    :cert-data {:fingerprint fp-client}
                                    :dtls/engine c-engine}
                                   true)
          s0 (dc/create-connection {:ice-ufrag "sufrag"
                                    :ice-pwd "spwd12345678901234567890"
                                    :remote-ice-ufrag "cufrag"
                                    :remote-ice-pwd "cpwd12345678901234567890"
                                    :remote-fingerprint fp-client
                                    :cert-data {:fingerprint fp-server}
                                    :dtls/engine s-engine}
                                   false)
          ;; 1. STUN keepalive + nomination
          stun-step (-> (dc/handle-timeout c0 :stun/keepalive 1000)
                        (dc/serialize-network-out))
          stun-pkts (mapv #(if (map? %) (:packet %) %) (:network-out-bytes stun-step))
          s-after-stun (-> (dc/handle-receive s0 (b/to-bytes (first stun-pkts)) 1010 (b/to-socket-address "127.0.0.1:50001"))
                           (dc/serialize-network-out))
          c-after-stun (-> (dc/handle-receive (:new-state stun-step)
                                              (b/to-bytes (first (:network-out-bytes s-after-stun)))
                                              1020
                                              (b/to-socket-address "127.0.0.1:50002"))
                           (dc/serialize-network-out))
          _ (is (= :connected (:ice-connection-state (:new-state c-after-stun))))
          _ (is (true? (:nominated? (:new-state c-after-stun))))

          ;; 2. DTLS flight kickoff + SCTP 4-way handshake
          _ (dtls/begin-handshake! c-engine)
          _ (dtls/begin-handshake! s-engine)
          dtls-kickoff (-> (dc/handle-timeout (:new-state c-after-stun) :dtls/flight-timeout 1100)
                           (dc/serialize-network-out))
          hs-res (pump-packets (:new-state dtls-kickoff)
                               (:new-state s-after-stun)
                               1200
                               (:network-out-bytes dtls-kickoff)
                               [])
          c-est (:client-state hs-res)
          s-est (:server-state hs-res)
          _ (is (= :established (:state c-est)))
          _ (is (= :established (:state s-est)))

          ;; 3. Open DataChannel via DCEP and send a multi-fragment 3000-byte payload
          dc-open (-> (dc/create-data-channel c-est "mesh-bus" {:ordered true :protocol "bitecho/v1"})
                      (dc/serialize-network-out))
          pumped-open (pump-packets (:new-state dc-open)
                                    s-est
                                    1310
                                    (:network-out-bytes dc-open)
                                    [])
          c-ch-open (:client-state pumped-open)
          s-ch-open (:server-state pumped-open)
          _ (is (= :open (get-in c-ch-open [:data-channels 0 :state])))
          _ (is (= :open (get-in s-ch-open [:data-channels 0 :state])))

          large-payload (b/bytes-from-seq (take 3000 (cycle (range 256))))
          send-res (-> (dc/send-data c-ch-open large-payload 0 :webrtc/binary 1400)
                       (dc/serialize-network-out))
          rx-fold (reduce (fn [acc pkt-buf]
                            (let [r (-> (dc/handle-receive (:s acc) (b/to-bytes pkt-buf) 1410)
                                        (dc/serialize-network-out))]
                              {:s (:new-state r)
                               :evts (into (:evts acc) (:app-events r))}))
                          {:s s-ch-open :evts []}
                          (:network-out-bytes send-res))
          msg-evt (first (filter #(= (:type %) :on-message) (:evts rx-fold)))]
      (is (some? msg-evt))
      (is (= 0 (:stream-id msg-evt)))
      (is (b/bytes= large-payload (:payload msg-evt)))))

  (testing "DTLS fingerprint mismatch immediately closes connection and emits SCTP ABORT"
    (let [c-engine (make-mock-dtls-engine "AA:BB" (atom "WRONG:FP"))
          c0 (dc/create-connection {:remote-fingerprint "EXPECTED:FP"
                                    :dtls/engine c-engine}
                                   true)
          res (dc/handle-receive c0 (b/bytes-from-seq [22 3 253 0 0 0 0 0 0 0 1 0 1 1]) 2000)]
      (is (= :closed (:state (:new-state res))))
      (is (some #(= (:type %) :on-error) (:app-events res)))))

  (testing "M2b: Real DTLS 1.2 engine (SSLEngine on JVM, node:crypto DTLS 1.2 on Node.js) + full SCTP/DCEP E2E + datachannel.api"
    (let [node-a (api/create-node {:port 5000 :setup "active"})
          node-b (api/create-node {:port 5001 :setup "passive"})
          cert-a (:cert-data node-a)
          cert-b (:cert-data node-b)
          c0 (dc/create-connection {:ice-ufrag (get-in node-a [:ice-creds :ufrag])
                                    :ice-pwd (get-in node-a [:ice-creds :pwd])
                                    :remote-ice-ufrag (get-in node-b [:ice-creds :ufrag])
                                    :remote-ice-pwd (get-in node-b [:ice-creds :pwd])
                                    :remote-fingerprint (:fingerprint cert-b)
                                    :remote-candidates ["127.0.0.1:5001"]
                                    :cert-data cert-a}
                                   true)
          s0 (dc/create-connection {:ice-ufrag (get-in node-b [:ice-creds :ufrag])
                                    :ice-pwd (get-in node-b [:ice-creds :pwd])
                                    :remote-ice-ufrag (get-in node-a [:ice-creds :ufrag])
                                    :remote-ice-pwd (get-in node-a [:ice-creds :pwd])
                                    :remote-fingerprint (:fingerprint cert-a)
                                    :cert-data cert-b}
                                   false)
          _ (dtls/begin-handshake! (:dtls/engine c0))
          _ (dtls/begin-handshake! (:dtls/engine s0))
          dtls-kickoff (-> (dc/handle-timeout c0 :dtls/flight-timeout 1100)
                           (dc/serialize-network-out))
          hs-res (pump-packets (:new-state dtls-kickoff)
                               s0
                               1200
                               (:network-out-bytes dtls-kickoff)
                               [])
          c-est (:client-state hs-res)
          s-est (:server-state hs-res)
          _ (is (dtls/handshake-finished? (:dtls/engine c-est)))
          _ (is (dtls/handshake-finished? (:dtls/engine s-est)))
          _ (is (= (:fingerprint cert-b) (dtls/peer-fingerprint (:dtls/engine c-est))))
          _ (is (= (:fingerprint cert-a) (dtls/peer-fingerprint (:dtls/engine s-est))))
          _ (is (= :established (:state c-est)))
          _ (is (= :established (:state s-est)))
          aead-prop (tc/quick-check
                     25
                     (prop/for-all [bvec (gen/vector (gen/choose 0 255) 1 512)]
                                   (let [plain (b/bytes-from-seq bvec)
                                         enc (:bytes (dtls/wrap-app-data (:dtls/engine c-est) plain))
                                         dec (:bytes (dtls/unwrap-packet (:dtls/engine s-est) enc))]
                                     (b/bytes= plain dec))))
          dc-open (-> (dc/create-data-channel c-est "bitecho" {:ordered true :protocol "fressian-v1"})
                      (dc/serialize-network-out))
          pumped-open (pump-packets (:new-state dc-open)
                                    s-est
                                    1300
                                    (:network-out-bytes dc-open)
                                    [])
          msg-bytes (b/utf8->bytes "m2b-real-dtls12-sctp-payload")
          send-res (-> (dc/send-data (:client-state pumped-open) msg-bytes 0 :webrtc/binary 1400)
                       (dc/serialize-network-out))
          rx-res (pump-packets (:new-state send-res)
                               (:server-state pumped-open)
                               1410
                               (:network-out-bytes send-res)
                               [])
          msg-evt (first (filter #(= (:type %) :on-message) (:server-events rx-res)))]
      (is (:pass? aead-prop) (pr-str aead-prop))
      (is (some? msg-evt))
      (is (b/bytes= msg-bytes (:payload msg-evt)))
      (is (b/bytes= (b/hmac-sha1 "key" (b/utf8->bytes "msg"))
                    (b/hmac-sha1 "key" "msg")))
      (is (b/bytes= (b/hmac-sha256 "key" (b/utf8->bytes "msg"))
                    (b/hmac-sha256 "key" "msg")))
      (is (zero? (b/blength (:bytes (dtls/unwrap-packet (:dtls/engine s-est)
                                                        (b/bytes-from-seq [23 0x03 0x03 0 1 0 0 0 0 0 0 0 1 0xAA]))))))
      (is (false? (api/should-reap-child? c-est 1500)))
      (is (true? (api/should-reap-child? (assoc c-est :state :closed) 1500))))))

;; =============================================================================
;; 11. RFC 6762 Multicast DNS (`datachannel.mdns`) Codec & Candidate Resolution
;; =============================================================================

(def ^:private gen-mdns-label
  (gen/fmap (fn [chars]
              (str "a" (apply str chars) "z"))
            (gen/vector (gen/elements (vec "abcdefghijklmnopqrstuvwxyz0123456789-")) 4 22)))

(def ^:private gen-ipv4-str
  (gen/fmap (fn [[a b c d]]
              (str a "." b "." c "." d))
            (gen/tuple (gen/choose 1 223)
                       (gen/choose 0 255)
                       (gen/choose 0 255)
                       (gen/choose 1 254))))

(deftest mdns-codec-and-candidate-resolution-test
  (testing "Generative roundtrip for RFC 6762 mDNS query/response packets, state machine, and SDP candidate resolution"
    (let [res (tc/quick-check
               50
               (prop/for-all [label gen-mdns-label
                              ip-str gen-ipv4-str
                              ttl (gen/choose 10 3600)
                              port (gen/choose 1024 65535)
                              unicast? gen/boolean
                              flush? gen/boolean]
                             (let [hostname (str (str/lower-case label) ".local")
                                   q-pkt (mdns/encode-mdns-query hostname {:qtype 1 :unicast-response? unicast?})
                                   q-dec (mdns/decode-mdns-packet q-pkt)
                                   q-first (first (:questions q-dec))
                                   r-pkt (mdns/encode-mdns-response {:hostname hostname
                                                                     :ip ip-str
                                                                     :ttl ttl
                                                                     :cache-flush? flush?})
                                   r-dec (mdns/decode-mdns-packet r-pkt)
                                   a-first (first (:answers r-dec))
                                   ;; Pure responder & cache state-machine flow
                                   host-table (-> (mdns/init-mdns-table)
                                                  (mdns/register-local-host hostname ip-str ttl))
                                   q-step (mdns/handle-mdns-packet host-table q-pkt 1000)
                                   peer-table (mdns/init-mdns-table)
                                   r-step (mdns/handle-mdns-packet peer-table (:response-bytes q-step) 1000)
                                   cand-str (sdp/format-candidate {:foundation "1"
                                                                   :component 1
                                                                   :transport "UDP"
                                                                   :type "host"
                                                                   :ip hostname
                                                                   :port port})
                                   parsed-cand (sdp/parse-candidate cand-str)
                                   resolved-cand (mdns/resolve-candidate-address parsed-cand (:state r-step) 1000)]
                               (and (mdns/mdns-hostname? hostname)
                                    (mdns/mdns-hostname? (str hostname "."))
                                    (not (mdns/mdns-hostname? ip-str))
                                    (not (mdns/mdns-hostname? "nexus.ingress.bitecho.org"))
                                    (false? (:qr? q-dec))
                                    (= 0 (:id q-dec))
                                    (= hostname (:qname q-first))
                                    (= 1 (:qtype q-first))
                                    (= unicast? (:unicast-response? q-first))
                                    (true? (:qr? r-dec))
                                    (true? (:aa? r-dec))
                                    (= hostname (:name a-first))
                                    (= 1 (:type a-first))
                                    (= ttl (:ttl a-first))
                                    (= flush? (:cache-flush? a-first))
                                    (= ip-str (:ip a-first))
                                    (some? (:response-bytes q-step))
                                    (= ip-str (get (:resolved r-step) hostname))
                                    (= ip-str (:ip resolved-cand))
                                    (= hostname (:mdns-hostname resolved-cand))
                                    (= port (:port resolved-cand))))))]
      (is (:pass? res) (pr-str res))
      (let [gen-host (mdns/generate-mdns-hostname)
            empty-tab (mdns/init-mdns-table)
            bad-step (mdns/handle-mdns-packet empty-tab (b/bytes-from-seq [1 2 3]) 1000)]
        (is (mdns/mdns-hostname? gen-host))
        (is (nil? (mdns/decode-mdns-packet (b/bytes-from-seq [1 2 3]))))
        (is (= 1 (get-in bad-step [:state :diagnostics :ignored-malformed])))))))
