(ns datachannel.buffer
  "Cross-platform binary buffer, byte-array, CRC32/CRC32C, HMAC, MD5, Base64,
   and random utilities for `.cljc` Sans-IO state machines across JVM and Node.js."
  (:require [clojure.string :as str]
            #?(:cljs [goog.crypt.base64 :as b64]))
  #?(:clj
     (:import [java.net InetAddress InetSocketAddress]
              [java.nio ByteBuffer ByteOrder]
              [java.nio.charset StandardCharsets]
              [java.security MessageDigest SecureRandom]
              [java.util Arrays Base64]
              [java.util.zip CRC32 CRC32C]
              [javax.crypto Mac]
              [javax.crypto.spec SecretKeySpec])))

#?(:clj (defonce ^:private secure-rand (SecureRandom.)))
#?(:cljs (def ^:private node-crypto (when (exists? js/require) (js/require "crypto"))))

;; =============================================================================
;; 1. Portable Byte Array Primitives
;; =============================================================================

(defn byte-array?
  "Returns true if `x` is a native byte array (`byte[]` on JVM, `Uint8Array` on CLJS)."
  [x]
  #?(:clj (bytes? x)
     :cljs (instance? js/Uint8Array x)))

(defn alloc-bytes
  "Allocates a zero-filled byte array of length `n`."
  [n]
  #?(:clj (byte-array (int n))
     :cljs (js/Uint8Array. (int n))))

(defn bytes-from-seq
  "Creates a native byte array from a sequence of byte integers."
  [coll]
  #?(:clj (byte-array (map unchecked-byte coll))
     :cljs (let [v (vec coll)
                 n (count v)
                 out (js/Uint8Array. n)]
             (dotimes [i n]
               (aset out i (bit-and (int (nth v i)) 0xFF)))
             out)))

(def empty-bytes
  "Shared zero-length byte array."
  (alloc-bytes 0))

(defn blength
  "Returns the byte length of `bs` (0 if nil)."
  ^long [bs]
  (if (nil? bs)
    0
    #?(:clj (alength ^bytes bs)
       :cljs (.-length ^js bs))))

(defn bget-u8
  "Reads an unsigned 8-bit integer (0..255) from `bs` at index `idx`."
  ^long [bs ^long idx]
  #?(:clj (bit-and (int (aget ^bytes bs (int idx))) 0xFF)
     :cljs (bit-and (aget ^js bs idx) 0xFF)))

(defn bget-s8
  "Reads a signed 8-bit integer (-128..127) from `bs` at index `idx`."
  ^long [bs ^long idx]
  #?(:clj (long (aget ^bytes bs (int idx)))
     :cljs (let [u (bit-and (aget ^js bs idx) 0xFF)]
             (if (>= u 128) (- u 256) u))))

(defn bset-u8!
  "Writes the low 8 bits of `val` into `bs` at index `idx`."
  [bs ^long idx ^long val]
  #?(:clj (aset-byte ^bytes bs (int idx) (unchecked-byte (bit-and val 0xFF)))
     :cljs (aset ^js bs idx (bit-and val 0xFF)))
  bs)

(defn bcopy!
  "Copies `len` bytes from `src` at `src-pos` into `dst` at `dst-pos`."
  [src src-pos dst dst-pos len]
  (when (pos? len)
    #?(:clj (System/arraycopy src (int src-pos) dst (int dst-pos) (int len))
       :cljs (.set ^js dst (.subarray ^js src src-pos (+ src-pos len)) dst-pos)))
  dst)

(defn bslice
  "Returns a new byte array containing bytes `[start, end)` of `bs`."
  [bs ^long start ^long end]
  (let [len (max 0 (- end start))]
    #?(:clj (Arrays/copyOfRange ^bytes bs (int start) (int (+ start len)))
       :cljs (let [out (js/Uint8Array. len)]
               (when (pos? len)
                 (.set out (.subarray ^js bs start (+ start len)) 0))
               out))))

(defn bconcat
  "Concatenates a collection of byte arrays into a single byte array."
  [arrays]
  (let [non-nil (keep identity arrays)
        total (long (reduce + 0 (map blength non-nil)))
        out (alloc-bytes total)]
    (loop [offset 0
           [arr & more] non-nil]
      (if-not arr
        out
        (let [n (blength arr)]
          (bcopy! arr 0 out offset n)
          (recur (+ offset n) more))))))

(defn bytes=
  "Constant-time / content equality for two byte arrays `a` and `b`."
  [a b]
  (cond
    (and (nil? a) (nil? b)) true
    (or (nil? a) (nil? b)) false
    (not= (blength a) (blength b)) false
    :else
    #?(:clj (MessageDigest/isEqual ^bytes a ^bytes b)
       :cljs (let [n (blength a)]
               (loop [i 0
                      diff 0]
                 (if (= i n)
                   (zero? diff)
                   (recur (inc i) (bit-or diff (bit-xor (bget-u8 a i) (bget-u8 b i))))))))))

;; =============================================================================
;; 2. Portable UTF-8, Hex, Base64, and Random Helpers
;; =============================================================================

(defn utf8->bytes
  "Encodes string `s` into UTF-8 bytes."
  [s]
  (let [s-str (or s "")]
    #?(:clj (.getBytes ^String s-str StandardCharsets/UTF_8)
       :cljs (js/Uint8Array. (.encode (js/TextEncoder.) s-str)))))

(defn bytes->utf8
  "Decodes UTF-8 bytes (or slice `[offset, offset+len)`) into a string."
  ([bs]
   (if (nil? bs)
     ""
     #?(:clj (String. ^bytes bs StandardCharsets/UTF_8)
        :cljs (.decode (js/TextDecoder. "utf-8") bs))))
  ([bs ^long offset ^long len]
   (bytes->utf8 (bslice bs offset (+ offset len)))))

(defn bytes->hex
  "Formats byte array `bs` as a lowercase hex string."
  [bs]
  (let [n (blength bs)
        hex-chars "0123456789abcdef"]
    (loop [i 0
           acc (transient [])]
      (if (= i n)
        (apply str (persistent! acc))
        (let [v (bget-u8 bs i)]
          (recur (inc i)
                 (-> acc
                     (conj! (nth hex-chars (unsigned-bit-shift-right v 4)))
                     (conj! (nth hex-chars (bit-and v 0x0F))))))))))

(defn base64-encode
  "Encodes byte array `bs` into a standard Base64 string."
  [bs]
  #?(:clj (.encodeToString (Base64/getEncoder) ^bytes bs)
     :cljs (b64/encodeByteArray bs)))

(defn random-bytes
  "Generates `n` cryptographically random bytes."
  [n]
  #?(:clj (let [b (byte-array (int n))]
            (.nextBytes secure-rand b)
            b)
     :cljs (if node-crypto
             (js/Uint8Array. (.randomBytes node-crypto (int n)))
             (let [b (js/Uint8Array. (int n))]
               (when (and (exists? js/crypto) (.-getRandomValues js/crypto))
                 (.getRandomValues js/crypto b))
               b))))

(defn random-int
  "Generates a cryptographically random non-negative integer in `[0, bound)`."
  ^long [^long bound]
  #?(:clj (.nextInt secure-rand (int bound))
     :cljs (let [bs (random-bytes 4)
                 u32 (bit-or (bit-shift-left (bget-u8 bs 0) 24)
                             (bit-shift-left (bget-u8 bs 1) 16)
                             (bit-shift-left (bget-u8 bs 2) 8)
                             (bget-u8 bs 3))
                 unsigned (bit-and u32 0x7FFFFFFF)]
             (mod unsigned bound))))

(defn random-u64
  "Generates a random 64-bit integer (truncated to safe 53-bit positive integer on JS so it fits cleanly in numbers, or full long on JVM)."
  ^long []
  #?(:clj (.nextLong secure-rand)
     :cljs (let [bs (random-bytes 7)]
             (loop [i 0
                    acc 0]
               (if (= i 6)
                 (+ (* acc 128) (bit-and (bget-u8 bs 6) 0x7F))
                 (recur (inc i) (+ (* acc 256) (bget-u8 bs i))))))))

(defn now-ms
  "Returns current wall-clock epoch milliseconds."
  ^long []
  #?(:clj (System/currentTimeMillis)
     :cljs (.now js/Date)))

;; =============================================================================
;; 3. Portable Stateful Binary Buffer (`PacketBuffer` + JVM `ByteBuffer` interop)
;; =============================================================================

(defprotocol IBinaryBuffer
  (buf-position [buf] "Returns current cursor position.")
  (buf-set-position! [buf pos] "Sets current cursor position.")
  (buf-limit [buf] "Returns current limit.")
  (buf-set-limit! [buf lim] "Sets current limit.")
  (buf-remaining [buf] "Returns remaining bytes `(limit - position)`.")
  (buf-has-remaining? [buf] "Returns true if `(pos? (buf-remaining buf))`.")
  (buf-clear! [buf] "Resets position to 0 and limit to capacity.")
  (buf-flip! [buf] "Sets limit to current position and resets position to 0.")
  (buf-order [buf] "Returns current byte order (`:big-endian` or `:little-endian`).")
  (buf-set-order! [buf order] "Sets byte order (`:big-endian` or `:little-endian`).")
  (buf-duplicate [buf] "Returns a duplicate buffer sharing the underlying byte array.")
  (buf-get-u8! [buf] "Reads unsigned 8-bit integer at current position and advances by 1.")
  (buf-get-u16! [buf] "Reads unsigned 16-bit integer at current position and advances by 2.")
  (buf-get-s16! [buf] "Reads signed 16-bit integer at current position and advances by 2.")
  (buf-get-u32! [buf] "Reads unsigned 32-bit integer at current position and advances by 4.")
  (buf-get-s32! [buf] "Reads signed 32-bit integer at current position and advances by 4.")
  (buf-get-i64! [buf] "Reads 64-bit integer at current position and advances by 8.")
  (buf-get-u32-at [buf idx] "Reads unsigned 32-bit integer at absolute index `idx` without advancing.")
  (buf-get-bytes! [buf dst] "Reads `(blength dst)` bytes into `dst` and advances position.")
  (buf-put-u8! [buf v] "Writes 8-bit integer `v` at current position and advances by 1.")
  (buf-put-u16! [buf v] "Writes 16-bit integer `v` at current position and advances by 2.")
  (buf-put-u16-at! [buf idx v] "Writes 16-bit integer `v` at absolute index `idx` without advancing.")
  (buf-put-u32! [buf v] "Writes 32-bit integer `v` at current position and advances by 4.")
  (buf-put-u32-at! [buf idx v] "Writes 32-bit integer `v` at absolute index `idx` without advancing.")
  (buf-put-i64! [buf v] "Writes 64-bit integer `v` at current position and advances by 8.")
  (buf-put-bytes! [buf src] "Writes all bytes from `src` at current position and advances.")
  (buf->bytes [buf] "Returns a native byte array copy of `[position, limit)` without mutating cursor.")
  (buf-backing-array [buf] "Returns the full backing byte array when available."))

#?(:clj
   (extend-type ByteBuffer
     IBinaryBuffer
     (buf-position [b] (.position b))
     (buf-set-position! [b pos] (.position b (int pos)) b)
     (buf-limit [b] (.limit b))
     (buf-set-limit! [b lim] (.limit b (int lim)) b)
     (buf-remaining [b] (.remaining b))
     (buf-has-remaining? [b] (.hasRemaining b))
     (buf-clear! [b] (.clear b) b)
     (buf-flip! [b] (.flip b) b)
     (buf-order [b] (if (= (.order b) ByteOrder/LITTLE_ENDIAN) :little-endian :big-endian))
     (buf-set-order! [b order]
       (.order b (if (= order :little-endian) ByteOrder/LITTLE_ENDIAN ByteOrder/BIG_ENDIAN))
       b)
     (buf-duplicate [b]
       (let [d (.duplicate b)]
         (.order d (.order b))
         d))
     (buf-get-u8! [b] (bit-and (int (.get b)) 0xFF))
     (buf-get-u16! [b] (bit-and (int (.getShort b)) 0xFFFF))
     (buf-get-s16! [b] (long (.getShort b)))
     (buf-get-u32! [b] (bit-and (long (.getInt b)) 0xFFFFFFFF))
     (buf-get-s32! [b] (long (.getInt b)))
     (buf-get-i64! [b] (.getLong b))
     (buf-get-u32-at [b idx] (bit-and (long (.getInt b (int idx))) 0xFFFFFFFF))
     (buf-get-bytes! [b dst] (.get b ^bytes dst) dst)
     (buf-put-u8! [b v] (.put b (unchecked-byte (bit-and (long v) 0xFF))) b)
     (buf-put-u16! [b v] (.putShort b (unchecked-short (bit-and (long v) 0xFFFF))) b)
     (buf-put-u16-at! [b idx v] (.putShort b (int idx) (unchecked-short (bit-and (long v) 0xFFFF))) b)
     (buf-put-u32! [b v] (.putInt b (unchecked-int (bit-and (long v) 0xFFFFFFFF))) b)
     (buf-put-u32-at! [b idx v] (.putInt b (int idx) (unchecked-int (bit-and (long v) 0xFFFFFFFF))) b)
     (buf-put-i64! [b v] (.putLong b (long v)) b)
     (buf-put-bytes! [b src]
       (when (and src (pos? (blength src)))
         (.put b ^bytes src))
       b)
     (buf->bytes [b]
       (let [dup (.duplicate b)
             arr (byte-array (.remaining dup))]
         (.get dup arr)
         arr))
     (buf-backing-array [b]
       (if (.hasArray b)
         (.array b)
         (buf->bytes b)))))

#?(:cljs
   (deftype JsBinaryBuffer [^js u8 ^js dv ^:mutable ^number pos ^:mutable ^number lim ^:mutable order]
     IBinaryBuffer
     (buf-position [_] pos)
     (buf-set-position! [this new-pos]
       (when (or (< new-pos 0) (> new-pos lim))
         (throw (ex-info "Buffer position out of bounds" {:pos new-pos :limit lim})))
       (set! pos new-pos)
       this)
     (buf-limit [_] lim)
     (buf-set-limit! [this new-lim]
       (when (or (< new-lim 0) (> new-lim (.-length u8)))
         (throw (ex-info "Buffer limit out of bounds" {:limit new-lim :capacity (.-length u8)})))
       (set! lim new-lim)
       (when (> pos lim) (set! pos lim))
       this)
     (buf-remaining [_] (max 0 (- lim pos)))
     (buf-has-remaining? [_] (< pos lim))
     (buf-clear! [this]
       (set! pos 0)
       (set! lim (.-length u8))
       this)
     (buf-flip! [this]
       (set! lim pos)
       (set! pos 0)
       this)
     (buf-order [_] order)
     (buf-set-order! [this new-order]
       (set! order new-order)
       this)
     (buf-duplicate [_]
       (JsBinaryBuffer. u8 dv pos lim order))
     (buf-get-u8! [_]
       (when (>= pos lim)
         (throw (ex-info "Buffer underflow" {:pos pos :limit lim :need 1})))
       (let [v (.getUint8 dv pos)]
         (set! pos (inc pos))
         v))
     (buf-get-u16! [_]
       (when (> (+ pos 2) lim)
         (throw (ex-info "Buffer underflow" {:pos pos :limit lim :need 2})))
       (let [le? (= order :little-endian)
             v (.getUint16 dv pos le?)]
         (set! pos (+ pos 2))
         v))
     (buf-get-s16! [_]
       (when (> (+ pos 2) lim)
         (throw (ex-info "Buffer underflow" {:pos pos :limit lim :need 2})))
       (let [le? (= order :little-endian)
             v (.getInt16 dv pos le?)]
         (set! pos (+ pos 2))
         v))
     (buf-get-u32! [_]
       (when (> (+ pos 4) lim)
         (throw (ex-info "Buffer underflow" {:pos pos :limit lim :need 4})))
       (let [le? (= order :little-endian)
             v (.getUint32 dv pos le?)]
         (set! pos (+ pos 4))
         v))
     (buf-get-s32! [_]
       (when (> (+ pos 4) lim)
         (throw (ex-info "Buffer underflow" {:pos pos :limit lim :need 4})))
       (let [le? (= order :little-endian)
             v (.getInt32 dv pos le?)]
         (set! pos (+ pos 4))
         v))
     (buf-get-i64! [_]
       (when (> (+ pos 8) lim)
         (throw (ex-info "Buffer underflow" {:pos pos :limit lim :need 8})))
       (let [le? (= order :little-endian)
             hi (.getUint32 dv (if le? (+ pos 4) pos) le?)
             lo (.getUint32 dv (if le? pos (+ pos 4)) le?)]
         (set! pos (+ pos 8))
         (+ (* (bit-and hi 0x1FFFFF) 4294967296) lo)))
     (buf-get-u32-at [_ idx]
       (let [le? (= order :little-endian)]
         (.getUint32 dv idx le?)))
     (buf-get-bytes! [_ dst]
       (let [n (blength dst)]
         (when (> (+ pos n) lim)
           (throw (ex-info "Buffer underflow" {:pos pos :limit lim :need n})))
         (when (pos? n)
           (.set ^js dst (.subarray u8 pos (+ pos n)) 0))
         (set! pos (+ pos n))
         dst))
     (buf-put-u8! [this v]
       (when (>= pos lim)
         (throw (ex-info "Buffer overflow" {:pos pos :limit lim :need 1})))
       (.setUint8 dv pos (bit-and v 0xFF))
       (set! pos (inc pos))
       this)
     (buf-put-u16! [this v]
       (when (> (+ pos 2) lim)
         (throw (ex-info "Buffer overflow" {:pos pos :limit lim :need 2})))
       (.setUint16 dv pos (bit-and v 0xFFFF) (= order :little-endian))
       (set! pos (+ pos 2))
       this)
     (buf-put-u16-at! [this idx v]
       (.setUint16 dv idx (bit-and v 0xFFFF) (= order :little-endian))
       this)
     (buf-put-u32! [this v]
       (when (> (+ pos 4) lim)
         (throw (ex-info "Buffer overflow" {:pos pos :limit lim :need 4})))
       (.setUint32 dv pos (unsigned-bit-shift-right v 0) (= order :little-endian))
       (set! pos (+ pos 4))
       this)
     (buf-put-u32-at! [this idx v]
       (.setUint32 dv idx (unsigned-bit-shift-right v 0) (= order :little-endian))
       this)
     (buf-put-i64! [this v]
       (when (> (+ pos 8) lim)
         (throw (ex-info "Buffer overflow" {:pos pos :limit lim :need 8})))
       (let [le? (= order :little-endian)
             pos-v (if (neg? v) (+ v 9007199254740992) v)
             hi (js/Math.floor (/ pos-v 4294967296))
             lo (unsigned-bit-shift-right (mod pos-v 4294967296) 0)]
         (if le?
           (do (.setUint32 dv pos lo true)
               (.setUint32 dv (+ pos 4) hi true))
           (do (.setUint32 dv pos hi false)
               (.setUint32 dv (+ pos 4) lo false)))
         (set! pos (+ pos 8))
         this))
     (buf-put-bytes! [this src]
       (let [n (blength src)]
         (when (> (+ pos n) lim)
           (throw (ex-info "Buffer overflow" {:pos pos :limit lim :need n})))
         (when (pos? n)
           (.set u8 src pos))
         (set! pos (+ pos n))
         this))
     (buf->bytes [_]
       (bslice u8 pos lim))
     (buf-backing-array [_]
       u8)))

(defn allocate-buffer
  "Allocates a new binary buffer of `size` bytes in big-endian order."
  [size]
  #?(:clj (ByteBuffer/allocate (int size))
     :cljs (let [u8 (js/Uint8Array. (int size))
                 dv (js/DataView. (.-buffer u8) (.-byteOffset u8) (.-byteLength u8))]
             (JsBinaryBuffer. u8 dv 0 (int size) :big-endian))))

(defn wrap-buffer
  "Wraps a byte array `bs` (or returns an existing `IBinaryBuffer` duplicate) in big-endian order."
  [bs]
  (cond
    (satisfies? IBinaryBuffer bs) (buf-duplicate bs)
    #?@(:clj [(bytes? bs) (ByteBuffer/wrap ^bytes bs)]
        :cljs [(instance? js/Uint8Array bs)
               (let [dv (js/DataView. (.-buffer bs) (.-byteOffset bs) (.-byteLength bs))]
                 (JsBinaryBuffer. bs dv 0 (.-length bs) :big-endian))])))

(defn binary-buffer?
  "Returns true if `x` satisfies `IBinaryBuffer`."
  [x]
  (satisfies? IBinaryBuffer x))

(defn to-bytes
  "Coerces a byte array or `IBinaryBuffer` to a native byte array.
   Note: returns `nil` for non-buffer inputs such as Strings; use `utf8->bytes` for String encoding."
  [buf-or-bytes]
  (cond
    (nil? buf-or-bytes) nil
    (byte-array? buf-or-bytes) buf-or-bytes
    (satisfies? IBinaryBuffer buf-or-bytes) (buf->bytes buf-or-bytes)
    :else nil))

;; =============================================================================
;; 4. Portable Unsigned 64-Bit Comparison & Signed 32/16-Bit Serial Arithmetic
;; =============================================================================

(defn compare-u64
  "Compares two 64-bit integers `a` and `b` as unsigned 64-bit numbers.
   Returns negative, zero, or positive integer."
  ^long [^long a ^long b]
  #?(:clj (Long/compareUnsigned a b)
     :cljs (compare a b)))

(defn s32-diff
  "Computes signed 32-bit serial difference `(a - b)` wrapped to `[-2147483648, 2147483647]` per RFC 4960."
  ^long [^long a ^long b]
  #?(:clj (long (unchecked-int (unchecked-subtract (unchecked-int a) (unchecked-int b))))
     :cljs (let [d (bit-or (- (bit-or a 0) (bit-or b 0)) 0)]
             d)))

(defn s16-diff
  "Computes signed 16-bit serial difference `(a - b)` wrapped to `[-32768, 32767]`."
  ^long [^long a ^long b]
  #?(:clj (long (unchecked-short (unchecked-subtract (unchecked-short a) (unchecked-short b))))
     :cljs (let [raw (bit-and (- a b) 0xFFFF)]
             (if (>= raw 0x8000) (- raw 0x10000) raw))))

;; =============================================================================
;; 5. Portable CRC32 (IEEE 802.3) and CRC32C (Castagnoli)
;; =============================================================================

#?(:cljs
   (def ^:private crc32-ieee-table
     (let [tbl (js/Uint32Array. 256)]
       (dotimes [n 256]
         (loop [k 0
                c n]
           (if (= k 8)
             (aset tbl n (unsigned-bit-shift-right c 0))
             (recur (inc k)
                    (if (pos? (bit-and c 1))
                      (bit-xor 0xEDB88320 (unsigned-bit-shift-right c 1))
                      (unsigned-bit-shift-right c 1))))))
       tbl)))

#?(:cljs
   (def ^:private crc32c-castagnoli-table
     (let [tbl (js/Uint32Array. 256)]
       (dotimes [n 256]
         (loop [k 0
                c n]
           (if (= k 8)
             (aset tbl n (unsigned-bit-shift-right c 0))
             (recur (inc k)
                    (if (pos? (bit-and c 1))
                      (bit-xor 0x82F63B78 (unsigned-bit-shift-right c 1))
                      (unsigned-bit-shift-right c 1))))))
       tbl)))

(defn crc32-ieee
  "Computes unsigned 32-bit IEEE 802.3 CRC32 over `buf-or-bytes-or-str`."
  ^long [buf-or-bytes-or-str]
  (let [bs (if (string? buf-or-bytes-or-str)
             (utf8->bytes buf-or-bytes-or-str)
             (to-bytes buf-or-bytes-or-str))]
    #?(:clj (let [crc (CRC32.)]
              (.update crc ^bytes bs)
              (.getValue crc))
       :cljs (let [len (blength bs)]
               (loop [i 0
                      c 0xFFFFFFFF]
                 (if (= i len)
                   (unsigned-bit-shift-right (bit-xor c 0xFFFFFFFF) 0)
                   (let [b (bget-u8 bs i)
                         idx (bit-and (bit-xor c b) 0xFF)
                         t (aget crc32-ieee-table idx)]
                     (recur (inc i)
                            (unsigned-bit-shift-right
                             (bit-xor (unsigned-bit-shift-right c 8) t)
                             0)))))))))

(defn crc32c
  "Computes unsigned 32-bit Castagnoli CRC32C over `buf-or-bytes-or-str`."
  ^long [buf-or-bytes-or-str]
  #?(:clj (if (instance? ByteBuffer buf-or-bytes-or-str)
            (let [crc (CRC32C.)]
              (.update crc ^ByteBuffer buf-or-bytes-or-str)
              (.getValue crc))
            (let [bs (if (string? buf-or-bytes-or-str)
                       (utf8->bytes buf-or-bytes-or-str)
                       (to-bytes buf-or-bytes-or-str))
                  crc (CRC32C.)]
              (.update crc ^bytes bs)
              (.getValue crc)))
     :cljs (let [bs (if (string? buf-or-bytes-or-str)
                      (utf8->bytes buf-or-bytes-or-str)
                      (to-bytes buf-or-bytes-or-str))
                 len (blength bs)]
             (when (satisfies? IBinaryBuffer buf-or-bytes-or-str)
               (buf-set-position! buf-or-bytes-or-str (buf-limit buf-or-bytes-or-str)))
             (loop [i 0
                    c 0xFFFFFFFF]
               (if (= i len)
                 (unsigned-bit-shift-right (bit-xor c 0xFFFFFFFF) 0)
                 (let [b (bget-u8 bs i)
                       idx (bit-and (bit-xor c b) 0xFF)
                       t (aget crc32c-castagnoli-table idx)]
                   (recur (inc i)
                          (unsigned-bit-shift-right
                           (bit-xor (unsigned-bit-shift-right c 8) t)
                           0))))))))

;; =============================================================================
;; 6. Portable SHA-1, SHA-256, HMAC-SHA1, HMAC-SHA256, and MD5
;; =============================================================================

(defn sha1-bytes
  "Computes 20-byte SHA-1 digest of `data-bytes-or-str`."
  [data-bytes-or-str]
  (let [d-bytes (if (string? data-bytes-or-str) (utf8->bytes data-bytes-or-str) (to-bytes data-bytes-or-str))]
    #?(:clj (let [md (MessageDigest/getInstance "SHA-1")]
              (.digest md ^bytes d-bytes))
       :cljs (let [hash (.createHash node-crypto "sha1")]
               (.update hash (js/Buffer.from d-bytes))
               (js/Uint8Array. (.digest hash))))))

(defn sha256-bytes
  "Computes 32-byte SHA-256 digest of `data-bytes-or-str`."
  [data-bytes-or-str]
  (let [d-bytes (if (string? data-bytes-or-str) (utf8->bytes data-bytes-or-str) (to-bytes data-bytes-or-str))]
    #?(:clj (let [md (MessageDigest/getInstance "SHA-256")]
              (.digest md ^bytes d-bytes))
       :cljs (let [hash (.createHash node-crypto "sha256")]
               (.update hash (js/Buffer.from d-bytes))
               (js/Uint8Array. (.digest hash))))))

(defn hmac-sha1
  "Computes 20-byte HMAC-SHA1 over `data-bytes-or-str` with `key-bytes-or-str`."
  [key-bytes-or-str data-bytes-or-str]
  (let [k-bytes (if (string? key-bytes-or-str) (utf8->bytes key-bytes-or-str) (to-bytes key-bytes-or-str))
        d-bytes (if (string? data-bytes-or-str) (utf8->bytes data-bytes-or-str) (to-bytes data-bytes-or-str))]
    #?(:clj (let [mac (Mac/getInstance "HmacSHA1")
                  key-spec (SecretKeySpec. ^bytes k-bytes "HmacSHA1")]
              (.init mac key-spec)
              (.doFinal mac ^bytes d-bytes))
       :cljs (let [hmac (.createHmac node-crypto "sha1" (js/Buffer.from k-bytes))]
               (.update hmac (js/Buffer.from d-bytes))
               (js/Uint8Array. (.digest hmac))))))

(defn hmac-sha256
  "Computes 32-byte HMAC-SHA256 over `data-bytes-or-str` with `key-bytes-or-str`."
  [key-bytes-or-str data-bytes-or-str]
  (let [k-bytes (if (string? key-bytes-or-str) (utf8->bytes key-bytes-or-str) (to-bytes key-bytes-or-str))
        d-bytes (if (string? data-bytes-or-str) (utf8->bytes data-bytes-or-str) (to-bytes data-bytes-or-str))]
    #?(:clj (let [mac (Mac/getInstance "HmacSHA256")
                  key-spec (SecretKeySpec. ^bytes k-bytes "HmacSHA256")]
              (.init mac key-spec)
              (.doFinal mac ^bytes d-bytes))
       :cljs (let [hmac (.createHmac node-crypto "sha256" (js/Buffer.from k-bytes))]
               (.update hmac (js/Buffer.from d-bytes))
               (js/Uint8Array. (.digest hmac))))))

(defn md5-bytes
  "Computes 16-byte MD5 digest of `data-bytes-or-str`."
  [data-bytes-or-str]
  (let [d-bytes (if (string? data-bytes-or-str) (utf8->bytes data-bytes-or-str) (to-bytes data-bytes-or-str))]
    #?(:clj (let [md (MessageDigest/getInstance "MD5")]
              (.digest md ^bytes d-bytes))
       :cljs (let [hash (.createHash node-crypto "md5")]
               (.update hash (js/Buffer.from d-bytes))
               (js/Uint8Array. (.digest hash))))))

;; =============================================================================
;; 7. Portable Socket Address / IPv4 Helpers
;; =============================================================================

(defn ipv4-bytes->str
  "Formats a 4-byte IPv4 address array as dotted quad string `'a.b.c.d'`."
  [addr-bytes]
  (str (bget-u8 addr-bytes 0) "."
       (bget-u8 addr-bytes 1) "."
       (bget-u8 addr-bytes 2) "."
       (bget-u8 addr-bytes 3)))

(defn ipv4-str->bytes
  "Parses a dotted quad IPv4 string `'a.b.c.d'` into a 4-byte array."
  [ip-str]
  (let [parts (str/split (str/trim (or ip-str "127.0.0.1")) #"\.")]
    (when (not= 4 (count parts))
      (throw (ex-info (str "Invalid IPv4 address: " ip-str) {:ip ip-str})))
    (let [out (alloc-bytes 4)]
      (dotimes [i 4]
        (bset-u8! out i (long (#?(:clj Integer/parseInt :cljs js/parseInt) (nth parts i)))))
      out)))

(defn parse-int
  "Parses string `s` as integer or returns `default-val`."
  ([s] (parse-int s nil))
  ([s default-val]
   (if (number? s)
     (long s)
     (try
       (let [v (#?(:clj Long/parseLong :cljs js/parseInt) (str/trim (str s)))]
         #?(:clj v
            :cljs (if (js/isNaN v) default-val v)))
       (catch #?(:clj Exception :cljs :default) _
         default-val)))))

(defn normalize-socket-addr
  "Normalizes a socket address (`InetSocketAddress` on JVM, `{:ip :port}` map, or `'ip:port'` string)
   into a map `{:ip <str> :port <int> :raw <orig>}`."
  [addr]
  (cond
    (nil? addr) nil
    #?@(:clj [(instance? InetSocketAddress addr)
              (let [^InetSocketAddress isa addr
                    inet (.getAddress isa)
                    ip (if inet (.getHostAddress inet) (.getHostString isa))]
                {:ip ip :port (.getPort isa) :raw isa})])
    (and (map? addr) (:ip addr) (:port addr))
    {:ip (str (:ip addr))
     :port (int (parse-int (:port addr) 0))
     :raw addr}

    (and (string? addr) (str/includes? addr ":"))
    (let [cleaned (str/replace-first addr #"^/" "")
          idx (str/last-index-of cleaned ":")
          ip (subs cleaned 0 idx)
          port (parse-int (subs cleaned (inc idx)) 0)]
      {:ip ip :port (int port) :raw addr})

    :else nil))

(defn to-socket-address
  "Resolves a candidate (`InetSocketAddress`, `'ip:port'` string, or `{:ip :port}` map)
   into `InetSocketAddress` on JVM or `{:ip <str> :port <int>}` map on CLJS."
  [cand]
  (cond
    (nil? cand) nil
    #?@(:clj [(instance? InetSocketAddress cand) cand])
    (and (map? cand) (:ip cand) (:port cand))
    (let [ip (str (:ip cand))
          port (int (parse-int (:port cand) 0))]
      #?(:clj (InetSocketAddress. ^String ip port)
         :cljs {:ip ip :port port}))
    (and (string? cand) (str/includes? cand ":"))
    (let [norm (normalize-socket-addr cand)]
      #?(:clj (InetSocketAddress. ^String (:ip norm) (int (:port norm)))
         :cljs {:ip (:ip norm) :port (:port norm)}))
    :else cand))

(defn format-ip-port
  "Formats a normalized or native socket address as `'ip:port'`."
  [addr]
  (when-let [norm (normalize-socket-addr addr)]
    (str (:ip norm) ":" (:port norm))))

(defn make-inet-address
  "Creates a platform address representation from a 4-byte IPv4 array (`InetAddress` on JVM,
   or `{:host-address <str> :bytes <u8>}` on CLJS supporting `:host-address`)."
  [addr-bytes]
  #?(:clj (InetAddress/getByAddress ^bytes addr-bytes)
     :cljs {:host-address (ipv4-bytes->str addr-bytes)
            :bytes addr-bytes}))

(defn inet-address->str
  "Extracts dotted-quad IPv4 string from `addr` returned by `make-inet-address`."
  [addr]
  (cond
    (string? addr) addr
    (map? addr) (:host-address addr)
    #?@(:clj [(instance? InetAddress addr) (.getHostAddress ^InetAddress addr)])
    :else (str addr)))
