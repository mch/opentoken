(ns mch.opentoken.util
  (:require [clojure.string :as str]))

(defn make-byte-array [s]
  (byte-array (map #(byte %) s)))

(defn map-to-string [m]
  "Converts a map to a OpenToken payload string."
  {:pre [(map? m)]}
  (let [sify (fn [k v acc] (format "%s=%s\r\n%s" k v acc))]
    (reduce (fn [acc x] (if (sequential? (second x))
                          (reduce #(sify (first x) %2 %1) acc (second x))
                          (sify (first x) (second x) acc))) "" m)))

(defn string-to-map [s]
  "Converts a OpenToken string to a Clojure map, where the value is a vector,
since OpenToken allows for multiple values per key. Either \r\n or \n may be
used to separate items."
  (let [sep (if (nil? (re-find #"\r\n" s)) #"\n" #"\r\n")
        pairs (map #(str/split % #"=") (str/split s sep))
        rfn (fn [acc x]
              (let [[key value] x
                    value-vec (get acc key [])]
                (assoc acc key (conj value-vec value))))]
    (reduce rfn {} pairs)))

(defn b64-decode [s]
  "Decode a string or array using Base64 encoding via Apache Commons Codec"
  (org.apache.commons.codec.binary.Base64/decodeBase64 s))

(defn b64-encode [ba]
  "Encode a string or array using Base64 encoding via Apache Commons Codec"
  (org.apache.commons.codec.binary.Base64/encodeBase64 ba))

(defn byte-array? [o]
  "Returns true if an object is a byte array"
  (instance? (Class/forName "[B") o))

(defn make-cookie-safe [s]
  "Makes a string cookie safe by changing = to *"
  (apply str (map #(if (= \= %) \* %) s)))

(defn revert-cookie-safety [s]
  "Reverts cookie safety by changing * to ="
  (apply str (map #(if (= \* %) \= %) s)))

(defn deflate [input]
  "Deflate a byte-array."
  (let [out (java.io.ByteArrayOutputStream.)
        deflater (java.util.zip.DeflaterOutputStream. out)]
    (doto deflater
      (.write input 0 (count input))
      (.close))
    (.toByteArray out)))

(defn inflate [input]
  "Inflate a byte-array."
  (let [out (java.io.ByteArrayOutputStream.)
        inflater (java.util.zip.InflaterOutputStream. out)]
    (doto inflater
      (.write input 0 (count input))
      (.close))
    (.toByteArray out)))

