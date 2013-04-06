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
  (org.apache.commons.codec.binary.Base64/decodeBase64 s))

(defn b64-encode [ba]
  (org.apache.commons.codec.binary.Base64/encodeBase64 ba))

