(ns mch.opentoken
  "Implements the OpenToken specification: http://tools.ietf.org/html/draft-smith-opentoken-02"
  (:require [gloss core io])
  (:require [clojure.string :as str])
  (:require [clojure.data.codec.base64 :as b64]))

;;; TODO
;;; - Error handling: catch various exceptions and rethrow as an OpenTokenException
;;; - Try multi-methods to dispatch encryption and decryption on cipher
;;; - Reduce structural duplication
;;; - Move everything except the public API defs to mch.opentoken.encryption and so on.
;;; - Use streams to reduce copying, or some other method more suitable to functional composition. 

(def cipher-suites {:none 0 :aes-256 1 :aes-128 2 :3des-168 3})
(def opentoken-version 1)
(def opentoken-literal "OTK")
(def opentoken-default-salt (byte-array 8 (byte 0)))
(def opentoken-default-iterations 1000)
(def opentoken-standard-pairs {"subject" ""
                               "not-before" ""
                               "not-on-or-after" ""
                               "renew-until" ""})

(def opentoken-frame-keys [:otk :version :cipher-suite :hmac :iv :key-info :payload])

(def opentoken-frame [(gloss.core/string :utf-8 :length 3)
                      :byte
                      :byte
                      (gloss.core/finite-block 20)
                      (gloss.core/finite-block :byte)
                      (gloss.core/finite-block :byte)
                      (gloss.core/finite-block :int16)])

(gloss.core/defcodec opentoken opentoken-frame)

(def payload-len-frame {:payload-len :int16})
(gloss.core/defcodec payload-len-codec payload-len-frame)

(defn map-to-string [m]
  "Converts a map to a OpenToken payload string."
  {:pre [(map? m)]}
  (let [sify (fn [k v acc] (format "%s=%s\r\n%s" k v acc))]
    (reduce (fn [acc x] (if (sequential? (second x))
                          (reduce #(sify (first x) %2 %1) acc (second x))
                          (sify (first x) (second x) acc))) "" m)))

(defn string-to-map [s]
  "Converts a OpenToken string to a Clojure map, where the value is a vector,
since OpenToken allows for multiple values per key."
  (let [pairs (map #(str/split % #"=") (str/split s #"\r\n"))
        rfn (fn [acc x]
              (let [[key value] x
                    value-vec (get acc key [])]
                (assoc acc key (conj value-vec value))))]
    (reduce rfn {} pairs)))

;; updating should be equivalent to creating a single byte-array and doing it all at once. 
(defn create-hmac [version suite iv key-info cleartext-payload]
  (let [digester (java.security.MessageDigest/getInstance "SHA-1")]
    (.update digester (byte version))
    (.update digester (byte suite))
    (if-not (nil? iv)
      (if (= (type iv) (type (byte-array 0)))
        (.update digester iv)))
    (if-not (nil? key-info)
      (if (= (type key-info) (type (byte-array 0)))
        (.update digester key-info)))
    (.update digester
             (.array (gloss.io/contiguous
                      (gloss.io/encode payload-len-codec {:payload-len (count cleartext-payload)}))))
    (.update digester (if (string? cleartext-payload) (.getBytes cleartext-payload "utf-8") cleartext-payload))
    (.digest digester)))

(defn deflate [input]
  (let [out (java.io.ByteArrayOutputStream.)
        deflater (java.util.zip.DeflaterOutputStream. out)]
    (doto deflater
      (.write input 0 (count input))
      (.close))
    (.toByteArray out)))

(defn inflate [input]
  (let [out (java.io.ByteArrayOutputStream.)
        inflater (java.util.zip.InflaterOutputStream. out)]
    (doto inflater
      (.write input 0 (count input))
      (.close))
    (.toByteArray out)))

(defn encrypt-des [cleartext key iv]
  (let [cipher (javax.crypto.Cipher/getInstance "DESede/CBC/PKCS5Padding")
        _ (if (nil? iv)
            (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key)
            (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key (javax.crypto.spec.IvParameterSpec. iv)))
        params (.getParameters cipher)
        iv (.getIV cipher)
        ciphertext (.doFinal cipher cleartext)]
    {:iv iv :ciphertext ciphertext}))

(defn encrypt-aes [cleartext key iv]
  (let [cipher (javax.crypto.Cipher/getInstance "AES/CBC/PKCS5Padding")
        _ (if (nil? iv)
            (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key)
            (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key (javax.crypto.spec.IvParameterSpec. iv)))
        params (.getParameters cipher)
        iv (.getIV cipher)
        ciphertext (.doFinal cipher cleartext)]
    {:iv iv :ciphertext ciphertext}))

(defn decrypt-des [ciphertext key iv]
  (let [cipher (javax.crypto.Cipher/getInstance "DESede/CBC/PKCS5Padding")
        _ (.init cipher javax.crypto.Cipher/DECRYPT_MODE key (javax.crypto.spec.IvParameterSpec. iv))
        cleartext (.doFinal cipher ciphertext)]
    cleartext))

(defn decrypt-aes [ciphertext key iv]
  (let [cipher (javax.crypto.Cipher/getInstance "AES/CBC/PKCS5Padding")
        _ (.init cipher javax.crypto.Cipher/DECRYPT_MODE key (javax.crypto.spec.IvParameterSpec. iv))
        cleartext (.doFinal cipher ciphertext)]
    cleartext))

(defn make-aes-key [key-len password salt]  
  (let [s (if (nil? salt) opentoken-default-salt
              (if (string? salt) (.getBytes salt "UTF-8") salt))
        pbe-name "PBKDF2WithHmacSHA1"
        key-factory (javax.crypto.SecretKeyFactory/getInstance pbe-name)
        key-spec (javax.crypto.spec.PBEKeySpec. (.toCharArray password) s opentoken-default-iterations key-len)
        key (javax.crypto.spec.SecretKeySpec. (.getEncoded (.generateSecret key-factory key-spec)) "AES")]
    key))

(defn make-3des-key [key-len password salt]
  (let [s (if (nil? salt) opentoken-default-salt
              (if (string? salt) (.getBytes salt "UTF-8") salt))
        pbe-name "PBEWithHmacSHA1AndDESede"
        key-factory (javax.crypto.SecretKeyFactory/getInstance pbe-name)
        key-spec (javax.crypto.spec.PBEKeySpec. (.toCharArray password) s opentoken-default-iterations key-len)
        key (javax.crypto.spec.SecretKeySpec. (.getEncoded (.generateSecret key-factory key-spec)) "DESede")]
    key))

(defn make-key [cipher password salt]
  (cond (= cipher :none) (byte-array 1 (byte 1))
        (= cipher :aes-256) (make-aes-key 256 password salt)
        (= cipher :aes-128) (make-aes-key 128 password salt)
        (= cipher :3des-168) (make-3des-key 168 password salt)
        :else (throw (IllegalArgumentException. "Invalid cipher."))))

(defn make-key-from-ba [cipher key]
  (cond (= cipher :aes-256) (javax.crypto.spec.SecretKeySpec. key "AES")
        (= cipher :aes-128) (javax.crypto.spec.SecretKeySpec. key "AES")
        (= cipher :3des-168) (javax.crypto.spec.SecretKeySpec. key "DESede")))

(defn encrypt [cleartext & {:keys [cipher password salt key iv]
                            :or {cipher :aes-256 password "" salt nil key nil iv nil}}]
  (if-not (contains? cipher-suites cipher)
    (throw (IllegalArgumentException. "Invalid cipher.")))
  (let [k (if-not (nil? key)
            (make-key-from-ba cipher key)
            (make-key cipher password salt))
        c (if (string? cleartext) (.getBytes cleartext "UTF-8") cleartext)]
    (cond (= cipher :none) c
          (contains? #{:aes-256 :aes-128} cipher) (encrypt-aes c k iv)
          (= cipher :3des-168) (encrypt-des c k iv))))

(defn decrypt [ciphertext & {:keys [cipher password salt key iv]
                             :or {cipher :aes-256 password "" salt nil key nil iv nil}}]
  (if-not (contains? cipher-suites cipher)
    (throw (IllegalArgumentException. "Invalid cipher.")))
  (let [k (if-not (nil? key)
            (make-key-from-ba cipher key)
            (make-key cipher password salt))]
    (cond (= cipher :none) ciphertext
          (contains? #{:aes-256 :aes-128} cipher) (decrypt-aes ciphertext k iv)
          (= cipher :3des-168) (decrypt-des ciphertext k iv))))

(defn create-frame [version cipher-suite hmac iv key-info payload]
  (.array (gloss.io/contiguous (gloss.io/encode opentoken
                                                [opentoken-literal
                                                 version
                                                 cipher-suite
                                                 hmac
                                                 iv
                                                 key-info
                                                 payload]))))

(defn decode-frame [token]
  (gloss.io/decode opentoken token))

(defn make-cookie-safe [s]
  "Makes a string cookie safe by changing = to *"
  (apply str (map #(if (= \= %) \* %) s)))

(defn revert-cookie-safety [s]
  "Reverts cookie safety by changing * to ="
  (apply str (map #(if (= \* %) \= %) s)))

(defn token-valid? [token]
  "Validates OTK literal and version."
  (and (= opentoken-version (:version token))
       (= opentoken-literal (:otk token))
       (>= 3 (:cipher-suite token))
       (<= 0 (:cipher-suite token))))

(defn hmac-valid? [token cleartext]
  "Validates OpenToken HMAC."
  (let [hmac (create-hmac (:version token)
                          (:cipher-suite token)
                          (:iv token)
                          (:key-info token)
                          cleartext)]
    (= (seq hmac) (seq (:hmac token)))))

(defn buffer-to-array [b]
  (if (nil? b)
    b
    (let [in (first b)
          l (.limit in)
          out (byte-array l)]
      (.get in out 0 l)
      out)))

(defn decode-token [token]
  "Decodes a OpenToken, returning a map of OpenToken components."
  (let [tbytes (-> token
                   (revert-cookie-safety)
                   (.getBytes "UTF-8")
                   (b64/decode)
                   (decode-frame))
        frame (apply hash-map (interleave opentoken-frame-keys tbytes))]
    (assoc frame
      :hmac (buffer-to-array (:hmac frame))
      :iv (buffer-to-array (:iv frame))
      :key-info (buffer-to-array (:key-info frame))
      :payload (buffer-to-array (:payload frame)))))

(defn decrypt-token [token & {:keys [cipher password salt key]
                              :or {cipher :aes-256 password nil salt nil key nil}}]
  "Decrypts and inflates the payload of the token, returning a byte array
containing the decrypted text."
  (if-not (contains? cipher-suites cipher) ;; TODO multi-method on cipher type?
    (throw (java.lang.IllegalArgumentException. "Cipher must be one of :none, :aes-256, :aes-128, or :3des-168.")))
  (let [t (if (string? token) (decode-token token) token)]
    (inflate (decrypt (:payload t) ;; TODO catch crypto exceptions and re-throw an OpenToken one?
                      :cipher cipher
                      :password password
                      :salt salt
                      :key key
                      :iv (:iv t)))))

(defn decode [token key-decider]
  "Decodes an OpenToken supplied as a string. Calls the key-decider
function with a map containing the token, from which the :cipher-suite
and :key-info items should be used to identify the key to use. The
key-decider function must return a map containing either a :password,
:password and :salt, or a :key. Returns a map of the key value pairs that
were stored in the token."
  (let [dt (decode-token token)] ;; catch gloss exceptions and rethrow OpenToken specific ones?
    (if-not (token-valid? dt)
      {:status :invalid-token} ;; throw exception?
      (let [{:keys [password salt key] :or {password nil salt nil key nil}}
            (key-decider dt)
            cleartext (decrypt-token dt :password password :salt salt :key key)]
        (if-not (hmac-valid? dt cleartext)
          {:status :invalid-hmac} ;; throw exception?
          (string-to-map (String. cleartext "UTF-8")))))))

;; TODO use the same key-decider function as decode? Nice symmetry that way.
;; TODO catch and rethrow exceptions?
(defn encode [payload & {:keys [cipher password salt key iv key-info] :or {cipher :aes-256 password nil salt nil key nil iv nil key-info nil}}]
  "Encodes a map as an encrypted OpenToken. One of :password, :password and :salt,
or :key must be supplied."
  (if-not (map? payload)
    (throw (java.lang.IllegalArgumentException. "Payload must be a map.")))
  (if-not (contains? cipher-suites cipher)
    (throw (java.lang.IllegalArgumentException. "Cipher must be one of :none, :aes-256, :aes-128, or :3des-168.")))
  (let [cleartext-payload (map-to-string payload)
        compressed-cleartext (deflate (.getBytes cleartext-payload "utf-8"))
        encryptor (fn [payload] (encrypt payload :cipher cipher :password password :salt salt :key key :iv iv))
        {:keys [ciphertext iv]} (encryptor compressed-cleartext)
        hmac (create-hmac opentoken-version (cipher cipher-suites) iv nil cleartext-payload)
        bin (create-frame opentoken-version (cipher cipher-suites) hmac iv key-info ciphertext)
        b64token (String. (b64/encode bin) "UTF-8")]
    (make-cookie-safe b64token)))
