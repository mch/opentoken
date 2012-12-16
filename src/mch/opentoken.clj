(ns mch.opentoken
  "Implements the OpenToken specification: http://tools.ietf.org/html/draft-smith-opentoken-02"
  (:require [gloss core io])
  (:require [clojure.data.codec.base64 :as b64]))

(def cipher-suites {:none 0 :aes-256 1 :aes-128 2 :3des-168 3})

(def opentoken-frame {:otk (gloss.core/string :utf-8 :length 3)
                      :version :byte
                      :cipher-suite :byte
                      :hmac (gloss.core/finite-block 20)
                      :iv (gloss.core/finite-block :byte)
                      :key-info (gloss.core/finite-block :byte)
                      :payload (gloss.core/finite-block :int16)})

(gloss.core/defcodec opentoken opentoken-frame)

(def payload-len-frame {:payload-len :int16})
  
(gloss.core/defcodec payload-len-codec payload-len-frame)

(defn stringify-payload [payload]
  "Converts a map to a OpenToken payload string."
  {:pre [(map? payload)]}
  (reduce #(format "%s=%s\r\n%s" (first %2) (second %2) %1) "" payload))

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
    (.update digester (.getBytes cleartext-payload "utf-8"))
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
        _ (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key)
        params (.getParameters cipher)
        iv (.getIV (.getParameterSpec params javax.crypto.spec.IvParameterSpec))
        ciphertext (.doFinal cipher cleartext)]
    {:iv iv :ciphertext ciphertext}))

(defn encrypt-aes [cleartext key iv]
  (let [cipher (javax.crypto.Cipher/getInstance "AES/CBC/PKCS5Padding")
        _ (if (nil? iv)
            (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key)
            (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key (javax.crypto.spec.IvParameterSpec. iv)))
        params (.getParameters cipher)
        iv (.getIV cipher)
        ;iv (.getIV (.getParameterSpec params javax.crypto.spec.IvParameterSpec)) ; or just (.getIV cipher)?
        ciphertext (.doFinal cipher cleartext)]
    {:iv iv :ciphertext ciphertext}))

(defn make-aes-key [key-len password salt]
  (let [s (if (string? salt) (.getBytes salt "UTF-8") salt)
        pbe-name "PBKDF2WithHmacSHA1"
        key-factory (javax.crypto.SecretKeyFactory/getInstance pbe-name)
        key-spec (javax.crypto.spec.PBEKeySpec. (.toCharArray password) s 65536 key-len)
        key (javax.crypto.spec.SecretKeySpec. (.getEncoded (.generateSecret key-factory key-spec)) "AES")]
    key))

(defn make-3des-key [key-len password salt]
  (let [s (if (string? salt) (.getBytes salt "UTF-8") salt)
        pbe-name "PBEWithHmacSHA1AndDESede"
        key-factory (javax.crypto.SecretKeyFactory/getInstance pbe-name)
        key-spec (javax.crypto.spec.PBEKeySpec. (.toCharArray password) s 65536 key-len)
        key (javax.crypto.spec.SecretKeySpec. (.getEncoded (.generateSecret key-factory key-spec)) "DESede")]
    key))

(defn make-key [cipher password salt]
  (cond (= cipher :none) (byte-array 1 (byte 1))
        (= cipher :aes-256) (make-aes-key 256 password salt)
        (= cipher :aes-128) (make-aes-key 128 password salt)
        (= cipher :3des-168) (make-3des-key 168 password salt)
        :else (throw (IllegalArgumentException. "Invalid cipher."))))


(defn encrypt [cleartext & {:keys [cipher password salt key iv]
                            :or {cipher :aes-256 password "" salt nil key nil iv nil}}]
  (if-not (contains? cipher-suites cipher)
    (throw (IllegalArgumentException. "Invalid cipher.")))
  (let [k (if-not (nil? key) key (make-key cipher password salt))
        c (if (string? cleartext) (.getBytes cleartext "UTF-8") cleartext)]
        (cond (= cipher :none) c
              (contains? #{:aes-256 :aes-128} cipher) (encrypt-aes c k iv)
              (= cipher :3des-168) (encrypt-des c k iv))))

(defn decrypt-aes [secret salt iv ciphertext & {:keys [cipher-name key-length] :or {cipher-name "AES" key-length 256}}]
  (if-not (string? secret) (throw (IllegalArgumentException. "Secret must be a string.")))
  (if-not (string? salt) (throw (IllegalArgumentException. "Salt must be a string.")))
  (if-not (contains? #{"AES" "DESede"} cipher-name) (throw (IllegalArgumentException. ":cipher-name must be \"AES\" or \"DESede\"")))
  (let [pbe-name (if (= cipher-name "AES") "PBKDF2WithHmacSHA1" "PBEWithHmacSHA1AndDESede")
        key-factory (javax.crypto.SecretKeyFactory/getInstance pbe-name)
        key-spec (javax.crypto.spec.PBEKeySpec. (.toCharArray secret) (.getBytes salt) 65536 key-length)
        key (javax.crypto.spec.SecretKeySpec. (.getEncoded (.generateSecret key-factory key-spec)) "AES")
        cipher (javax.crypto.Cipher/getInstance (str cipher-name "/CBC/PKCS5Padding"))
        _ (.init cipher javax.crypto.Cipher/DECRYPT_MODE key (javax.crypto.spec.IvParameterSpec. iv))
        plaintext (String. (.doFinal cipher ciphertext) "UTF-8")]
    plaintext))

(defn create-frame [version cipher-suite hmac iv key-info payload]
  (.array (gloss.io/contiguous (gloss.io/encode opentoken {:otk "OTK" :version 1 :cipher-suite 1
                                                           :hmac hmac :iv iv :key-info nil
                                                           :payload payload}))))

(defn make-cookie-safe [s]
  "Makes a string cookie safe by changing = to *"
  (apply str (map #(if (= \= %) \* %) s)))

(defn revert-cookie-safety [s]
  "Reverts cookie safety by changing * to ="
  (apply str (map #(if (= \* %) \= %) s)))

(defn encode [payload secret & {:keys [cipher salt] :or {cipher :none salt ""}}]
  "Returns a string representing the encrypted OpenToken."
  (if-not (map? payload)
    (throw (java.lang.IllegalArgumentException. "Payload must be a map.")))
  (if-not (contains? cipher-suites cipher)
    (throw (java.lang.IllegalArgumentException. "Cipher must be one of :none, :aes-256, :aes-128, or :3des-168.")))
  (let [cleartext-payload (stringify-payload payload)
        compressed-cleartext (deflate (.getBytes cleartext-payload "utf-8"))
        encryptor (fn [payload] (encrypt-aes secret salt payload))
        {:keys [ciphertext iv]} (encryptor compressed-cleartext)
        hmac (create-hmac 1 1 iv nil cleartext-payload)
        bin (create-frame 1 1 hmac iv nil ciphertext)
        b64token (String. (b64/encode bin) "UTF-8")]
    (make-cookie-safe b64token)))

(defn decode [token secret & {:keys [cipher salt] :or {cipher :aes-256}}]
  "Decodes a OpenToken. Will throw an exception if the token is invalid."
  nil)
