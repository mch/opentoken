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

;; Use java.util.zip.DeflaterOutputSteam
(defn deflate [payload]
  payload)

;; http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
(defn encrypt-aes [secret salt payload & {:keys [cipher-name key-length] :or {cipher-name "AES" key-length 256}}]
  (if-not (string? secret) (throw (IllegalArgumentException. "Secret must be a string.")))
  (if-not (string? salt) (throw (IllegalArgumentException. "Salt must be a string.")))
  (if-not (contains? #{"AES" "DESede"} cipher-name) (throw (IllegalArgumentException. ":cipher-name must be \"AES\" or \"DES\"")))
  (let [pbe-name (if (= cipher-name "AES") "PBKDF2WithHmacSHA1" "PBEWithHmacSHA1AndDESede")
        key-factory (javax.crypto.SecretKeyFactory/getInstance pbe-name)
        key-spec (javax.crypto.spec.PBEKeySpec. (.toCharArray secret) (.getBytes salt) 65536 key-length)
        key (javax.crypto.spec.SecretKeySpec. (.getEncoded (.generateSecret key-factory key-spec)) cipher-name)
        cipher (javax.crypto.Cipher/getInstance (str cipher-name "/CBC/PKCS5Padding"))
        _ (.init cipher javax.crypto.Cipher/ENCRYPT_MODE key)
        params (.getParameters cipher)
        iv (.getIV (.getParameterSpec params javax.crypto.spec.IvParameterSpec))
        ciphertext (.doFinal cipher (.getBytes payload "UTF-8"))]
    {:iv iv :ciphertext ciphertext}))

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

(defn encrypt [cipher payload]
  nil)

(defn create-frame [version cipher-suite hmac iv key-info payload]
  (.array (gloss.io/contiguous (gloss.io/encode opentoken {:otk "OTK" :version 1 :cipher-suite 1
                                                           :hmac hmac :iv iv :key-info nil
                                                           :payload payload}))))

(defn make-cookie-safe [s]
  "Makes a string cookie safe by changing = to *"
  (apply str (map #(if (= \= %) \* %) (String. (b64/encode (.getBytes s)) "UTF-8"))))

(defn revert-cookie-safety [s]
  "Reverts cookie safety by changing * to ="
  (apply str (map #(if (= \* %) \= %) (String. (b64/encode (.getBytes s)) "UTF-8"))))

(defn encode [payload secret & {:keys [cipher salt] :or {cipher :none salt nil}}]
  "Returns a string representing the encrypted OpenToken."
  (if-not (map? payload)
    (throw (java.lang.IllegalArgumentException. "Payload must be a map.")))
  (if-not (contains? cipher-suites cipher)
    (throw (java.lang.IllegalArgumentException. "Cipher must be one of :none, :aes-256, :aes-128, or :3des-168.")))
  (let [cleartext-payload (stringify-payload payload)
        compressed-cleartext (deflate cleartext-payload)
        encryptor (fn [payload] (encrypt-aes secret salt payload))
        {:keys [ciphertext iv]} (encryptor compressed-cleartext)
        hmac (create-hmac 1 1 iv nil cleartext-payload)
        bin (create-frame 1 1 hmac iv nil ciphertext)
        b64token (String. (b64/encode bin) "UTF-8")]
    (make-cookie-safe b64token)))

(defn decode [token secret & {:keys [cipher salt] :or {cipher :aes-256}}]
  "Decodes a OpenToken. Will throw an exception if the token is invalid."
  nil)
