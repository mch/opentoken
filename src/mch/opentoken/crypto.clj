(ns mch.opentoken.crypto)

(def cipher-suites {:none 0 :aes-256 1 :aes-128 2 :3des-168 3})
(def opentoken-default-salt (byte-array 8 (byte 0)))
(def opentoken-default-iterations 1000)

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

(defn pad-ciphertext [c]
  (let [pad-multiple 512
        c-length (count c)
        missing-bytes (mod (- pad-multiple (mod c-length pad-multiple)) pad-multiple)
        new-length (+ c-length missing-bytes)]
    (byte-array new-length c)))

(defn decrypt-des [ciphertext key iv]
  (let [cipher (javax.crypto.Cipher/getInstance "DESede/CBC/PKCS5Padding")
        _ (.init cipher javax.crypto.Cipher/DECRYPT_MODE key (javax.crypto.spec.IvParameterSpec. iv))
        cleartext (.doFinal cipher ciphertext)]
    cleartext))

(defn decrypt-aes [ciphertext key iv]
  (let [ciphertext-len (count ciphertext)
        padded-len (+ ciphertext-len (- 512 (mod ciphertext-len 512)))
        padded-ciphertext (byte-array padded-len ciphertext)
        cipher (javax.crypto.Cipher/getInstance "AES/CBC/PKCS5Padding")
        iv-spec (javax.crypto.spec.IvParameterSpec. iv)
        _ (.init cipher javax.crypto.Cipher/DECRYPT_MODE key iv-spec)]
    (.doFinal cipher padded-ciphertext 0 ciphertext-len)))

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
  (let [key (if-not (nil? key)
            (make-key-from-ba cipher key)
            (make-key cipher password salt))]
    (cond (= cipher :none) ciphertext
          (contains? #{:aes-256 :aes-128} cipher) (decrypt-aes ciphertext key iv)
          (= cipher :3des-168) (decrypt-des ciphertext key iv))))


