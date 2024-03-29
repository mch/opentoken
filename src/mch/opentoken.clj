(ns mch.opentoken
  "Implements the OpenToken specification: http://tools.ietf.org/html/draft-smith-opentoken-02"
  (:use mch.opentoken.crypto)
  (:use mch.opentoken.util)
  (:use mch.opentoken.packing))

;;; TODO
;;; - Error handling: catch various exceptions and rethrow as an OpenTokenException
;;; - Try multi-methods to dispatch encryption and decryption on cipher
;;; - Reduce structural duplication
;;; - Move everything except the public API defs to mch.opentoken.encryption and so on.
;;; - Use streams to reduce copying, or some other method more suitable to functional composition. 
;;; - Profile and see if there is any performance optimization to be done.
;;; - Validate input maps for proper characters
;;; - Encrypted payload size handling. Make sure that encrypted payloads larger than 256 bytes works,
;;;   and that payloads larger than 65536 result in an error.

;; updating should be equivalent to creating a single byte-array and doing it all at once. 
(defn create-hmac [key-bytes version suite iv key-info encrypted-payload-length cleartext-payload]
  (let [digester (javax.crypto.Mac/getInstance "HmacSHA1") ;; SunJCE
        key-spec (javax.crypto.spec.SecretKeySpec. key-bytes "AES")] ;; or DES?
    (.init digester key-spec)
    (.update digester (byte version))
    (.update digester (byte suite))
    (if-not (nil? iv)
      (if (= (type iv) (type (byte-array 0)))
        (.update digester iv)))
    (if-not (nil? key-info)
      (if (= (type key-info) (type (byte-array 0)))
        (.update digester key-info)))
    ;; The spec says to include the payload length in the HMAC, but...
    ;; (.update digester
    ;;          (.array (gloss.io/contiguous
    ;;                   (gloss.io/encode payload-len-codec {:payload-len encrypted-payload-length}))))
    (.update digester (if (string? cleartext-payload) (.getBytes cleartext-payload "utf-8") cleartext-payload))
    (.doFinal digester)))

(defn token-valid? [token]
  "Validates OTK literal and version. TODO validate IV length and cipher suite"
  (and (= opentoken-version (:version token))
       (= opentoken-literal (:otk token))
       (>= 3 (:cipher-suite token))
       (<= 0 (:cipher-suite token))))

(defn hmac-valid? [key-bytes token cleartext]
  "Validates OpenToken HMAC."
  (let [hmac (create-hmac key-bytes
                          (:version token)
                          (:cipher-suite token)
                          (:iv token)
                          (:key-info token)
                          (count (:payload token))
                          cleartext)]
    (= (seq hmac) (seq (:hmac token)))))

(defn decode-token [token]
  "Decodes a OpenToken, returning a map of OpenToken components."
  (let [tbytes (-> token
                   (revert-cookie-safety)
                   (.getBytes "UTF-8")
                   (b64-decode)
                   (decode-frame))
        frame (apply hash-map (interleave opentoken-frame-keys tbytes))]
    (assoc frame
      :hmac (buffer-to-array (:hmac frame))
      :iv (buffer-to-array (:iv frame))
      :key-info (buffer-to-array (:key-info frame))
      :payload (buffer-to-array (:payload frame)))))

(defn decrypt-token [token & {:keys [password key]
                              :or {password nil key nil}}]
  "Decrypts and inflates the payload of the token, returning a byte array
containing the decrypted text."
  (let [t (if (string? token) (decode-token token) token)
        cipher-suite ({0 :none 1 :aes-256 2 :aes-128 3 :3des-168} (:cipher-suite t))]
    (try (inflate (decrypt (:payload t) ;; TODO catch crypto exceptions and re-throw an OpenToken one?
                           :cipher cipher-suite
                           :password password
                           :key key
                           :iv (:iv t)))
         (catch javax.crypto.BadPaddingException e (throw (java.lang.IllegalArgumentException. "Invalid password or key."))))))

(defn decode [token password-or-key-decider & rest]
  "Decodes an OpenToken supplied as a string. The password-or-key-decider
may either be a string, in which case it is assumed to be a password, or a
function that takes one argument. If it is a function, it that function is
called with a map containing the token, from which the :cipher-suite
and :key-info items should be used to identify the key to use. The
key-decider function must return either a string password or a byte-array
containing a key.

Keyword arguments:
- :skip-token-check skips the token version and header check (necessary for the
  broken spec data.
- :skip-hmac-check skips the hmac verification"
  (let [dt (decode-token token) ;; catch gloss exceptions and rethrow OpenToken specific ones?
        skip-token-check (some #{:skip-token-check} rest)
        skip-hmac-check (some #{:skip-hmac-check} rest)]
    (if (and (nil? skip-token-check) (not (token-valid? dt)))
      {:status :invalid-token} ;; throw exception?
      (let [password-or-key-decider (if (ifn? password-or-key-decider)
                                      (password-or-key-decider dt)
                                      password-or-key-decider)
            {:keys [password key] :or {password nil key nil}}
            (if (string? password-or-key-decider)
              {:password password-or-key-decider}
              (if (byte-array? password-or-key-decider)
                {:key password-or-key-decider}
                (throw (java.lang.IllegalArgumentException. "A string password or byte-array key is required."))))
            cipher-suite ({0 :none 1 :aes-256 2 :aes-128 3 :3des-168} (:cipher-suite dt))
            key-bytes (if (nil? key) (make-key cipher-suite password nil) key)
            cleartext (decrypt-token dt :key key-bytes)]
        (if (and (nil? skip-hmac-check) (not (hmac-valid? key-bytes dt cleartext)))
          {:status :invalid-hmac} ;; throw exception?
          (string-to-map (String. cleartext "UTF-8")))))))

;; TODO catch and rethrow exceptions?
(defn encode [payload password-or-key & {:keys [cipher iv key-info] :or {cipher :aes-256 iv nil key-info nil}}]
  "Encodes a map as an encrypted OpenToken. If the second argument is a string, it is treated as a password.
If it is a byte-array, it is treated as an encryption key.

Keyword arguments:
 - :cipher, value is one of :none, :aes-128, :aes-256, or :3des-168.
 - :iv, an intermediate value to use in the cipher.
 - :key-info, a byte-array that will be carried in plain text in the token."
  (if-not (map? payload)
    (throw (java.lang.IllegalArgumentException. "Payload must be a map.")))
  (if-not (contains? cipher-suites cipher)
    (throw (java.lang.IllegalArgumentException. "Cipher must be one of :none, :aes-256, :aes-128, or :3des-168.")))
  (if-not (or (string? password-or-key) (byte-array? password-or-key))
    (throw (java.lang.IllegalArgumentException. "password-or-key must either be a byte-array or a string.")))
  (if-not (or (nil? iv) (byte-array? iv))
    (throw (java.lang.IllegalArgumentException. "iv must either be a byte-array or nil.")))
  (if-not (or (nil? key-info) (byte-array? key-info))
    (throw (java.lang.IllegalArgumentException. "key-info must either be a byte-array or nil.")))
  (let [cleartext-payload (map-to-string payload)
        compressed-cleartext (deflate (.getBytes cleartext-payload "utf-8"))
        password (if (string? password-or-key) password-or-key nil)
        key-bytes (if (byte-array? password-or-key) password-or-key (make-key cipher password nil))
        encryptor (fn [payload] (encrypt payload :cipher cipher :key key-bytes :iv iv))
        {:keys [ciphertext iv]} (encryptor compressed-cleartext)
        hmac (create-hmac key-bytes opentoken-version (cipher cipher-suites) iv nil (count ciphertext) cleartext-payload)
        bin (create-frame opentoken-version (cipher cipher-suites) hmac iv key-info ciphertext)
        b64token (String. (b64-encode bin) "UTF-8")]
    (make-cookie-safe b64token)))
