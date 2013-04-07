(ns mch.opentoken
  "Implements the OpenToken specification: http://tools.ietf.org/html/draft-smith-opentoken-02"
  (:use mch.opentoken.crypto)
  (:use mch.opentoken.util)
  (:require [gloss core io]))

;;; TODO
;;; - Error handling: catch various exceptions and rethrow as an OpenTokenException
;;; - Try multi-methods to dispatch encryption and decryption on cipher
;;; - Reduce structural duplication
;;; - Move everything except the public API defs to mch.opentoken.encryption and so on.
;;; - Use streams to reduce copying, or some other method more suitable to functional composition. 

(def opentoken-version 1)
(def opentoken-literal "OTK")
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

;; updating should be equivalent to creating a single byte-array and doing it all at once. 
(defn create-hmac [version suite iv key-info encrypted-payload-length cleartext-payload]
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
                      (gloss.io/encode payload-len-codec {:payload-len encrypted-payload-length}))))
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
  "Validates OTK literal and version. TODO validate IV length and cipher suite"
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
    (inflate (decrypt (:payload t) ;; TODO catch crypto exceptions and re-throw an OpenToken one?
                      :cipher cipher-suite
                      :password password
                      :key key
                      :iv (:iv t)))))

(defn decode [token password-or-key-decider & rest]
  "Decodes an OpenToken supplied as a string. Calls the key-decider
function with a map containing the token, from which the :cipher-suite
and :key-info items should be used to identify the key to use. The
key-decider function must return a map containing either a :password
or a :key. Returns a map of the key value pairs that were stored in the token."
  (let [dt (decode-token token) ;; catch gloss exceptions and rethrow OpenToken specific ones?
        skip-token-check (some #{:skip-token-check} rest)
        skip-hmac-check (some #{:skip-hmac-check} rest)]
    (if (and (nil? skip-token-check) (not (token-valid? dt)))
      {:status :invalid-token} ;; throw exception?
      (let [{:keys [password key] :or {password nil key nil}}
            (if (ifn? password-or-key-decider)
              (password-or-key-decider dt)
              {:password password-or-key-decider})
            cleartext (decrypt-token dt :password password :key key)]
        (if (and (nil? skip-hmac-check) (not (hmac-valid? dt cleartext)))
          {:status :invalid-hmac} ;; throw exception?
          (string-to-map (String. cleartext "UTF-8")))))))

;; TODO use the same key-decider function as decode? Nice symmetry that way.
;; TODO catch and rethrow exceptions?
(defn encode [payload & {:keys [cipher password key iv key-info] :or {cipher :aes-256 password nil key nil iv nil key-info nil}}]
  "Encodes a map as an encrypted OpenToken. One of :password or :key must be supplied."
  (if-not (map? payload)
    (throw (java.lang.IllegalArgumentException. "Payload must be a map.")))
  (if-not (contains? cipher-suites cipher)
    (throw (java.lang.IllegalArgumentException. "Cipher must be one of :none, :aes-256, :aes-128, or :3des-168.")))
  (let [cleartext-payload (map-to-string payload)
        compressed-cleartext (deflate (.getBytes cleartext-payload "utf-8"))
        encryptor (fn [payload] (encrypt payload :cipher cipher :password password :key key :iv iv))
        {:keys [ciphertext iv]} (encryptor compressed-cleartext)
        hmac (create-hmac opentoken-version (cipher cipher-suites) iv nil (count ciphertext) cleartext-payload)
        bin (create-frame opentoken-version (cipher cipher-suites) hmac iv key-info ciphertext)
        b64token (String. (b64-encode bin) "UTF-8")]
    (make-cookie-safe b64token)))
