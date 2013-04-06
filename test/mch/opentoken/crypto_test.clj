(ns mch.opentoken.crypto_test
  (:require [mch.opentoken.crypto :as crypto])
  (:require [mch.opentoken.util :as util])
  (:use midje.sweet)
  (:use clojure.java.io))

(def password "Wharrrrghhhbll!")
(def expected-aes128-key (util/make-byte-array [120 80 -61 -83 -72 -31 -12 118 -29 85 105 68 76 -29 50 -78]))
(def expected-aes256-key (util/make-byte-array [120 80 -61 -83 -72 -31 -12 118 -29 85 105 68 76 -29 50 -78
                                                -43 -41 -13 36 71 48 -20 -127 44 40 -94 -13 -15 99 -115 -4]))

(facts "about making AES and DES keys"
       (fact "can make 128 bit AES key"
             (seq (crypto/make-aes-key 128 password nil)) => (seq expected-aes128-key))
       (fact "can make 256 bit AES key"
             (seq (crypto/make-aes-key 256 password nil)) => (seq expected-aes256-key))
       ;; No DES provider in my JDK...
;;       (fact "can make DES key"
       ;;             (seq (.getEncoded (crypto/make-3des-key 168 password nil))) => (seq expected-aes256-key))
       )

(facts "About AES 256 encryption and decryption"
      (let [cipher :aes-256
            password "secret"
            key (byte-array 32 (byte 34)) ; 256 bits
            cleartext "Hi everyone."
            cleartext-b (.getBytes cleartext "UTF-8")
            ciphertext1 (crypto/encrypt cleartext :cipher cipher :password password)
            ciphertext2 (crypto/encrypt cleartext :cipher cipher :key key)]
        (fact (seq (:ciphertext (crypto/encrypt cleartext  :cipher cipher :password password
                                                :iv (:iv ciphertext1)))) =>  (seq (:ciphertext ciphertext1)))
        (fact (seq (:ciphertext (crypto/encrypt cleartext-b  :cipher cipher :password password
                                                :iv (:iv ciphertext1)))) => (seq (:ciphertext ciphertext1)))
        (fact (seq (:ciphertext (crypto/encrypt cleartext-b :cipher cipher :key key
                                                :iv (:iv ciphertext2)))) => (seq (:ciphertext ciphertext2)))
        (fact (seq (crypto/decrypt (:ciphertext ciphertext1) :iv (:iv ciphertext1) :password password)) => (seq cleartext-b))))

(def key-bytes (util/make-byte-array [-56 -94 -56 65 -9 -35 -84 120 -21 -102 81 -98 36 -23 -35 33]))
(def iv-bytes (util/make-byte-array [-75 -35 -36 -114 -63 9 -39 118 -66 124 57 -99 -111 18 -13 97]))

(def expected-decrypted-bytes (util/make-byte-array [120, -100, 93, -50, 49, 107, -61, 64, 12, -122, -31, -35, -1, -27, -54, 89, 119, 33, -74, -64, 67, -23, -38, 64, 32, -98, -70, 20, -27, 44, -109, 20, 87, 10, 58, -103, -28, -25, -41, -108, 66, 33, -45, 7, 47, -33, -16, -120, 122, 56, -13, -84, -58, 3, -60, 54, -123, -104, 67, -124, -79, -19, 49, 119, 8, -3, 71, 67, -85, 95, -28, 77, -59, -7, -31, -61, 106, -126, 74, -11, 90, 81, -24, -101, 43, 122, -63, -45, -21, -31, 29, -31, 37, 34, 21, 44, 11, -43, -70, -27, -29, 54, 119, -75, -23, 104, -22, 92, -100, -89, -47, 72, -22, 77, -51, -101, -70, -98, -65, -74, 52, 124, 66, -54, 57, -13, 126, 106, -29, -108, 41, 65, -101, -26, -68, -21, 24, -70, 25, -88, -121, -46, -25, 70, 54, -104, 74, 80, 11, 52, 59, -37, -109, 110, -105, 126, 117, -58, -62, -9, -80, -118, 95, -105, -1, 67, 26, -29, -2, -113, -1, 3, -125, -82, 69, 44]))

(def payload-bytes (util/make-byte-array [-116, 35, -44, 20, 30, -42, 64, -46, -124, -82, -58, -111, -5, -62, 21, -8, -65, -92, 63, 113, 30, 36, 72, 21, -34, -124, -77, 52, 20, 94, -13, -20, -45, -3, -56, -10, -1, 52, -33, -36, 32, 96, -60, -3, 2, 56, 34, -8, 126, 109, -47, 1, -15, 67, 4, -40, -40, -111, 33, -57, 98, -94, 29, 37, 115, 37, 71, 37, 87, 48, 65, 46, 69, -53, -27, 24, 23, -48, -40, 113, 26, -27, -25, -96, -81, -90, 110, 7, 85, 67, 108, 80, -29, 76, 38, -1, 39, -22, -94, -87, -9, -99, -52, -110, 34, 31, 64, 49, 100, -94, -90, -81, -128, 39, 95, -96, 119, -18, 102, -127, 96, 98, 24, 88, 47, -6, -76, 35, -14, -61, -25, 68, 90, -12, 121, 106, 82, 90, -54, -112, -74, 79, 60, -113, -53, 24, -33, -24, -93, -79, 123, 58, 44, 114, 62, -106, 21, -105, 99, -24, 88, -42, -56, -71, 21, -120, -32, -108, 25, 78, -66, 32, -123, -86, 31, 4, 6, -41, 26, -108, -15, 95, 76, 21, -54, 34, 124, 46, -106, 94, 91, 64]))

(defn decrypt-aes [ciphertext key-spec iv-spec]
  (let [c-length (count ciphertext)
        padded-ciphertext (crypto/pad-ciphertext ciphertext)
        cipher (javax.crypto.Cipher/getInstance "AES/CBC/PKCS5Padding")]
    (.init cipher 2 key-spec iv-spec)
    (.doFinal cipher padded-ciphertext 0 c-length)))


(defn decrypt-aes-2 [ciphertext key-bytes iv-bytes]
  (let [key-spec (javax.crypto.spec.SecretKeySpec. key-bytes "AES")
        iv-spec (javax.crypto.spec.IvParameterSpec. iv-bytes)]
    (decrypt-aes ciphertext key-spec iv-spec)))


(facts "about padding ciphertext for decryption"
       (fact "Pads up to 512"
             (count (crypto/pad-ciphertext (byte-array 2))) => 512)
       (fact "Stays at 512"
             (count (crypto/pad-ciphertext (byte-array 512))) => 512)
       (fact "Pads up to 1024"
             (count (crypto/pad-ciphertext (byte-array 513))) => 1024))


(facts "about AES 128 decryption"
       (fact "pf data decrypts properly with pre-created specs"
             (seq (crypto/decrypt-aes payload-bytes key-bytes iv-bytes)) => (seq expected-decrypted-bytes)))




