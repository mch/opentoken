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
             (seq (.getEncoded (crypto/make-aes-key 128 password nil))) => (seq expected-aes128-key))
       (fact "can make 256 bit AES key"
             (seq (.getEncoded (crypto/make-aes-key 256 password nil))) => (seq expected-aes256-key))
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



