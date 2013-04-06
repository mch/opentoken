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
;;       (fact "can make DES key"
       ;;             (seq (.getEncoded (crypto/make-3des-key 168 password nil))) => (seq expected-aes256-key))
       )


