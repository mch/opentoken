(ns mch.opentoken-test
  (:use clojure.test
        mch.opentoken)
  (:require [clojure.data.codec.base64 :as b64]))

(def test {:otk "OTK"
           :version 1
           :cipher-suite 0
           :iv nil
           :key-info nil
           :payload "foo=bar\r\nbar=baz"})

(def expected {"foo" "bar" "bar" "baz"})

(deftest aes-128
  (testing "AES-128 decoding"
    (let [cipher :aes-128
          key (b64/decode (.getBytes "a66C9MvM8eY4qJKyCXKW+w==" "UTF-8"))
          token "UFRLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"]
      (is (= token (encode expected :key key :cipher cipher))))))

(deftest aes-256
  (testing "AES-256 encoding and decoding"
    (let [cipher :aes-256
          key (b64/decode (.getBytes "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc=" "UTF-8"))
          token "UFRLAQEujlLGEvmVKDKyvL1vaZ27qMYhTxDSAZwtaufqUff7GQXTjvWBAAAgJJGPta7VOITap4uDZ_OkW_Kt4yYZ4BBQzw_NR2CNE-g*"]
      (is (= token (encode expected :key key :cipher cipher))))))
      ;(is (= (decode token key :cipher cipher) expected)))))

(deftest threedes-168
  (testing "3DES-168 decoding"
    (let [cipher :3des-168
          key (b64/decode (.getBytes "a66C9MvM8eY4qJKyCXKW+19PWDeuc3th" "UTF-8"))
          token "UFRLAQNoCsuAwybXOSBpIc9ZvxQVx_3fhghqSjy-pNJpfgAAGGlGgJ79NhX43lLRXAb9Mp5unR7XFWopzw**"]
      (is (= token (encode expected :key key :cipher cipher))))))

;; (deftest multi-value
;;   (testing "that keys with multiple values return a list of values")
;;   (is (= 0 1)))

(deftest stringify-map-test
  (testing "that maps are converted to OpenToken formatted strings"
    (let [m {"foo" "bar" "baz" "quux"}]
      (is (= "baz=quux\r\nfoo=bar\r\n" (stringify-payload m))))))

(deftest deflate-test
  (testing "DEFLATE"
    (let [input "Visiting is pretty, visiting is cool, foo fighters are awesome"
          input-b (.getBytes input "UTF-8")
          deflated (deflate input-b)
          inflated (inflate deflated)
          output (String. inflated "UTF-8")]
      (is (= input output))
      (is (= (seq input-b) (seq inflated)))
      (is (not (= input-b deflated))))))
      
(deftest hmac-test
  (testing "Changing hmac inputs changes hmac"
    (let [version1 1
          version2 2
          suite1 1
          suite2 2
          iv1 (byte-array 20 (byte 2))
          iv2 (byte-array 20 (byte 3))
          iv3 nil
          key-info1 (byte-array 3 (byte 2))
          key-info2 (byte-array 3 (byte 4))
          key-info3 nil
          text1 "yay"
          text2 "boo"]
      (is (not= (create-hmac version1 suite1 iv1 key-info1 text1)
                (create-hmac version2 suite1 iv1 key-info1 text1)))
      (is (not= (create-hmac version1 suite1 iv1 key-info1 text1)
                (create-hmac version1 suite2 iv1 key-info1 text1)))
      (is (not= (create-hmac version1 suite1 iv1 key-info1 text1)
                (create-hmac version1 suite1 iv2 key-info1 text1)))
      (is (not= (create-hmac version1 suite1 iv1 key-info1 text1)
                (create-hmac version1 suite1 iv1 key-info2 text1)))
      (is (not= (create-hmac version1 suite1 iv1 key-info1 text1)
                (create-hmac version1 suite1 iv1 key-info1 text2))))))

(deftest create-frame-test
  (testing "binary frame creation"
    ))

(deftest cookie-safe-test
  (testing "replacing b64 padding to make it cookie-safe"
    (let [input "234ads==="
          safe (make-cookie-safe input)
          output (revert-cookie-safety safe)]
      (is (= "234ads***" safe))
      (is (= output input)))))
          
(deftest encrypt-with-password
  (testing "Password and salt based AES 256 encryption"
    (let [cipher :aes-256
          password "secret"
          salt "12345"
          salt-b (.getBytes "12345" "UTF-8")
          key (byte-array 32 (byte 34)) ; 256 bits
          cleartext "Hi everyone."
          cleartext-b (.getBytes cleartext "UTF-8")
          ciphertext1 (encrypt cleartext :cipher cipher :password password :salt salt)
          ciphertext2 (encrypt cleartext :cipher cipher :key key)]
      (println (seq (:ciphertext ciphertext1)))
      (is (= (seq (:ciphertext ciphertext1))
             (seq (:ciphertext (encrypt cleartext  :cipher cipher :password password :salt salt-b
                                        :iv (:iv ciphertext1))))))
      (is (= (seq (:ciphertext ciphertext1))
             (seq (:ciphertext (encrypt cleartext-b  :cipher cipher :password password :salt salt
                                        :iv (:iv ciphertext1))))))
      (is (= (seq (:ciphertext ciphertext2))
             (seq (:ciphertext (encrypt cleartext-b :cipher cipher :key key
                                        :iv (:iv ciphertext2)))))))))

      
          
(deftest validate-token-test
  (testing "token validation"
    (is (= 0 1))))
