(ns mch.opentoken-test
  (:use clojure.test
        mch.opentoken)
  (:require [clojure.data.codec.base64 :as b64]))

;; Data from the spec at http://tools.ietf.org/html/draft-smith-opentoken-02
;; This data appears to be broken. The header is PTK instead of OTK, and the
;; encrypted data is not correctly padded. The key is base64 encoded. 
(def spec-data [{:cipher :aes-128
                 :key "a66C9MvM8eY4qJKyCXKW+w=="
                 :token "UFRLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"}
                {:cipher :aes-256
                 :key "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc="
                 :token "UFRLAQEujlLGEvmVKDKyvL1vaZ27qMYhTxDSAZwtaufqUff7GQXTjvWBAAAgJJGPta7VOITap4uDZ_OkW_Kt4yYZ4BBQzw_NR2CNE-g*"}
                {:cipher :3des-168
                 :key "a66C9MvM8eY4qJKyCXKW+19PWDeuc3th"
                 :token "UFRLAQNoCsuAwybXOSBpIc9ZvxQVx_3fhghqSjy-pNJpfgAAGGlGgJ79NhX43lLRXAb9Mp5unR7XFWopzw**"}])

(def test-payload-map {"foo" "bar" "bar" "baz"})
(def expected-cleartext "bar=baz\r\nfoo=bar\r\n")

(deftest public-api-test
  (testing "Encoding and decoding the tokens with a password through the public API"
    (let [password "password"
          token (encode test-payload-map :password password)
          key-decider (fn [key-info] {:password password})
          output (decode token key-decider)]
      (is (= output test-payload-map))))
  (testing "Encoding and decoding the tokens with a password and salt through the public API"
    (let [password "password"
          salt "saltydog"
          token (encode test-payload-map :password password :salt salt)
          key-decider (fn [key-info] {:password password :salt salt})
          output (decode token key-decider)]
      (is (= output test-payload-map))))
  (testing "Encoding and decoding the tokens with a key through the public API"
    (let [key (b64/decode (.getBytes "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc=" "UTF-8"))
          token (encode test-payload-map :key key)
          key-decider (fn [key-info] {:key key})
          output (decode token key-decider)]
      (is (= output test-payload-map)))))

(deftest aes-128
  (testing "AES-128 decoding"
    (let [cipher :aes-128
          key (b64/decode (.getBytes "a66C9MvM8eY4qJKyCXKW+w==" "UTF-8"))
          token (encode test-payload-map :key key :cipher cipher)
          tamper-token (apply str "A" (rest token))
          output (decrypt-token token  :key key :cipher cipher)]
      (println output)
      (is (= expected-cleartext (String. output "UTF-8"))))))

(deftest map-to-string-test
  (testing "that maps are converted to OpenToken formatted strings"
    (let [m {"foo" "bar" "baz" "quux"}]
      (is (= "baz=quux\r\nfoo=bar\r\n" (map-to-string m))))))

(deftest string-to-map-test
  (testing "that OpenToken strings can be converted to maps."
    (let [s1 "bar=baz\r\nfoo=bar\r\n"
          s2 "bar=baz\r\nfoo=bar\r\nbar=quux\r\n"]
      (is (= {"bar" ["baz"] "foo" ["bar"]} (string-to-map s1)))
      (is (= {"bar" ["baz" "quux"] "foo" ["bar"]} (string-to-map s2))))))

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
          
(deftest encrypt-decrypt
  (testing "AES 256 encryption and decryption"
    (let [cipher :aes-256
          password "secret"
          salt "12345"
          salt-b (.getBytes "12345" "UTF-8")
          key (byte-array 32 (byte 34)) ; 256 bits
          cleartext "Hi everyone."
          cleartext-b (.getBytes cleartext "UTF-8")
          ciphertext1 (encrypt cleartext :cipher cipher :password password :salt salt)
          ciphertext2 (encrypt cleartext :cipher cipher :key key)]
      (is (= (seq (:ciphertext ciphertext1))
             (seq (:ciphertext (encrypt cleartext  :cipher cipher :password password :salt salt-b
                                        :iv (:iv ciphertext1))))))
      (is (= (seq (:ciphertext ciphertext1))
             (seq (:ciphertext (encrypt cleartext-b  :cipher cipher :password password :salt salt
                                        :iv (:iv ciphertext1))))))
      (is (= (seq (:ciphertext ciphertext2))
             (seq (:ciphertext (encrypt cleartext-b :cipher cipher :key key
                                        :iv (:iv ciphertext2))))))
      (is (= (seq cleartext-b) (seq (decrypt (:ciphertext ciphertext1) :iv (:iv ciphertext1) :password password :salt salt)))))))

(deftest validate-token-test
  (testing "token has valid header, version and cipher."
    (let [cleartext "foo=bar\r\nbar=baz\r\n"
          key (b64/decode (.getBytes "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc=" "UTF-8"))
          token (decode-token (encode {"foo" "bar" "bar" "baz"} :key key))
          broken-version (assoc token :version 0)
          broken-header (assoc token :otk "PTK")
          broken-cipher (assoc token :cipher-suite 4)]
      (println token)
      (is (token-valid? token))
      (is (not (token-valid? broken-cipher)))
      (is (not (token-valid? broken-version)))
      (is (not (token-valid? broken-header))))))

(deftest validate-hmac-test
  (testing "token has correct hmac"
    (let [cleartext "bar=baz\r\nfoo=bar\r\n"
          key (b64/decode (.getBytes "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc=" "UTF-8"))
          token (decode-token (encode {"foo" "bar" "bar" "baz"} :key key))]
      (is (hmac-valid? token cleartext))
      (is (not (hmac-valid? token (str cleartext "A")))))))
