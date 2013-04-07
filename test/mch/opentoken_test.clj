(ns mch.opentoken-test
  (:use clojure.test
        mch.opentoken
        mch.opentoken.util)
  (:use midje.sweet))

;; TODO
;; - tests for large payloads, above 256 bytes, above 65536 bytes
;; - code clean up

;; Data from the spec at http://tools.ietf.org/html/draft-smith-opentoken-02
;; This data appears to be broken. The header is PTK instead of OTK.
(def spec-data {:aes-128 {:cipher :aes-128
                          :key "a66C9MvM8eY4qJKyCXKW+w=="
                          :token "UFRLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"}
                :aes-256 {:cipher :aes-256
                          :key "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc="
                          :token "UFRLAQEujlLGEvmVKDKyvL1vaZ27qMYhTxDSAZwtaufqUff7GQXTjvWBAAAgJJGPta7VOITap4uDZ_OkW_Kt4yYZ4BBQzw_NR2CNE-g*"}
                :3des-168 {:cipher :3des-168
                           :key "a66C9MvM8eY4qJKyCXKW+19PWDeuc3th"
                           :token "UFRLAQNoCsuAwybXOSBpIc9ZvxQVx_3fhghqSjy-pNJpfgAAGGlGgJ79NhX43lLRXAb9Mp5unR7XFWopzw**"}})

(def test-payload-map {"foo" ["bar"] "bar" ["baz"]})
(def expected-cleartext "bar=baz\r\nfoo=bar\r\n")

;; TODO: should these exceptions be opentoken specific?
(facts "about encode arguments"
  (fact "first argument must be a map"
    (encode {"foo" "bar"} "password") => string?)
  (fact "first argument must not be a string"
    (encode "test" "password") => (throws java.lang.IllegalArgumentException))
  (fact "second argument can be a byte-array"
    (encode {"foo" "test"} (byte-array 32 (byte 0))) => string?)
  (fact "second argument cannot be a map"
    (encode {"test" "asfd"} {}) => (throws java.lang.IllegalArgumentException))
  (fact "Cipher must be one of the enumerated cipher suites."
    (encode test-payload-map "password" :cipher :not-a-cipher-suite) => (throws java.lang.IllegalArgumentException))
  (fact "iv must be a byte array"
    (encode test-payload-map "password" :iv "string") => (throws java.lang.IllegalArgumentException))
  (fact "aes 256 iv must be 16 bytes long"
    (encode test-payload-map "password" :iv (byte-array 15 (byte 0))) => (throws java.security.InvalidAlgorithmParameterException))
  (fact "aes 128 iv must be 16 bytes long"
    (encode test-payload-map "password" :cipher-suite :aes-128 :iv (byte-array 15 (byte 0))) => (throws java.security.InvalidAlgorithmParameterException))
  (fact "3DES 168 iv must be 16 bytes long"
    (encode test-payload-map "password" :cipher-suite :3des-168 :iv (byte-array 15 (byte 0))) => (throws java.security.InvalidAlgorithmParameterException))
  (fact "key-info can be nil"
    (encode test-payload-map "password" :key-info nil) => string?)
  (fact "key-info can be a byte-array"
    (encode test-payload-map "password" :key-info (byte-array 12 (byte 0))) => string?)
  (fact "key-info can only be nil or a byte-array, not a string."
    (encode test-payload-map "password" :key-info "the password is password") => (throws java.lang.IllegalArgumentException)))

(facts "about decode arguments"
  (let [password "secret"
        token (encode test-payload-map password)]
    (fact "wrong password throws exception"
      (decode token "soopersecret") => (throws java.lang.IllegalArgumentException))
    (fact "decider function must return a string password"
      (decode token (fn [token] ["can't be a list"])) => (throws java.lang.IllegalArgumentException))
    (fact "decider function must return a byte-array key"
      (decode token (fn [token] "can't be a string")) => (throws java.lang.IllegalArgumentException))))
        
(facts "about opentoken decoding"
  (fact "aes-128 tokens can be decoded"
    (let [{:keys [cipher key token]} (:aes-128 spec-data)]
      (decode token (b64-decode key) :skip-token-check) => test-payload-map))
  (fact "aes-256 tokens can be decoded"
    (let [{:keys [cipher key token]} (:aes-256 spec-data)]
      (decode token (b64-decode key) :skip-token-check) => test-payload-map))
  (fact "DES tokens can be decoded"
    (let [{:keys [cipher key token]} (:3des-168 spec-data)]
      (decode token (b64-decode key) :skip-token-check) => test-payload-map)))

(facts "about the public api"
  (fact "encoding and decoding are symmetric with a decoder key-decider"
    (let [password "Secr1t"
          token (encode test-payload-map password)]
      (decode token (fn [key-info] password)) => test-payload-map))
  (fact "encoding and decoding are symmetric with a decoder password as a string param"
    (let [password "Secr1t"
          token (encode test-payload-map password)]
      (decode token password) => test-payload-map)))
          
(deftest public-api-test
  (testing "Encoding and decoding the tokens with a password through the public API"
    (let [password "password"
          token1 (encode test-payload-map password)
          key-decider (fn [token-map] password)
          output (decode token1 key-decider)]
      (is (= output test-payload-map))))
  
  (testing "Encoding and decoding the tokens with a key through the public API"
    (let [key (b64-decode (.getBytes (:key (:aes-256 spec-data)) "UTF-8"))
          token1 (encode test-payload-map key)
          key-decider (fn [key-info] key)
          output (decode token1 key-decider)]
      (is (= output test-payload-map))))

  (testing "Using the key-info to decide what key to use"
    (let [password "password"
          key-info (.getBytes "use the password" "UTF-8") ; must be binary
          token1 (encode test-payload-map password :key-info key-info)
          key-info-output (atom nil)
          key-decider (fn [token] (reset! key-info-output (:key-info token)) password)
          _ (decode token1 key-decider)]
      (is (and (not (nil? @key-info-output))
               (= (seq key-info) (seq @key-info-output)))))))

(deftest aes-128
  (testing "AES-128 encode - decode"
    (let [cipher :aes-128
          key (b64-decode (.getBytes "a66C9MvM8eY4qJKyCXKW+w==" "UTF-8"))
          token (encode test-payload-map key :cipher cipher)
          output (decrypt-token token  :key key :cipher cipher)]
      (is (= expected-cleartext (String. output "UTF-8")))))

  ;; (testing "AES-128 decode fails with broken token"
  ;;   ... broken-token (apply str "A" (rest token))

  (testing "AES-128 same IV, same token, different IV, different token"
    (let [cipher :aes-128
          key (b64-decode (.getBytes "a66C9MvM8eY4qJKyCXKW+w==" "UTF-8"))
          token1 (encode test-payload-map key :cipher cipher)
          token2 (encode test-payload-map key :cipher cipher)
          iv (:iv (decode-token token1))
          token3 (encode test-payload-map key :cipher cipher :iv iv)
          output (decrypt-token token1  :key key :cipher cipher)]
      (is (= token1 token3))
      (is (not= token1 token2))))

  (testing "AES-128 different key, different token"
    (let [cipher :aes-128
          key1 (b64-decode (.getBytes "a66C9MvM8eY4qJKyCXKW+w==" "UTF-8"))
          key2 (byte-array key1)
          _ (aset-byte key2 0 106)
          token1 (encode test-payload-map key1 :cipher cipher)
          iv (:iv (decode-token token1))
          token2 (encode test-payload-map key2 :cipher cipher :iv iv)]
      (is (not= token1 token2))))

  (testing "AES-128 different password, different token"
      (let [cipher :aes-128
            password1 "1234"
            password2 "5678"
            token1 (encode test-payload-map password1 :cipher cipher)
            iv (:iv (decode-token token1))
            token2 (encode test-payload-map password2 :cipher cipher :iv iv)]
        (is (not= token1 token2)))))

(deftest aes-256
  (testing "AES-256 decoding"
    (let [cipher :aes-256
          key (b64-decode (.getBytes (:key (:aes-256 spec-data)) "UTF-8"))
          token (encode test-payload-map key :cipher cipher)
          tamper-token (apply str "A" (rest token))
          output (decrypt-token token  :key key :cipher cipher)]
      (is (= expected-cleartext (String. output "UTF-8"))))))

(deftest des-168
  (testing "DES-168 decoding"
    (let [cipher :3des-168
          key (b64-decode (.getBytes (:key (:3des-168 spec-data)) "UTF-8"))
          token (encode test-payload-map key :cipher cipher)
          tamper-token (apply str "A" (rest token))
          output (decrypt-token token :key key :cipher cipher)]
      (is (= expected-cleartext (String. output "UTF-8"))))))

(deftest hmac-test
  (testing "Changing hmac inputs changes hmac"
    (let [key-bytes (byte-array 16 (byte 0))
          version1 1
          version2 2
          suite1 1
          suite2 2
          iv1 (byte-array 20 (byte 2))
          iv2 (byte-array 20 (byte 3))
          iv3 nil
          key-info1 (byte-array 3 (byte 2))
          key-info2 (byte-array 3 (byte 4))
          key-info3 nil
          enc-payload-len1 255
          enc-payload-len2 257
          text1 "yay"
          text2 "boo"]
      (is (not= (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len1 text1)
                (create-hmac key-bytes version2 suite1 iv1 key-info1 enc-payload-len1 text1)))
      (is (not= (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len1 text1)
                (create-hmac key-bytes version1 suite2 iv1 key-info1 enc-payload-len1 text1)))
      (is (not= (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len1 text1)
                (create-hmac key-bytes version1 suite1 iv2 key-info1 enc-payload-len1 text1)))
      (is (not= (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len1 text1)
                (create-hmac key-bytes version1 suite1 iv1 key-info2 enc-payload-len1 text1)))
      (is (not= (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len1 text1)
                (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len1 text2)))
      (is (not= (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len1 text1)
                (create-hmac key-bytes version1 suite1 iv1 key-info1 enc-payload-len2 text1)))))) 

(deftest validate-token-test
  (testing "token has valid header, version and cipher."
    (let [cleartext "foo=bar\r\nbar=baz\r\n"
          key (b64-decode (.getBytes "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc=" "UTF-8"))
          token (decode-token (encode {"foo" "bar" "bar" "baz"} key))
          broken-version (assoc token :version 0)
          broken-header (assoc token :otk "PTK")
          broken-cipher (assoc token :cipher-suite 4)]
      (is (token-valid? token))
      (is (not (token-valid? broken-cipher)))
      (is (not (token-valid? broken-version)))
      (is (not (token-valid? broken-header))))))

(deftest validate-hmac-test
  (testing "token has correct hmac"
    (let [cleartext "bar=baz\r\nfoo=bar\r\n"
          key (b64-decode (.getBytes "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc=" "UTF-8"))
          token (decode-token (encode {"foo" "bar" "bar" "baz"} key))]
      (is (hmac-valid? key token cleartext))
      (is (not (hmac-valid? key token (str cleartext "A")))))))


