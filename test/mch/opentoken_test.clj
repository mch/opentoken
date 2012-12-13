(ns mch.opentoken_test
  (:use clojure.test
        opentoken.core))

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
          iv "a66C9MvM8eY4qJKyCXKW+w=="
          token "UFRLAQK9THj0okLTUB663QrJFg5qA58IDhAb93ondvcx7sY6s44eszNqAAAga5W8Dc4XZwtsZ4qV3_lDI-Zn2_yadHHIhkGqNV5J9kw*"]
      (is (= (decode token :cipher cipher :iv iv) expected)))))

(deftest aes-256
  (testing "AES-256 decoding"
    (let [cipher :aes-256
          iv "a66C9MvM8eY4qJKyCXKW+19PWDeuc3thDyuiumak+Dc="
          token "UFRLAQEujlLGEvmVKDKyvL1vaZ27qMYhTxDSAZwtaufqUff7GQXTjvWBAAAgJJGPta7VOITap4uDZ_OkW_Kt4yYZ4BBQzw_NR2CNE-g*"]
      (is (= (decode token :cipher cipher :iv iv) expected)))))

(deftest 3des-168
  (testing "3DES-168 decoding"
    (let [cipher :3des-168
          iv "a66C9MvM8eY4qJKyCXKW+19PWDeuc3th"
          token "UFRLAQNoCsuAwybXOSBpIc9ZvxQVx_3fhghqSjy-pNJpfgAAGGlGgJ79NhX43lLRXAb9Mp5unR7XFWopzw**"]
      (is (= (decode token :cipher cipher :iv iv) expected)))))

(deftest multi-value
  (testing "that keys with multiple values return a list of values")
  (is (= 0 1)))
