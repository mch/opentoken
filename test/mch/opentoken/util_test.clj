(ns mch.opentoken.util_test
  (:use clojure.test)
  (:use mch.opentoken.util)
  (:use midje.sweet)
  (:use clojure.java.io))

(deftest map-to-string-test
  (testing "that maps with string values are converted to OpenToken formatted strings"
    (let [m {"foo" "bar" "baz" "quux"}]
      (is (= "baz=quux\r\nfoo=bar\r\n" (map-to-string m)))))
  (testing "that maps with vector values are converted to OpenToken formatted strings"
    (let [m {"foo" ["bar"] "baz" ["quux"]}]
      (is (= "baz=quux\r\nfoo=bar\r\n" (map-to-string m)))))
  (testing "that maps with vector values are converted to OpenToken formatted strings"
    (let [m {"foo" ["bar" "bakery"] "baz" ["quux"]}]
      (is (= "baz=quux\r\nfoo=bakery\r\nfoo=bar\r\n" (map-to-string m))))))

(deftest string-to-map-test
  (testing "that OpenToken strings can be converted to maps."
    (let [s1 "bar=baz\r\nfoo=bar\r\n"
          s2 "bar=baz\r\nfoo=bar\r\nbar=quux\r\n"]
      (is (= {"bar" ["baz"] "foo" ["bar"]} (string-to-map s1)))
      (is (= {"bar" ["baz" "quux"] "foo" ["bar"]} (string-to-map s2))))))

(facts "string-to-map handles \n separate items"
  (fact (string-to-map "foo=bar\nbifur=bofur") => {"foo" ["bar"] "bifur" ["bofur"]}))

(deftest cookie-safe-test
  (testing "replacing b64 padding to make it cookie-safe"
    (let [input "234ads==="
          safe (make-cookie-safe input)
          output (revert-cookie-safety safe)]
      (is (= "234ads***" safe))
      (is (= output input)))))
          
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
      
