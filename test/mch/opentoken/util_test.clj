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
