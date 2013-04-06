(defproject opentoken "0.1.0-SNAPSHOT"
  :description "An implementation of OpenToken (http://tools.ietf.org/html/draft-smith-opentoken-02)"
  :url "https://github.com/mch/opentoken"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.4.0"]
                 [gloss "0.2.2-beta3"]
                 [org.clojure/data.codec "0.1.0"]]
  :profiles {:dev {:dependencies [[midje "1.5.1"]]}})
