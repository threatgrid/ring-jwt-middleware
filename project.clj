(defproject threatgrid/ring-jwt-middleware "1.0.3-SNAPSHOT"
  :description "A simple middleware to deal with JWT Authentication"
  :pedantic? :abort
  :license {:name "Eclipse Public License - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo}
  :url "http://github.com/threatgrid/ring-jwt-middleware"
  :deploy-repositories [["releases" {:url "https://clojars.org/repo" :creds :gpg}]
                        ["snapshots" {:url "https://clojars.org/repo" :creds :gpg}]]
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [threatgrid/clj-jwt "0.3.1"]
                 [threatgrid/clj-momo "0.3.5"]
                 [org.clojure/tools.logging "1.0.0"]
                 [metosin/ring-http-response "0.9.1"]]
  :profiles {:dev {:pedantic? :warn}})
