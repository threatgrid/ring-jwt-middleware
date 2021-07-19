(defproject threatgrid/ring-jwt-middleware "1.0.2"
  :description "A simple middleware to deal with JWT Authentication"
  :pedantic? :abort
  :license {:name "Eclipse Public License - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo}
  :url "http://github.com/threatgrid/ring-jwt-middleware"
  :deploy-repositories [["releases" {:url "https://clojars.org/repo" :creds :gpg}]
                        ["snapshots" {:url "https://clojars.org/repo" :creds :gpg}]]
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [clj-time "0.15.2"] ;threatgrid/clj-momo > yogsototh/clj-jwt, metosin/compojure-api, metosin/ring-http-response
                 [org.mozilla/rhino "1.7.7.1"] ; metosin/compojure-api > threatgrid/clj-momo
                 [com.google.guava/guava "16.0.1"] ; metosin/compojure-api > threatgrid/clj-momo
                 [threatgrid/clj-jwt "0.3.1"]
                 [threatgrid/clj-momo "0.3.5"]
                 [org.clojure/tools.logging "1.0.0"]
                 [metosin/ring-http-response "0.9.1"]
                 [metosin/compojure-api "1.1.13"]])
