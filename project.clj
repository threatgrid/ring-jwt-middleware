(defproject threatgrid/ring-jwt-middleware "0.0.12"
  :description "A simple middleware to deal with JWT Authentication"
  :license {:name "Eclipse Public License - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo}
  :url "http://github.com/threatgrid/ring-jwt-middleware"
  :deploy-repositories [["releases" {:url "https://clojars.org/repo" :creds :gpg}]
                        ["snapshots" {:url "https://clojars.org/repo" :creds :gpg}]]
  :dependencies [[org.clojure/clojure "1.9.0"]
                 [yogsototh/clj-jwt "0.2.1"]
                 [threatgrid/clj-momo "0.2.21"]
                 [org.clojure/tools.logging "0.4.0"]
                 [metosin/ring-http-response "0.9.0"]
                 [metosin/compojure-api "1.1.12"]])
