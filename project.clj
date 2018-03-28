(defproject threatgrid/ring-jwt-middleware "0.0.4-SNAPSHOT"
  :description "A simple middleware to deal with JWT Authentication"
  :license {:name "Eclipse Public License - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo}
  :url "http://github.com/threatgrid/ring-jwt-middleware"
  :deploy-repositories [["releases" :clojars]]
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [yogsototh/clj-jwt "0.2.1"]
                 [threatgrid/clj-momo "0.2.9"]
                 [org.clojure/tools.logging "0.3.1"]
                 [metosin/ring-http-response "0.8.2"]
                 [metosin/compojure-api "1.1.9"]])
