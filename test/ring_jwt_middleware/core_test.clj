(ns ring-jwt-middleware.core-test
  (:require [clj-jwt.key :refer [public-key]]
            [clj-momo.lib.clj-time.core :as time]
            [clojure.test :refer [deftest are is testing use-fixtures join-fixtures]]
            [ring-jwt-middleware.core :as sut]
            [schema.core :as s]))

(defn with-fixed-time
  [f]
  (with-redefs
    [time/now
     (constantly
      (time/date-time 2017 06 30 9 35 2))]
    (f)))


(defn with-fixed-uuid
  [f]
  (with-redefs
    [sut/gen-uuid (constantly "00000000-0000-0000-0000-000000000000")]
    (f)))

(defn make-jwt
  "a useful one liner for easy testing"
  [input-map]
  (-> input-map
      clj-jwt.core/jwt
      (clj-jwt.core/sign
       :RS256
       (clj-jwt.key/private-key
        "resources/cert/ring-jwt-middleware.key"
        "clojure"))
      clj-jwt.core/to-str))



(def log-events (atom []))

(defn test-log-fn
  [msg infos]
  (swap! log-events #(conj % {:msg msg :infos infos})))

(defn reset-log-events
  []
  (reset! log-events []))

(defn with-clean-event-logs [f]
  (do (reset-log-events)
      (f)))

(use-fixtures :once (join-fixtures [with-fixed-time
                                    with-fixed-uuid]))

(use-fixtures :each with-clean-event-logs)

(def input-jwt-token-1
  "a map for creating a sample token with clj-jwt"
  {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
   :exp (clj-time.coerce/from-long (* 1000 1499419023))
   :iat (clj-time.coerce/from-long (* 1000 1498814223)) ;; 2017-06-30T09:17:03Z
   :nbf (clj-time.coerce/from-long (* 1000 1498813923))
   :sub "foo@bar.com"
   :user-identifier "foo@bar.com"
   :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
   :foo "bar"})

(def jwt-token-1
  "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyLWlkZW50aWZpZXIiOiJmb29AYmFyLmNvbSIsInN1YiI6ImZvb0BiYXIuY29tIiwiZXhwIjoxNDk5NDE5MDIzLCJqdGkiOiJyM2UwM2FjNmUtOGQwOS00ZDVlLTg1OTgtMzBlNTFhMjZkZDJkIiwibmJmIjoxNDk4ODEzOTIzLCJmb28iOiJiYXIiLCJ1c2VyX2lkIjoiZjAwMTA5MjQtZTFiYy00YjAzLWI2MDAtODljNmNmNTI3NTdjIiwiaWF0IjoxNDk4ODE0MjIzfQ.PLNokPvuPz5t0Se3m2pjxzB97lJoWvGICXAia7mAxTiW8WBH0pOOm74ffHEeXGH1y8bRlfmH29eVKHq_IpZfYRIV0ydegQhbty5C35ij3Mqo0A3pAGOoezyp3XymHHE-JeEAgulxYy8BWN9zpij-zYO2uAZf4r7HIuNT5CJWTnmS4AYSrNeQl0ntTLUYwjDLwuJrL7VH4JeiwSEK-HBN1YkxLNPc22hyXKHz37vj4ERO1-GnEmdtOIntZ-BRj-qoX0q1Qx0BGyK-kJgRz_nHrbyX6GtuqYXzhU-uQ-S122K1s6Vek9GmtncchH2qkMaAtv7J4NTVnFU_3t_7LiOlRw")

(def decoded-jwt-1
  "jwt-token-1 decoded"
  {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
   :exp 1499419023
   :iat 1498814223 ;; 2017-06-30T09:17:03Z
   :nbf 1498813923
   :sub "foo@bar.com"
   :user-identifier "foo@bar.com"
   :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
   :foo "bar"})

(def jwt-signed-with-wrong-algorithm
  "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJqdGkiOiJyM2UwM2FjNmUtOGQwOS00ZDVlLTg1OTgtMzBlNTFhMjZkZDJkIiwiZXhwIjoxNDk5NDE5MDIzLCJpYXQiOjE0OTg4MTQyMjMsIm5iZiI6MTQ5ODgxMzkyMywic3ViIjoiZm9vQGJhci5jb20iLCJ1c2VyLWlkZW50aWZpZXIiOiJmb29AYmFyLmNvbSIsInVzZXJfaWQiOiJmMDAxMDkyNC1lMWJjLTRiMDMtYjYwMC04OWM2Y2Y1Mjc1N2MiLCJmb28iOiJiYXIifQ.")

(def decoded-jwt-2
  {:user-identifier "bar@foo.com",
   :iat 1487168050 ;; 2017-02-15T14:14:10Z
   :exp (+ 1487168050 (* 7 24 60 60))
   :nbf (- 1487168050 (* 5 24 60 60))})

(deftest decode-test
  (is (= decoded-jwt-1
         (sut/decode jwt-token-1
                     (public-key "resources/cert/ring-jwt-middleware.pub")
                     test-log-fn)))
  (is (= [] @log-events))
  (is (nil?
       (sut/decode jwt-signed-with-wrong-algorithm
                   (public-key "resources/cert/ring-jwt-middleware.pub")
                   test-log-fn)))

  (is (= "Invalid signature" (:msg (first @log-events))))
  (is (= :warn (:level (:infos (first @log-events)))))
  (is (= {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
          :exp 1499419023
          :iat 1498814223
          :nbf 1498813923
          :sub "foo@bar.com"
          :user-identifier "foo@bar.com"
          :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
          :foo "bar"}
         (get-in (first @log-events) [:infos :jwt :claims]))))

(deftest validate-errors-test
  (is (nil? (sut/validate-jwt decoded-jwt-1 86400 test-log-fn)))
  (is (= '("This JWT doesn't contain the following fields #{:exp :nbf :iat}")
         (sut/validate-jwt {} 86400 test-log-fn)))
  (is (= '("This JWT doesn't contain the following fields #{:exp :nbf}")
         (sut/validate-jwt {:user-identifier "foo@bar.com"
                            :iat 1487168050} 86400 test-log-fn)))
  (testing "check-fn fail"
    (is (= "check-fn fail test"
           (try
             (sut/validate-jwt decoded-jwt-1
                               86400
                               (fn [jwt] (throw (ex-info "check-fn fail test" {:test-infos :test})))
                               test-log-fn)
             (catch Exception e (.getMessage e)))))
    (is (= [{:msg "jwt-check-fn thrown an exception on",
             :infos
             {:level :error,
              :jwt
              {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d",
               :exp 1499419023,
               :iat 1498814223,
               :nbf 1498813923,
               :sub "foo@bar.com",
               :user-identifier "foo@bar.com",
               :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c",
               :foo "bar"}}}]
           @log-events))
    (reset-log-events))
  (with-redefs
    [time/now (constantly (time/date-time 2017 02 16 14 14 11))]
    (is (= '("This JWT has expired since 1s (we don't allow JWT older than 1 day; we only checked creation date and not maximal expiration date)")
           (sut/validate-jwt decoded-jwt-2 86400 test-log-fn))))

  (with-redefs
    [time/now (constantly (time/date-time 2017 02 16 15 14 10 0))]
    (is (= '("This JWT has expired since 1h (we don't allow JWT older than 1 day; we only checked creation date and not maximal expiration date)")
           (sut/validate-jwt decoded-jwt-2 86400 test-log-fn))))

  (with-redefs
    [time/now (constantly (time/date-time 2017 02 17 15 14 10 0))]
    (is (= '("This JWT has expired since 1 day 1h (we don't allow JWT older than 1 day; we only checked creation date and not maximal expiration date)")
           (sut/validate-jwt decoded-jwt-2 86400 test-log-fn))))

  (with-redefs
    [time/now (constantly (time/date-time 2017 02 18 15 14 10 0))]
    (is (= '("This JWT has expired since 2 days 1h (we don't allow JWT older than 1 day; we only checked creation date and not maximal expiration date)")
           (sut/validate-jwt decoded-jwt-2 86400 test-log-fn))))

  (with-redefs
    [time/now (constantly (time/date-time 2019 04 03 8 24 5 123))]
    (is (= '("This JWT has expired since 2 years 45 days 18h 9min 55s (we don't allow JWT older than 1 day; we only checked creation date and not maximal expiration date)")
           (sut/validate-jwt decoded-jwt-2 86400 test-log-fn))))

  (with-redefs
    [time/now (constantly (time/date-time 2017 02 16 14 14 11))]
    (is (= '("This JWT has expired since 1s (we don't allow JWT older than 1 day; we only checked creation date and not maximal expiration date)")
           (sut/validate-jwt decoded-jwt-2 86400 nil test-log-fn)))))

(deftest get-jwt-test
  (testing "get-jwt requests containing a JWT"
    (is (= "foo"
           (sut/get-jwt {:headers {"authorization" "Bearer foo"}}))))
  (testing "get-jwt requests without no JWT"
    (is (nil? (sut/get-jwt {:headers {"authorization" "Bearer"}})))
    (is (nil? (sut/get-jwt {:headers {"bad" "Bearer foo"}})))))

(deftest wrap-jwt-auth-fn-test
  (testing "basic usage"
    (let [wrapper (sut/wrap-jwt-auth-fn
                   {:pubkey-path "resources/cert/ring-jwt-middleware.pub"})
          ring-fn-1 (wrapper (fn [req] {:status 200
                                        :body (:identity req)}))
          ring-fn-2 (wrapper (fn [req] {:status 200
                                        :body(:jwt req)}))
          req-1 {:headers {"authorization"
                           (str "Bearer " jwt-token-1)}}
          req-bad-jwt {:headers {"authorization"
                                 (str "Bearer x" jwt-token-1)}}
          req-no-header {}
          req-auth-header-not-jwt {:headers {"authorization"
                                             "api-key 1234-1234-1234-1234"}}]
      (with-redefs [time/now (constantly (time/date-time 2017 06 30 11 32 10))]
        (let [response-1 (ring-fn-1 req-1)
              response-2 (ring-fn-2 req-1)
              response-no-header (ring-fn-1 req-no-header)
              response-auth-header-not-jwt (ring-fn-1 req-auth-header-not-jwt)]
          (:status (ring-fn-1 req-1))
          (is (= 200 (:status response-1)))
          (is (= "foo@bar.com" (:body response-1)))
          (is (= decoded-jwt-1 (:body response-2)))
          (is (= 401 (:status (ring-fn-1 req-bad-jwt))))
          (is (= 401 (:status response-no-header)))
          (is (= 401 (:status response-auth-header-not-jwt)))))
      (testing "The JWT should be expired after 24h"
        (is (= 401
               (with-redefs [time/now (constantly (time/date-time 2017 07 1 9 17 4))]
                 (:status (ring-fn-1 req-1)))))
        (is (= 200
               (with-redefs [time/now (constantly (time/date-time 2017 07 1 9 17 3))]
                 (:status (ring-fn-1 req-1))))))))
  (testing "Authorized No Auth Header strategy test"
    (let [wrapper (sut/wrap-jwt-auth-fn
                   {:pubkey-path "resources/cert/ring-jwt-middleware.pub"
                    :no-jwt-handler sut/authorize-no-jwt-header-strategy})
          ring-fn-1 (wrapper (fn [req] {:status 200
                                        :body (:identity req)}))
          ring-fn-2 (wrapper (fn [req] {:status 200
                                        :body(:jwt req)}))
          req-1 {:headers {"authorization"
                           (str "Bearer " jwt-token-1)}}
          req-bad-jwt {:headers {"authorization"
                                 (str "Bearer x" jwt-token-1)}}
          req-no-header {}]
      (with-redefs [time/now (constantly (time/date-time 2017 06 30 11 32 10))]
        (let [response-1 (ring-fn-1 req-1)
              response-2 (ring-fn-2 req-1)
              response-no-header (ring-fn-1 req-no-header)]
          (:status (ring-fn-1 req-1))
          (is (= 200 (:status response-1)))
          (is (= "foo@bar.com" (:body response-1)))
          (is (= decoded-jwt-1 (:body response-2)))
          (is (= 401 (:status (ring-fn-1 req-bad-jwt))))
          (is (= 200 (:status response-no-header)))
          (is (= nil (:body   response-no-header)))))
      (testing "The JWT should be expired after 24h"
        (is (= 401
               (with-redefs [time/now (constantly (time/date-time 2017 07 1 9 17 4))]
                 (:status (ring-fn-1 req-1)))))
        (is (= 200
               (with-redefs [time/now (constantly (time/date-time 2017 07 1 9 17 3))]
                 (:status (ring-fn-1 req-1))))))))
  (testing "Manual No Auth Header strategy test"
    (let [wrap-dummy-id (fn [handler]
                          (fn [request]
                            (-> request
                                (assoc :identity "dummy")
                                handler)))
          wrapper (sut/wrap-jwt-auth-fn
                   {:pubkey-path "resources/cert/ring-jwt-middleware.pub"
                    :no-jwt-handler wrap-dummy-id})
          ring-fn (wrapper (fn [req] {:status 200
                                      :body (:identity req)}))
          req-no-header {}
          req-auth-header-not-jwt {:headers {"authorization"
                                             "api-key 1234-1234-1234-1234"}}]
      (with-redefs [time/now (constantly (time/date-time 2017 06 30 11 32 10))]
        (let [response-no-header (ring-fn req-no-header)
              response-auth-header-not-jwt (ring-fn req-auth-header-not-jwt)]
          (is (= 200 (:status response-no-header)))
          (is (= "dummy" (:body   response-no-header)))

          (is (= 200 (:status response-auth-header-not-jwt)))
          (is (= "dummy" (:body response-auth-header-not-jwt)))))))
  (testing "revocation test"
    (let [always-revoke (fn [_] true)
          wrapper-always-revoke (sut/wrap-jwt-auth-fn
                                 {:pubkey-path "resources/cert/ring-jwt-middleware.pub"
                                  :is-revoked-fn always-revoke})
          never-revoke (fn [_] false)
          wrapper-never-revoke (sut/wrap-jwt-auth-fn
                                {:pubkey-path  "resources/cert/ring-jwt-middleware.pub"
                                 :is-revoked-fn never-revoke})
          ring-fn-1 (wrapper-always-revoke
                     (fn [req] {:status 200
                                :body (:identity req)}))

          ring-fn-2 (wrapper-never-revoke
                     (fn [req] {:status 200
                                :body (:identity req)}))
          req {:headers {"authorization"
                         (str "Bearer " jwt-token-1)}}]
      (is (= 401 (:status (ring-fn-1 req))))
      (is (= 200 (:status (ring-fn-2 req))))
      (is (= "foo@bar.com"
             (:body (ring-fn-2 req))))))
  (testing "post jwt transformation test"
    (let [post-transform (fn [m] {:user {:id (:sub m)}
                                  :org {:id (:foo m)}})
          wrapper-tr (sut/wrap-jwt-auth-fn
                      {:pubkey-path "resources/cert/ring-jwt-middleware.pub"
                       :post-jwt-format-fn post-transform})
          ring-fn-1 (wrapper-tr
                     (fn [req] {:status 200
                                :body (:identity req)}))
          req {:headers {"authorization"
                         (str "Bearer " jwt-token-1)}}]
      (is (= 200 (:status (ring-fn-1 req))))
      (is (= {:user {:id "foo@bar.com"}
              :org {:id "bar"}}
             (:body (ring-fn-1 req))))))
  (testing "post jwt transformation test"
    (let [post-transform (fn [m] {:user {:id (:sub m)}
                                  :org {:id (:foo m)}})
          wrapper-check (sut/wrap-jwt-auth-fn
                         {:pubkey-path "resources/cert/ring-jwt-middleware.pub"})
          ring-fn-1 (wrapper-check
                     (fn [req] {:status 200
                                :body (:identity req)}))
          req {:headers {"authorization"
                         (str "Bearer " jwt-token-1)}}]
      (is (= 200
             (with-redefs [time/now (constantly (time/date-time 2017 07 1 9 17 3))]
               (:status (ring-fn-1 req)))))
      (is (= 401
             (with-redefs [time/now (constantly (time/date-time 2018 07 1 9 17 4))]
               (:status (ring-fn-1 req))))))))


(deftest jwt->oauth-ids-test
  (is (= {:scopes #{"scope1" "scope2"},
          :org {:id "org-id"},
          :oauth {:client {:id "client-id"}},
          :user {:id "user-id"}}
         (sut/jwt->oauth-ids
          "http://example.com/claims"
          {:sub "user-id"
           "http://example.com/claims/scopes" ["scope1" "scope2"]
           "http://example.com/claims/org/id" "org-id"
           "http://example.com/claims/oauth/client/id" "client-id"})))

  (is (= {:scopes #{"scope1" "scope2"},
          :org {:id "org-id"},
          :oauth {:client {:id "client-id"}},
          :user {:id "user-id"}}
         (sut/jwt->oauth-ids
          "http://example.com/claims"
          {:sub "user-id"
           "http://example.com/claims/scopes" ["scope1" "scope2"]
           "http://example.com/claims/user/id" "BAD-USER-ID"
           "http://example.com/claims/org/id" "org-id"
           "http://example.com/claims/oauth/client/id" "client-id"})))

  (is (= {:user
          {:idp {:name "Visibility", :id "iroh"},
           :name "John Doe",
           :email "john.doe@dev.null",
           :id "user-id"},
          :oauth {:kind "code", :client {:id "client-id"}},
          :org {:name "ACME Inc.", :id "org-id"},
          :scopes #{"scope1" "scope2"}}
         (sut/jwt->oauth-ids
          "http://example.com/claims"
          {:sub "user-id"
           "http://example.com/claims/scopes" ["scope1" "scope2"]
           "http://example.com/claims/user/id" "user-id"
           "http://example.com/claims/user/name" "John Doe"
           "http://example.com/claims/user/email" "john.doe@dev.null"
           "http://example.com/claims/user/idp/id" "iroh"
           "http://example.com/claims/user/idp/name" "Visibility"
           "http://example.com/claims/org/id" "org-id"
           "http://example.com/claims/org/name" "ACME Inc."
           "http://example.com/claims/oauth/client/id" "client-id"
           "http://example.com/claims/oauth/kind" "code"}))))




