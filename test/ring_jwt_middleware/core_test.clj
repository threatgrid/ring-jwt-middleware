(ns ring-jwt-middleware.core-test
  (:require [clj-jwt.core :as jwt]
            [clj-jwt.intdate :refer [intdate->joda-time]]
            [clj-jwt.key :refer [public-key]]
            [clojure.test :refer [deftest is testing use-fixtures]]
            [java-time :as jt]
            [ring-jwt-middleware.core :as sut]
            [ring-jwt-middleware.config :as config]
            [ring-jwt-middleware.result :as result]
            [clojure.tools.logging]
            [clojure.tools.logging.impl]
            [schema.test]))

(defn with-disabled-logs [t]
  (binding [clojure.tools.logging/*logger-factory*
            clojure.tools.logging.impl/disabled-logger-factory]
    (t)))

(use-fixtures :each
  schema.test/validate-schemas
  with-disabled-logs)

(def fixed-current-epoch (constantly 1498815302))

(defn make-jwt
  "a useful one liner for easy testing"
  [input-map privkey-name kid]
  (let [privkey (clj-jwt.key/private-key
                 (str "resources/cert/" privkey-name ".key") "clojure")]
    (-> input-map
        jwt/jwt
        (jwt/sign :RS256 privkey kid)
        jwt/to-str)))

(def epoch-to-time intdate->joda-time)

(defn to-epoch
  "local date time to UTC-0 epoch in s"
  [d]
  (quot
   (jt/to-millis-from-epoch
    (jt/zoned-date-time d (jt/zone-id "UTC" (jt/zone-offset 0))))
   1000))

(defn const-d
  [& args]
  (constantly (to-epoch (apply jt/local-date-time args))))


(jt/available-zone-ids)

(def jwt-token-1
  (make-jwt
   {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
    :exp (epoch-to-time 1499419023)
    :iat (epoch-to-time 1498814223) ;; 2017-06-30T09:17:03Z
    :nbf (epoch-to-time 1498813923)
    :sub "foo@bar.com"
    :iss "TEST-ISSUER-1"
    :user-identifier "foo@bar.com"
    :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
    :foo "bar"}
   "jwt-key-1"
   "kid-1"))

(def jwt-token-2
  (make-jwt
   {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
    :exp (epoch-to-time 1499419023)
    :iat (epoch-to-time 1498814223) ;; 2017-06-30T09:17:03Z
    :nbf (epoch-to-time 1498813923)
    :sub "foo@bar.com"
    :iss "TEST-ISSUER-2"
    :user-identifier "foo@bar.com"
    :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
    :foo "bar"}
   "jwt-key-2"
   "kid-2"))

(def jwt-token-3
  (make-jwt
   {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
    :exp (epoch-to-time 1499419023)
    :iat (epoch-to-time 1498814223) ;; 2017-06-30T09:17:03Z
    :nbf (epoch-to-time 1498813923)
    :sub "foo@bar.com"
    :iss "TEST-ISSUER-3"
    :user-identifier "foo@bar.com"
    :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
    :foo "bar"}
   "jwt-key-3"
   "kid-3"))

(def decoded-jwt-1
  "jwt-token-1 decoded"
  {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
   :exp 1499419023
   :iat 1498814223 ;; 2017-06-30T09:17:03Z
   :nbf 1498813923
   :sub "foo@bar.com"
   :iss "TEST-ISSUER-1"
   :user-identifier "foo@bar.com"
   :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
   :foo "bar"})

(def jwt-signed-with-wrong-key
  (make-jwt
   {:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d"
    :exp (epoch-to-time 1499419023)
    :iat (epoch-to-time 1498814223) ;; 2017-06-30T09:17:03Z
    :nbf (epoch-to-time 1498813923)
    :sub "foo@bar.com"
    :iss "TEST-ISSUER-1"
    :user-identifier "foo@bar.com"
    :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"
    :foo "bar"}
   "jwt-key-2"
   "kid-2"))

(def decoded-jwt-2
  {:user-identifier "bar@foo.com",
   :iss "TEST-ISSUER-1"
   :iat 1487168050 ;; 2017-02-15T14:14:10Z
   :exp (+ 1487168050 (* 7 24 60 60))
   :nbf (- 1487168050 (* 5 24 60 60))})

(def pubkey1 (public-key "resources/cert/jwt-key-1.pub"))
(def pubkey2 (public-key "resources/cert/jwt-key-2.pub"))
(def pubkey3 (public-key "resources/cert/jwt-key-3.pub"))

(deftest decode-test
  (is (= decoded-jwt-1
         (:jwt (result/<-result (sut/decode jwt-token-1 (constantly pubkey1) :claims)))))
  (is (result/error? (sut/decode jwt-signed-with-wrong-key (constantly pubkey1) :claims)))
  (is (= {:error :jwt_invalid_signature, :error_description "Invalid Signature"}
         (-> (sut/decode jwt-signed-with-wrong-key (constantly pubkey1) :claims)
             :jwt-error
             (select-keys [:error :error_description])))))

(deftest validate-errors-test
  (let [cfg (config/->config {:current-epoch fixed-current-epoch
                           :pubkey-path "resources/cert/jwt-key-1.pub"})]

    (is (result/success? (sut/validate-jwt cfg "jwt" decoded-jwt-1)))
    (is (= {:jwt-error {:jwt {}
                        :error :jwt_missing_field
                        :error_description
                        "This JWT doesn't contain the following fields #{:exp :nbf :iat}"}}
           (sut/validate-jwt cfg "jwt" {})))
    (is (= {:jwt-error {:jwt {:user-identifier "foo@bar.com", :iat 1487168050},
                        :error :jwt_missing_field,
                        :error_description
                        "This JWT doesn't contain the following fields #{:exp :nbf}"}}
           (sut/validate-jwt cfg "jwt" {:user-identifier "foo@bar.com" :iat 1487168050})))
    (testing "custom check-fn"
      (is (= {:jwt-error
              {:jwt
               {:user-identifier "foo@bar.com",
                :sub "foo@bar.com",
                :iss "TEST-ISSUER-1",
                :exp 1499419023,
                :jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d",
                :nbf 1498813923,
                :foo "bar",
                :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c",
                :iat 1498814223},
               :raw-jwt "jwt",
               :error :jwt_custom_check_fail,
               :error_description "SOMETHING BAD HAPPENED"}}
             (sut/validate-jwt
              (assoc cfg
                     :jwt-check-fn
                     (fn [_raw-jwt _jwt] ["SOMETHING BAD HAPPENED"]))
              "jwt"
              decoded-jwt-1))))
    (testing "check-fn throw an exception"
      (is (= {:jwt-error
              {:level :error,
               :raw-jwt "jwt",
               :jwt
               {:user-identifier "foo@bar.com",
                :sub "foo@bar.com",
                :iss "TEST-ISSUER-1",
                :exp 1499419023,
                :jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d",
                :nbf 1498813923,
                :foo "bar",
                :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c",
                :iat 1498814223},
               :error :jwt-custom-check-exception,
               :error_description "jwt-check-fn threw an exception"}}
             (-> (try
                   (sut/validate-jwt
                    (assoc cfg
                           :jwt-check-fn
                           (fn [_raw-jwt _jwt] (throw (ex-info "check-fn fail test" {:test-infos :test}))))
                    "jwt"
                    decoded-jwt-1)
                   (catch Exception e (.getMessage e)))
                 (update :jwt-error dissoc :exception)))))

    (testing "check-fn fail by using the raw-jwt"
      (is (= {:jwt-error
              {:raw-jwt "jwt"
               :jwt
               {:user-identifier "foo@bar.com",
                :sub "foo@bar.com",
                :iss "TEST-ISSUER-1",
                :exp 1499419023,
                :jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d",
                :nbf 1498813923,
                :foo "bar",
                :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c",
                :iat 1498814223},
               :error :jwt_custom_check_fail,
               :error_description "jwt"}}
             (try (sut/validate-jwt (assoc cfg :jwt-check-fn (fn [raw-jwt _jwt] [raw-jwt]))
                                    "jwt"
                                    decoded-jwt-1)
                  (catch Exception e (.getMessage e))))))

    (testing "expiration message"
      (testing "expired time"
        (let [explain-msg "This JWT has expired %s ago (we don't allow JWT older than 1 day; we only check creation date and not maximal expiration date)"
              tst-fn (fn [d expected]
                       (is (= (format explain-msg expected)
                              (-> (sut/validate-jwt (assoc cfg :current-epoch d) "jwt" decoded-jwt-2)
                                  :jwt-error
                                  :error_description))))]
          (tst-fn (const-d 2017 02 16 14 14 11) "1s")
          (tst-fn (const-d 2017 02 16 15 14 10 0) "1h")
          (tst-fn (const-d 2017 02 17 15 14 10 0) "1 day 1h")
          (tst-fn (const-d 2017 02 18 15 14 10 0) "2 days 1h")
          (tst-fn (const-d 2019 04 03 8 24 5 123) "2 years 45 days 18h 9min 55s")
          (is (= (format explain-msg "1s")
                 (-> (sut/validate-jwt (assoc cfg :current-epoch (const-d 2017 02 16 14 14 11)) "jwt" decoded-jwt-2)
                     :jwt-error
                     :error_description))
              "Default maximal JWT lifetime should be set to 1 day")))

      (testing "max lifetime"
        (let [explain-msg "This JWT has expired %s ago (we don't allow JWT older than %s; we only check creation date and not maximal expiration date)"
              tst-fn (fn [d max-lifetime expected expected-max]
                       (is (= (format explain-msg expected expected-max)
                              (-> (sut/validate-jwt (assoc cfg
                                                           :jwt-max-lifetime-in-sec max-lifetime
                                                           :current-epoch d)
                                                    "jwt" decoded-jwt-2)
                                  :jwt-error :error_description))))]
          (tst-fn (const-d 2017 02 16 14 14 11) 86400 "1s" "1 day")
          (tst-fn (const-d 2017 02 16 14 14 11) 86300 "1min 41s" "23h 58min 20s"))))))

(deftest get-jwt-test
  (testing "get-jwt requests containing a JWT"
    (is (= {:result "foo"}
           (sut/get-jwt {:headers {"authorization" "Bearer foo"}}))))
  (testing "get-jwt requests without no JWT"
    (is (= {:jwt-error {:error :no_jwt, :error_description "No JWT found in HTTP headers"}}
           (sut/get-jwt {:headers {"authorization" "Bearer"}})))
    (is (= {:jwt-error {:error :no_jwt, :error_description "No JWT found in HTTP headers"}}
           (sut/get-jwt {:headers {"bad" "Bearer foo"}})))))

(defn with-mid [cfg handler]
  (let [wrapper
        (sut/wrap-jwt-auth-fn (into {:pubkey-path "resources/cert/jwt-key-1.pub"}
                                    cfg))]
    (wrapper handler)))

(deftest wrap-jwt-auth-fn-test
  (let [handler (fn [req] {:status 200
                           :body (select-keys req [:jwt :identity :jwt-error])})
        req {:headers {"authorization" (str "Bearer " jwt-token-1)}}
        req-bad-jwt {:headers {"authorization" (str "Bearer x" jwt-token-1)}}
        req-no-header {}
        req-auth-header-not-jwt {:headers {"authorization" "api-key 1234-1234-1234-1234"}}

        handler-with-mid-cfg
        (fn [cfg]
          (fn [req]
            (let [wrapper (sut/wrap-jwt-auth-fn
                           (into
                            {:pubkey-path "resources/cert/jwt-key-1.pub"
                             :current-epoch (const-d 2017 06 30 11 32 10)}
                            cfg))
                  ring-fn (wrapper handler)]
              (ring-fn req))))]
    (testing "Basic usage"
      (let [ring-fn (handler-with-mid-cfg {})]
        (is (= {:status 200
                :body {:jwt {:user-identifier "foo@bar.com",
                             :sub "foo@bar.com",
                             :iss "TEST-ISSUER-1",
                             :exp 1499419023,
                             :jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d",
                             :nbf 1498813923,
                             :foo "bar",
                             :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c",
                             :iat 1498814223},
                       :identity "foo@bar.com"}}
               (ring-fn req)))

        (is (= {:status 401,
                :body
                {:error :jwt_decode_failed_exception,
                 :error_description "JWT decode failed"}}
               (-> (ring-fn req-bad-jwt)
                   (select-keys [:status :body])
                   (update :body select-keys [:error :error_description]))))
        (is (= {:status 401
                :body {:error :invalid_request,
                       :error_description "No JWT found in HTTP Authorization header"}}
               (-> (ring-fn req-no-header)
                   (select-keys [:status :body])
                   (update :body select-keys [:error :error_description]))))
        (is (= {:status 401
                :body {:error :invalid_request,
                       :error_description "No JWT found in HTTP Authorization header"}}
               (-> (ring-fn req-auth-header-not-jwt)
                   (select-keys [:status :body])
                   (update :body select-keys [:error :error_description]))))))
    (testing "The JWT should be expired after 24h"
      (let [ring-fn (handler-with-mid-cfg {:current-epoch (const-d 2017 07 1 9 17 4)})]
        (is (= 401
               (:status (ring-fn req)))))
      (let [ring-fn (handler-with-mid-cfg {:current-epoch (const-d 2017 07 1 9 17 3)})]
        (is (= 200
               (:status (ring-fn req))))))


    (testing "multiple keys support"
      (let [pubkey-fn (fn [claims]
                        (case (:iss claims)
                          "TEST-ISSUER-1" pubkey1
                          "TEST-ISSUER-2" pubkey2))
            ring-fn (handler-with-mid-cfg {:pubkey-fn pubkey-fn})
            req {:headers {"authorization" (str "Bearer " jwt-token-1)}}
            req-2 {:headers {"authorization" (str "Bearer " jwt-token-2)}}
            req-3 {:headers {"authorization" (str "Bearer " jwt-token-3)}}
            response-1 (ring-fn req)
            response-2 (ring-fn req-2)
            response-3 (ring-fn req-3)]
        (is (= 200 (:status response-1)))
        (is (= 200 (:status response-2)))
        (is (= 401 (:status response-3)))
        (is (= :jwt_decode_failed_exception
               (get-in response-3 [:body :error])))))

    (testing "Authorized No Auth Header strategy test"
      (let [ring-fn (handler-with-mid-cfg {:allow-unauthenticated-access? true})]
        (is (= {:status 200
                :body {:jwt {:user-identifier "foo@bar.com",
                             :sub "foo@bar.com",
                             :iss "TEST-ISSUER-1",
                             :exp 1499419023,
                             :jti "r3e03ac6e-8d09-4d5e-8598-30e51a26dd2d",
                             :nbf 1498813923,
                             :foo "bar",
                             :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c",
                             :iat 1498814223},
                       :identity "foo@bar.com"}}
               (ring-fn req)))

        (is (= {:status 401,
                :body
                {:error :jwt_decode_failed_exception,
                 :error_description "JWT decode failed"}}
               (-> (ring-fn req-bad-jwt)
                   (select-keys [:status :body])
                   (update :body select-keys [:error :error_description]))))
        (is (= {:status 200
                :body
                {:jwt-error
                 {:error :no_jwt, :error_description "No JWT found in HTTP headers"}}}
               (ring-fn req-no-header)))
        (is (= {:status 200
                :body
                {:jwt-error
                 {:error :no_jwt, :error_description "No JWT found in HTTP headers"}}}
               (ring-fn req-auth-header-not-jwt)))))


    (testing "revocation test"
      (let [revoke-handler (handler-with-mid-cfg {:is-revoked-fn (constantly true)})
            no-revoke-handler (handler-with-mid-cfg {:is-revoked-fn (constantly false)})]
        (is (= 401 (:status (revoke-handler req))))
        (is (= 200 (:status (no-revoke-handler req))))
        (is (= "foo@bar.com"
               (get-in (no-revoke-handler req) [:body :identity]))))
      (let [revoke-handler (handler-with-mid-cfg {:is-revoked-fn (constantly {:error :internal-error :error_description "Internal Error"})})
            no-revoke-handler (handler-with-mid-cfg {:is-revoked-fn (constantly false)})]
        (is (= 401 (:status (revoke-handler req))))
        (is (= {:error :internal-error
                :error_description "Internal Error"}
               (select-keys (:body (revoke-handler req))
                                 [:error :error_description]))
            "is-revoked-fn can provide specific errors")
        (is (= 200 (:status (no-revoke-handler req))))
        (is (= "foo@bar.com"
               (get-in (no-revoke-handler req) [:body :identity]))))
      )

    (testing "post jwt transformation test"
      (let [post-transform (fn [m] {:user {:id (:sub m)}
                                    :org {:id (:foo m)}})
            ring-fn (handler-with-mid-cfg {:post-jwt-format-fn post-transform})]
        (is (= 200 (:status (ring-fn req))))
        (is (= {:user {:id "foo@bar.com"}
                :org {:id "bar"}}
               (get-in (ring-fn req) [:body :identity])))))))
