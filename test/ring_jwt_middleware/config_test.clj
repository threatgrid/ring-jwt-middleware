(ns ring-jwt-middleware.config-test
  (:require [clojure.test :as t]
            [ring-jwt-middleware.config :as sut])
  (:import java.lang.AssertionError))

(t/deftest init-config-test
  (t/is (= (str "Assert failed:"
                " The configuration should provide at least one of "
                "`pubkey-path` or `pukey-fn`"
                "\n(or pubkey-path pubkey-fn)")
           (try
             (sut/->config {})
             (catch AssertionError e (.getMessage e)))))

  (t/is (= {:allow-unauthenticated-access? false
            :current-epoch sut/current-epoch!
            :is-revoked-fn sut/no-revocation-strategy
            :jwt-max-lifetime-in-sec 86400
            :post-jwt-format-fn sut/jwt->user-id
            :post-jwt-format-fn-arg-fn :claims
            :pubkey-path "/some/path"
            :pubkey-fn-arg-fn :claims
            :error-handler sut/default-error-handler}
           (sut/->config {:pubkey-path "/some/path"})))

  (t/is (sut/->config {:pubkey-fn (constantly "/some/path")})
        "providing a pubkey-fn should be enough"))

(t/deftest jwt->oauth-ids-test
  (t/is (= {:scopes #{"scope1" "scope2"},
            :org {:id "org-id"},
            :oauth {:client {:id "client-id"}},
            :user {:id "user-id"}}
           (sut/jwt->oauth-ids
            "http://example.com/claims"
            {:sub "user-id"
             "http://example.com/claims/scopes" ["scope1" "scope2"]
             "http://example.com/claims/org/id" "org-id"
             "http://example.com/claims/oauth/client/id" "client-id"})))

  (t/is (= {:scopes #{"scope1" "scope2"},
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

  (t/is (= {:user
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
