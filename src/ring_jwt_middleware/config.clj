(ns ring-jwt-middleware.config
  (:require [clojure.string :as string]
            [clojure.tools.logging :as log]
            [ring-jwt-middleware.schemas :refer [Config JWTClaims UserConfig]]
            [ring.util.http-response :as resp]
            [schema.core :as s]))

(s/defn current-millis! :- s/Num
  "This intermediate function is useful to use with-redefs during external tests"
  []
  (System/currentTimeMillis))

(s/defn current-epoch! :- s/Num
  "Returns the current time in epoch"
  []
  (quot (current-millis!) 1000))

(defn default-error-handler
  "Return an `unauthorized` HTTP response and log the error along debug infos"
  [{:keys [error error_description] :as jwt-error}]
  (log/infof "%s: %s %s" error error_description (dissoc jwt-error :error :error_description :raw_jwt))
  (resp/unauthorized (dissoc jwt-error :raw_jwt)))

(def default-jwt-lifetime-in-sec
  "Default JWT lifetime is 24h"
  86400)

(def no-revocation-strategy
  "The default function used for `:is-revoked-fn` configuration"
  (constantly false))

(s/defn jwt->user-id :- s/Str
  "can be used as post-jwt-format-fn"
  [jwt :- JWTClaims]
  (:sub jwt))

(s/defn jwt->oauth-ids
  "can be used as post-jwt-format-fn

  This is an example function that given a JWT whose claims looks like:

  - :sub
  - \"<prefix>/scopes\"
  - \"<prefix>/org/id\"
  - \"<prefix>/oauth/client/id\"

  It is a generic format about what an access-token should provide:

  - user-id, client-id, scopes
  - org-id

  mainly transform a list of <prefix>/foo/bar/baz value into a deep nested map.
  For example:

  (sut/jwt->oauth-ids
          \"http://example.com/claims\"
          {:sub \"user-id\"
           \"http://example.com/claims/scopes\" [\"scope1\" \"scope2\"]
           \"http://example.com/claims/user/id\" \"user-id\"
           \"http://example.com/claims/user/name\" \"John Doe\"
           \"http://example.com/claims/user/email\" \"john.doe@dev.null\"
           \"http://example.com/claims/user/idp/id\" \"iroh\"
           \"http://example.com/claims/user/idp/name\" \"Visibility\"
           \"http://example.com/claims/org/id\" \"org-id\"
           \"http://example.com/claims/org/name\" \"ACME Inc.\"
           \"http://example.com/claims/oauth/client/id\" \"client-id\"
           \"http://example.com/claims/oauth/kind\" \"code\"})

  => {:user {:idp {:name \"Visibility\"
                   :id \"iroh\"},
             :name \"John Doe\",
             :email \"john.doe@dev.null\",
             :id \"user-id\"}
      :oauth {:kind \"code\"
              :client {:id \"client-id\"}},
      :org   {:name \"ACME Inc.\"
              :id \"org-id\"},
      :scopes #{\"scope1\" \"scope2\"}}
  "
  [prefix :- s/Str
   jwt :- JWTClaims]
  (let [n (+ 1 (count prefix))
        update-if-contains? (fn [m k f]
                              (if (contains? m k)
                                (update m k f)
                                m))
        keywordize #(map keyword %)
        str-to-path (fn [k]
                      (-> k ;; the key of the jwt map that starts with prefix
                          (subs n) ;; remove the prefix
                          (string/split #"/") ;; split on /
                          ;; finally keywordize all elements
                          keywordize))
        tmp (->> jwt
                 (map (fn [[k v]]
                        (when (and (string? k) (string/starts-with? k prefix))
                          [(str-to-path k) v])))
                 (remove nil?) ;; remove key not starting by prefix
                 (reduce (fn [acc [kl v]] (assoc-in acc kl v)) {}) ;; construct the hash-map
                 )]
    (-> tmp
        (assoc-in [:user :id] (:sub jwt)) ;; :sub overwrite any :user :id
        (update-if-contains? :scopes set) ;; and scopes should be a set, not alist
        )))

(def default-config
  {:allow-unauthenticated-access? false
   :current-epoch current-epoch!
   :is-revoked-fn no-revocation-strategy
   :jwt-max-lifetime-in-sec default-jwt-lifetime-in-sec
   :post-jwt-format-fn jwt->user-id
   :error-handler default-error-handler})

(defn conf-valid?
  [{:keys [pubkey-path pubkey-fn] :as conf}]
  (s/validate Config conf)
  (assert (or pubkey-path pubkey-fn)
          "The configuration should provide at least one of `pubkey-path` or `pukey-fn`"))

(s/defn ->config :- Config
  [user-config :- UserConfig]
  (let [config (into default-config user-config)]
    (conf-valid? config)
    config))
