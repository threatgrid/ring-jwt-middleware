(ns ring-jwt-middleware.core
  (:require [clj-jwt.core :refer [str->jwt verify]]
            [clj-jwt.key :refer [public-key]]
            [clojure.set :as set]
            [clojure.string :as string]
            [clojure.tools.logging :as log]
            [ring-jwt-middleware.result :refer [->err ->pure <-result result-of let-either]]
            [ring.util.http-response :as resp]
            [schema.core :as s]
            [schema-tools.core :as st]))

;; Schemas
(s/defschema KeywordOrString
  (s/conditional keyword? s/Keyword
                 :else s/Str))

(def JWT
  "A JWT is just a string"
  s/Str)

(s/defschema JWTClaims
  (st/merge
   (st/optional-keys
    {:exp s/Num
     :nbf s/Num
     :iat s/Num
     :iss s/Str
     :sub s/Str
     :aud (s/conditional string? s/Str :else [s/Str])
     :user_email s/Str})
   {KeywordOrString s/Any}))

(defn describe
  "A function adding a description meta to schema.
  This help schema as documentation."
  [s description]
  (if (instance? clojure.lang.IObj s)
    (with-meta s {:description description})
    s))

(s/defschema Config
  "Middleware Configuration"
  (st/optional-keys
   {:allow-unauthenticated? (describe s/Bool
                                      "Set this to true to allow unauthenticated requests")
    :current-epoch (describe (s/=> s/Num)
                             "A function returning the current time in epoch format")
    :is-revoked-fn (describe (s/=> s/Bool JWTClaims)
                             "A function that take a JWT and return true if it is revoked")
    :jwt-max-lifetime-in-sec (describe s/Num
                                       "Maximal number of second a JWT does not expires")
    :jwt-check-fn  (describe (s/=> s/Bool JWT JWTClaims)
                             "A function that take a JWT, claims and return a string")
    :post-jwt-format-fn (describe (s/=> s/Any JWTClaims)
                                  "A function taking the JWT claims and building an Identity object suitable for your needs")
    :pubkey-fn (describe (s/=> s/Any s/Str)
                         "A function returning a public key (takes precedence over pubkey-path)")
    :pubkey-path (describe s/Str
                           "The path to find the public key that will be used to check the JWT signature")}))

(s/defn get-jwt :- (result-of s/Str)
  "get the JWT from a ring request"
  [req]
  (if-let [raw-jwt (some->> (get-in req [:headers "authorization"])
                            (re-seq #"^Bearer\s+(.*)$")
                            first
                            second)]
    (->pure raw-jwt)
    (->err :no_jwt "No JWT found in HTTP headers" {})))

(s/defn decode :- (result-of {:jwt JWTClaims})
  "Given a JWT return an Auth hash-map"
  [token :- s/Str
   pubkey-fn :- (s/=> s/Any)]
  (try
    (let [jwt (str->jwt token)]
      (if-let [pubkey (pubkey-fn (:claims jwt))]
        (if (verify jwt :RS256 pubkey)
          (->pure {:jwt (:claims jwt)})
          (->err :jwt_invalid_signature "Invalid Signature" {:level :warn
                                                             :jwt jwt
                                                             :token token}))
        (->err :jwt_public_key_not_found
               (str "Cannot retrieve a key for your JWT."
                    " One common reason would be that it has the wrong `iss` claim")
               {:jwt jwt
                :level :warn
                :token token})))
    (catch Exception e
      (->err :jwt_decode_failed_exception
             "JWT decode failed"
             {:exception_message (.getMessage e)
              :token token
              :level :warn
              :exception e}))))

(s/defn hr-duration :- s/Str
  "Given a duration in ms,
   return a human readable string"
  [t :- s/Num]
  (let [second     1000
        minute     (* 60 second)
        hour       (* 60 minute)
        day        (* 24 hour)
        year       (* 365 day)
        nb-years   (quot t year)
        nb-days    (quot (rem t year) day)
        nb-hours   (quot (rem t day) hour)
        nb-minutes (quot (rem t hour) minute)
        nb-seconds (quot (rem t minute) second)
        nb-ms      (rem t second)]
    (->> (vector
          (when (pos? nb-years)
            (str nb-years " year" (when (> nb-years 1) "s")))
          (when (pos? nb-days)
            (str nb-days " day" (when (> nb-days 1) "s")))
          (when (pos? nb-hours)
            (str nb-hours "h"))
          (when (pos? nb-minutes)
            (str nb-minutes "min"))
          (when (pos? nb-seconds)
            (str nb-seconds "s"))
          (when (pos? nb-ms)
            (str nb-ms "ms")))
         (remove nil?)
         (string/join " "))))

(s/defn current-epoch! :- s/Num
  "Returns the current time in epoch"
  []
  (quot (System/currentTimeMillis) 1000))

(s/defn check-jwt-expiry :- (result-of s/Keyword)
  "Return a result with some error if the JWT do not respect time-related restrictions."
  [{:keys [jwt-max-lifetime-in-sec current-epoch]} :- Config
   jwt :- JWTClaims]
  (let [required-fields #{:nbf :exp :iat}
        jwt-keys        (set (keys jwt))]
    (if (set/subset? required-fields jwt-keys)
      (let [now                   (current-epoch)
            expired-secs          (- now (+ (:iat jwt 0) jwt-max-lifetime-in-sec))
            before-secs           (- (:nbf jwt) now)
            expired-lifetime-secs (- now (:exp jwt 0))
            err-metas             {:jwt jwt :now now}]
        (cond
          (pos? before-secs)
          (->err :jwt_valid_in_future
                 (format "This JWT will be valid in %s"
                         (hr-duration (* 1000 before-secs)))
                 err-metas)
          (pos? expired-secs)
          (->err :jwt_expired_via_max_jwt_lifetime
                 (format (str "This JWT has expired %s ago (we don't allow JWT older than %s;"
                              " we only check creation date and not maximal expiration date)")
                         (hr-duration (* 1000 expired-secs))
                         (hr-duration (* 1000 jwt-max-lifetime-in-sec)))
                 err-metas)
          (pos? expired-lifetime-secs)
          (->err :jwt_expired
                 (format "This JWT max lifetime has expired %s ago"
                         (hr-duration (* 1000 expired-lifetime-secs)))
                 err-metas)
          :else (->pure :ok)))
      (->err :jwt_missing_field
             (format "This JWT doesn't contain the following fields %s"
                     (pr-str (set/difference required-fields jwt-keys)))
             {:jwt jwt}))))

(defn default-error-handler
  "Return an `unauthorized` HTTP response and log the error along debug infos"
  [{:keys [error error_description] :as error-data}]
  (log/infof "%s: %s %s" error error_description (dissoc error-data :error :error_description :raw_jwt))
  (resp/unauthorized (dissoc error-data :raw_jwt)))

(def default-jwt-lifetime-in-sec
  "Default JWT lifetime is 24h"
  86400)

(def no-revocation-strategy
  "The default function used for `:is-revoked-fn` configuration"
  (constantly false))

(s/defn validate-jwt :- (result-of s/Keyword)
  "Run both expiration and user checks,
  return a vec of errors or nothing"
  ([{:keys [jwt-check-fn] :as cfg} :- Config
    raw-jwt :- s/Str
    jwt :- JWTClaims]
   (let-either [_ (check-jwt-expiry cfg jwt)]
     (if (fn? jwt-check-fn)
       (or (try (when-let [checks (seq (remove nil? (jwt-check-fn raw-jwt jwt)))]
                  (->err :jwt_custom_check_fail
                         (string/join ", " checks)
                         {:jwt jwt
                          :raw-jwt raw-jwt}))
                (catch Exception e
                  (->err :jwt-custom-check-exception
                         "jwt-check-fn threw an exception"
                         {:level :error
                          :exception e
                          :raw-jwt raw-jwt
                          :jwt jwt})))
           (->pure :custom-checks-ok))
       (->pure :no-custom-checks))))
  )

(defn forbid-no-jwt-header-strategy
  "Forbid all request with no Auth header"
  [_handler]
  (constantly
   (resp/unauthorized {:error :invalid_request
                       :error_description "No Authorization Header"})))

(def authorize-no-jwt-header-strategy
  "Authorize all request even with no Auth header."
  identity)

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

(s/defn mk-wrap-authentication
  "A function building a middleware that will add some fields to the ring request:

  - :jwt that will contain the jwt claims
  - :identity that will contain an object derived from the JWT claims
  - :jwt-error if something went wrong

  To build the middleware the configuration is a map with the following fields:

  - pubkey-path ; should contain a path to the public key to be used to verify JWT signature
  - pubkey-fn ; should contain a function that once called will return the public key
  - is-revoked-fn ; should be a function that takes a decoded jwt and return true if the jwt is revoked
  - jwt-check-fn ; should be a function taking a raw JWT string, and a decoded JWT and returns a list of errors or nil if no error is found.
  - jwt-max-lifetime-in-sec ; maximal lifetime of a JWT in seconds (takes priority over :exp)
  - post-jwt-format-fn ; a function taking a JWT and returning a data structure representing the identity of a user

  "
  [raw-config :- Config]
  (let [{:keys [pubkey-path
                pubkey-fn
                is-revoked-fn
                jwt-max-lifetime-in-sec
                post-jwt-format-fn
                current-epoch]
         :or {jwt-max-lifetime-in-sec default-jwt-lifetime-in-sec
              is-revoked-fn no-revocation-strategy
              post-jwt-format-fn jwt->user-id
              current-epoch current-epoch!}
         :as config} raw-config
        p-fn (or pubkey-fn (constantly (public-key pubkey-path)))
        is-revoked-fn (if (fn? is-revoked-fn)
                        is-revoked-fn
                        (do (log/error "is-revoked-fn is not a function! no-revocation-strategy is used.")
                            no-revocation-strategy))]
    (fn [handler]
      (fn [request]
        (let [authentication-result
              (let-either [raw-jwt (get-jwt request)
                           {:keys [jwt] :as  _decoded-result} (decode raw-jwt p-fn)
                           _ (validate-jwt config raw-jwt jwt)
                           _ (try (if (is-revoked-fn jwt)
                                    (->err :jwt_revoked "JWT is revoked" {:jwt jwt})
                                    (->pure :ok))
                                  (catch Exception e
                                    (->err :jwt-revocation-fn-exception
                                           "is-revoked-fn thrown an exception"
                                           {:level :error
                                            :exception e
                                            :jwt jwt})))]
                (->pure {:identity (post-jwt-format-fn jwt)
                         :jwt jwt}))]
          (handler (into request (<-result authentication-result))))))))

(s/defschema RingRequest
  "we don't need to be more precise that saying this is an hash-map.
  The RingRequest schema is used as a documentation helper."
  {s/Any s/Any})

(s/defn authenticated? :- s/Bool
  [request :- RingRequest]
  (and (contains? request :jwt)
       (not (contains? request :jwt-error))))

(defn mk-wrap-authorization
  "A function building a middleware taking care of the authorization logic.

  It must be used in conjunction with `mk-wrap-authentication`.

  The configuration is map containing two handlers.

  - allow-unauthenticated? => set it to true to not block the request when no JWT is provided
  - error-handler => a function taking a JWT error (see Result) and returning a ring response.
                     This function should generally just return a 401 (unauthorized)."
  [{:keys [allow-unauthenticated?
           error-handler]
    :or {allow-unauthenticated? false}}]
  (let [handle-error (or error-handler default-error-handler)]
    (fn [handler]
      (let [no-jwt-fn (if allow-unauthenticated?
                        (authorize-no-jwt-header-strategy handler)
                        (forbid-no-jwt-header-strategy handler))]
        (fn [request]
          (if (authenticated? request)
            (handler request)
            (let [jwt-error (:jwt-error request)]
              (case (:error jwt-error)
                :no_jwt (no-jwt-fn request)
                nil (handle-error {:error :unauthenticated_user
                                   :error_description "No authenticated user."})
                (handle-error jwt-error)))))))))


(def default-config
  {:allow-unauthenticated false
   :current-epoch current-epoch!
   :is-revoked-fn (constantly false)
   :jwt-max-lifetime-in-sec default-jwt-lifetime-in-sec
   :post-jwt-format-fn ,,,
   }
  )


(defn wrap-jwt-auth-fn
  "wrap a ring handler with JWT check both authentication and authorization mixed"
  [conf]
  (let [wrap-authentication (mk-wrap-authentication conf)
        wrap-authorization (mk-wrap-authorization conf)]
    (comp wrap-authentication wrap-authorization)))
