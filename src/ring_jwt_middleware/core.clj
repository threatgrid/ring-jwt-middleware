(ns ring-jwt-middleware.core
  (:require [clj-jwt.core :refer [str->jwt verify]]
            [clj-jwt.key :refer [public-key]]
            [clojure.set :as set]
            [clojure.string :as string]
            [ring-jwt-middleware.config :refer [->config]]
            [ring-jwt-middleware.result
             :refer
             [->err ->pure <-result let-either result-of]]
            [ring-jwt-middleware.schemas :refer [Config JWTClaims JWTDecoded UserConfig]]
            [ring.util.http-response :as resp]
            [schema.core :as s]))

(s/defn get-jwt :- (result-of s/Str)
  "get the JWT from a ring request"
  [req]
  (if-let [raw-jwt (some->> (get-in req [:headers "authorization"])
                            (re-seq #"^Bearer\s+(.*)$")
                            first
                            second)]
    (->pure raw-jwt)
    (->err :no_jwt "No JWT found in HTTP headers" {})))

(s/defn decode :- (result-of {:jwt JWTDecoded})
  "Given a JWT return an Auth hash-map"
  [token :- s/Str
   pubkey-fn :- (s/=> s/Any)
   pubkey-fn-arg-fn :- (s/=> s/Any)]
  (try
    (let [jwt (str->jwt token)]
      (if-let [pubkey (pubkey-fn (pubkey-fn-arg-fn jwt))]
        (if (verify jwt :RS256 pubkey)
          (->pure {:jwt (select-keys jwt [:header :claims])})
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
       (->pure :no-custom-checks)))))

(s/defn mk-wrap-authentication
  "A function building a middleware that will add some fields to the ring request:

  - :jwt that will contain the jwt claims
  - :identity that will contain an object derived from the JWT claims
  - :jwt-error if something went wrong

  To build the middleware the configuration is a map with the following fields:

  - pubkey-path ; should contain a path to the public key to be used to verify JWT signature
  - pubkey-fn ; should contain a function that once called will return the public key
  - pubkey-fn-arg-fn ; should contain a function that will be called to modify the argument (the raw JWT) of `pubkey-fn`
  - is-revoked-fn ; should be a function that takes a decoded jwt and return a non nil value if the jwt is revoked
  - jwt-check-fn ; should be a function taking a raw JWT string, and a decoded JWT and returns a list of errors or nil if no error is found.
  - jwt-max-lifetime-in-sec ; maximal lifetime of a JWT in seconds (takes priority over :exp)
  - post-jwt-format-fn ; a function taking a JWT and returning a data structure representing the identity of a user

  "
  [user-config :- UserConfig]
  (let [{:keys [pubkey-path
                pubkey-fn
                is-revoked-fn
                post-jwt-format-fn
                post-jwt-format-fn-arg-fn
                pubkey-fn-arg-fn]
         :as config} (->config user-config)
        p-fn (or pubkey-fn (constantly (public-key pubkey-path)))]
    (fn [handler]
      (fn [request]
        (let [authentication-result
              (let-either [raw-jwt (get-jwt request)
                           {:keys [jwt]} (decode raw-jwt p-fn pubkey-fn-arg-fn)
                           _ (validate-jwt config raw-jwt (:claims jwt))
                           _ (try (if-let [{:keys [error error_description]
                                            :as _revoked-result} (is-revoked-fn (:claims jwt))]
                                    (if (and (keyword? error)
                                             (string? error_description))
                                      (->err error error_description {:jwt jwt})
                                      (->err :jwt_revoked "JWT is revoked" {:jwt jwt}))
                                    (->pure :ok))
                                  (catch Exception e
                                    (->err :jwt-revocation-fn-exception
                                           "is-revoked-fn thrown an exception"
                                           {:level :error
                                            :exception e
                                            :jwt jwt})))]
                (->pure {:identity (post-jwt-format-fn (post-jwt-format-fn-arg-fn jwt))
                         :jwt (:claims jwt)}))]
          (handler (into request (<-result authentication-result))))))))

(s/defschema RingRequest
  "we don't need to be more precise that saying this is an hash-map.
  The RingRequest schema is used as a documentation helper."
  {s/Any s/Any})

(s/defn authenticated? :- s/Bool
  [request :- RingRequest]
  (and (contains? request :jwt)
       (not (contains? request :jwt-error))))

(defn forbid-no-jwt-header-strategy
  "Forbid all request with no Auth header"
  [_handler]
  (constantly
   (resp/unauthorized {:error :invalid_request
                       :error_description "No JWT found in HTTP Authorization header"})))

(def authorize-no-jwt-header-strategy
  "Authorize all request even with no Auth header."
  identity)

(s/defn mk-wrap-authorization
  "A function building a middleware taking care of the authorization logic.

  It must be used in conjunction with `mk-wrap-authentication`.

  The configuration is map containing two handlers.

  - allow-unauthenticated-access? => set it to true to not block the request when no JWT is provided
  - error-handler => a function taking a JWT error (see Result) and returning a ring response.
                     This function should generally just return a 401 (unauthorized)."
  [user-config :- UserConfig]
  (let [{:keys [allow-unauthenticated-access?
                error-handler]} (->config user-config)]
    (fn [handler]
      (let [no-jwt-fn (if allow-unauthenticated-access?
                        (authorize-no-jwt-header-strategy handler)
                        (forbid-no-jwt-header-strategy handler))]
        (fn [request]
          (if (authenticated? request)
            (handler request)
            (let [jwt-error (:jwt-error request)]
              (case (:error jwt-error)
                :no_jwt (no-jwt-fn request)
                nil (error-handler {:error :unauthenticated_user
                                    :error_description "No authenticated user."})
                (error-handler jwt-error)))))))))


(defn wrap-jwt-auth-fn
  "wrap a ring handler with JWT check both authentication and authorization mixed"
  [conf]
  (let [wrap-authentication (mk-wrap-authentication conf)
        wrap-authorization (mk-wrap-authorization conf)]
    (comp wrap-authentication wrap-authorization)))

(defn wrap-jwt-auth-with-in-between-middleware-fn
  "Wrap the JWT authentication, authorization and a middleware wrapper in the middle

  The wrapper will have access to both:
  - the request with JWT details added by the authentication layer
  - the response status returned by the authorization layer.

  This is a good place to put a log middlware that will log all requests
  "
  [conf wrap-logs]
  (let [wrap-authentication (mk-wrap-authentication conf)
        wrap-authorization (mk-wrap-authorization conf)]
    (comp wrap-authentication wrap-logs wrap-authorization)))
