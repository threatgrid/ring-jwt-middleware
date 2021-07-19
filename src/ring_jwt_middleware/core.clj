(ns ring-jwt-middleware.core
  (:require [clj-jwt.core :refer [str->jwt verify]]
            [clj-jwt.key :refer [public-key]]
            [clj-momo.lib.clj-time.coerce :as time-coerce]
            [clj-momo.lib.clj-time.core :as time]
            [clojure.set :as set]
            [clojure.string :as str]
            [clojure.tools.logging :as log]
            [ring.util.http-response :as resp]))

(defn gen-uuid []
  (str (java.util.UUID/randomUUID)))

(defn get-jwt
  "get the JWT from a ring request"
  [req]
  (some->> (get-in req [:headers "authorization"])
           (re-seq #"^Bearer\s+(.*)$")
           first
           second))

(defn decode
  "Given a JWT return an Auth hash-map"
  [token pubkey-fn log-fn]
  (try
    (let [jwt (str->jwt token)]
      (if-let [pubkey (pubkey-fn (:claims jwt))]
        (if (verify jwt :RS256 pubkey)
          (:claims jwt)
          (do (log-fn "Invalid signature"
                      {:level :warn
                       :jwt jwt
                       :token token})
              nil))
        (do (log-fn (str "Cannot retrieve a key for your JWT."
                         " One common reason would be that it has the wrong `iss` claim")
                    {:level :warn
                     :jwt jwt
                     :token token})
            nil)))
    (catch Exception e
      (log-fn "JWT decode failed:"
              {:exception_message (.getMessage e)
               :token token
               :level :warn})
      nil)))

(defn hr-duration
  "Given a duration in ms,
   return a human readable string"
  [t]
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
         (str/join " "))))

(defn jwt-expiry-ms
  "Given a JWT and a lifetime,
   calculate when it expired"
  [jwt-created jwt-max-lifetime-in-sec]
  (- (time-coerce/to-epoch (time/now))
     (+ jwt-created
        jwt-max-lifetime-in-sec)))

(defn check-jwt-expiry
  "Return a string if JWT expiration check fails, nil otherwise"
  [jwt jwt-max-lifetime-in-sec]
  (let [required-fields #{:nbf :exp :iat}
        jwt-keys (set (keys jwt))]
    (if (set/subset? required-fields jwt-keys)
      (let [now (time-coerce/to-epoch (time/now))
            expired-secs (- now (+ (:iat jwt 0) jwt-max-lifetime-in-sec))
            before-secs (- (:nbf jwt) now)
            expired-lifetime-secs (- now (:exp jwt 0))]
        (cond
          (pos? before-secs)
          (format "This JWT will be valid in %s"
                  (hr-duration (* 1000 before-secs)))

          (pos? expired-secs)
          (format "This JWT has expired %s ago (we don't allow JWT older than %s; we only check creation date and not maximal expiration date)"
                  (hr-duration (* 1000 expired-secs))
                  (hr-duration (* 1000 jwt-max-lifetime-in-sec)))

          (pos? expired-lifetime-secs)
          (format "This JWT max lifetime has expired %s ago"
                  (hr-duration (* 1000 expired-lifetime-secs)))))
      (format "This JWT doesn't contain the following fields %s"
              (pr-str (set/difference required-fields jwt-keys))))))

(defn default-error-handler
  "Return an `unauthorized` HTTP response
  and log the error along debug infos"
  [error-msg infos]
  (let [err {:error :invalid_jwt
             :error_description error-msg}]
    (log/info error-msg (pr-str (into infos err)))
    (resp/unauthorized err)))

(def default-jwt-lifetime-in-sec 86400)

(def no-revocation-strategy (constantly false))

(defn validate-jwt
  "Run both expiration and user checks,
  return a vec of errors or nothing"
  ([raw-jwt
    jwt
    jwt-max-lifetime-in-sec
    jwt-check-fn
    log-fn]
   (let [exp-vals [(check-jwt-expiry jwt
                                     (or jwt-max-lifetime-in-sec
                                         default-jwt-lifetime-in-sec))]
         checks (if (fn? jwt-check-fn)
                  (or (try (seq (jwt-check-fn raw-jwt jwt))
                           (catch Exception e
                             (log-fn "jwt-check-fn thrown an exception on"
                                     {:level :error
                                      :jwt jwt})
                             (throw e)))
                      [])
                  [])]
     (seq (remove nil?
                  (concat checks exp-vals)))))

  ([raw-jwt jwt jwt-max-lifetime-in-sec log-fn]
   (validate-jwt raw-jwt jwt jwt-max-lifetime-in-sec nil log-fn)))

(defn forbid-no-jwt-header-strategy
  "Forbid all request with no Auth header"
  [handler]
  (constantly
   (resp/unauthorized {:error :invalid_request
                       :error_description "No Authorization Header"})))

(def authorize-no-jwt-header-strategy
  "Authorize all request even with no Auth header."
  identity)

(defn jwt->user-id
  "can be used as post-jwt-format-fn"
  [jwt]
  (:sub jwt))

(defn jwt->oauth-ids
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
  [prefix jwt]
  (let [n (+ 1 (count prefix))
        update-if-contains? (fn [m k f]
                              (if (contains? m k)
                                (update m k f)
                                m))
        keywordize #(map keyword %)
        str-to-path (fn [k]
                      (-> k ;; the key of the jwt map that starts with prefix
                          (subs n) ;; remove the prefix
                          (str/split #"/") ;; split on /
                          ;; finally keywordize all elements
                          keywordize))
        tmp (->> jwt
                 (map (fn [[k v]]
                        (when (and (string? k) (str/starts-with? k prefix))
                          [(str-to-path k) v])))
                 (remove nil?) ;; remove key not starting by prefix
                 (reduce (fn [acc [kl v]] (assoc-in acc kl v)) {}) ;; construct the hash-map
                 )]
    (-> tmp
        (assoc-in [:user :id] (:sub jwt)) ;; :sub overwrite any :user :id
        (update-if-contains? :scopes set) ;; and scopes should be a set, not alist
        )))

(defn default-structured-log
  [msg infos]
  (let [level (or (:level infos) :info)
        txt (format "JWT: %s\n%s"
                    msg
                    (pr-str infos))]
    (log/log level txt)))

(defn wrap-jwt-auth-fn
  "wrap a ring handler with JWT check"
  [{:keys [pubkey-path
           pubkey-fn
           is-revoked-fn
           jwt-check-fn
           jwt-max-lifetime-in-sec
           post-jwt-format-fn
           no-jwt-handler
           error-handler
           structured-log-fn]
    :or {jwt-max-lifetime-in-sec default-jwt-lifetime-in-sec
         is-revoked-fn no-revocation-strategy
         post-jwt-format-fn jwt->user-id
         no-jwt-handler forbid-no-jwt-header-strategy
         structured-log-fn default-structured-log}}]
  (let [p-fn (or pubkey-fn (constantly (public-key pubkey-path)))
        is-revoked-fn (if (fn? is-revoked-fn)
                        is-revoked-fn
                        (do (structured-log-fn
                             "is-revoked-fn is not a function! no-revocation-strategy is used."
                             {:level :error})
                            no-revocation-strategy))
        handle-error (or error-handler default-error-handler)]
    (fn [handler]
      (let [no-jwt-fn (no-jwt-handler handler)]
        (fn [request]
          (if-let [raw-jwt (get-jwt request)]
            (if-let [jwt (decode raw-jwt p-fn structured-log-fn)]
              (if-let [validation-errors
                       (validate-jwt raw-jwt
                                     jwt
                                     jwt-max-lifetime-in-sec
                                     jwt-check-fn
                                     structured-log-fn)]
                (handle-error (format "(%s) %s"
                                      (or (jwt->user-id jwt) "Unknown User ID")
                                      (str/join ", " validation-errors))
                              {:jwt jwt
                               :error :jwt_validation_error
                               :errors validation-errors})
                (if (try (is-revoked-fn jwt)
                         (catch Exception e
                           (structured-log-fn "is-revoked-fn thrown an exception for"
                                              {:level :error
                                               :jwt jwt})
                           (throw e)))
                  (handle-error (format "JWT revoked for %s"
                                        (or (jwt->user-id jwt) "Unknown User ID"))
                                {:jwt jwt
                                 :error :jwt_revoked})
                  (handler (assoc request
                                  :identity (post-jwt-format-fn jwt)
                                  :jwt jwt))))
              (handle-error "Invalid Authorization Header (couldn't verify the JWT signature)"
                            {:authorization-header (str "Bearer:" raw-jwt)}))
            (no-jwt-fn request)))))))
