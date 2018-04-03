(ns ring-jwt-middleware.core
  (:require [clj-jwt
             [core :refer :all]
             [key :refer [public-key]]
             [json-key-fn :as jkf]]
            [clj-momo.lib.clj-time
             [coerce :as time-coerce]
             [core :as time]]
            [clojure
             [set :as set]
             [string :as str]]
            [clojure.tools.logging :as log]
            [compojure.api.meta :as meta]
            [ring.util.http-response :refer [unauthorized]]))

(defn get-jwt
  "get the JWT from a ring request"
  [req]
  (some->> (get-in req [:headers "authorization"])
           (re-seq #"^Bearer\s+(.*)$")
           first
           second))

(defn decode
  "Given a JWT return an Auth hash-map"
  [token pubkey]
  (try
    (let [jwt (str->jwt token)]
      (if (verify jwt :RS256 pubkey)
        (:claims jwt)
        (do (log/warn "Invalid signature")
            nil)))
    (catch Exception e
      (log/warn "JWT decode failed:" (.getMessage e)) nil)))

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
  [jwt
   jwt-max-lifetime-in-sec
   long-lived-jwt?]
  (let [required-fields #{:nbf :exp :iat}
        jwt-keys (set (keys jwt))]
    (if (set/subset? required-fields jwt-keys)
      (let [now (time-coerce/to-epoch (time/now))
            expired-secs (if (long-lived-jwt? jwt)
                           -1
                           (- now (+ (:iat jwt 0)
                                     jwt-max-lifetime-in-sec)))
            before-secs (- (:nbf jwt) now)
            expired-lifetime-secs (- now (:exp jwt 0))]
        (cond
          (pos? before-secs)
          (format "This JWT will be valid in %s"
                  (hr-duration (* 1000 before-secs)))

          (pos? expired-secs)
          (format "This JWT has expired since %s"
                  (hr-duration (* 1000 expired-secs)))

          (pos? expired-lifetime-secs)
          (format "This JWT max lifetime has expired since %s"
                  (hr-duration (* 1000 expired-lifetime-secs)))))
      (format "This JWT doesn't contain the following fields %s"
              (pr-str (set/difference required-fields jwt-keys))))))

(defn log-and-refuse
  "Return an `unauthorized` HTTP response
  and log the error along debug infos"
  [error-log-msg error-msg]
  (log/debug error-log-msg)
  (log/errorf "JWT Error(s): %s" error-msg)
  (unauthorized error-msg))

(def default-jwt-lifetime-in-sec 86400)

(def no-revocation-strategy (constantly false))

(def no-long-lived-jwt (constantly false))

(defn validate-jwt
  "Run both expiration and user checks,
  return a vec of errors or nothing"
  ([jwt
    jwt-max-lifetime-in-sec
    jwt-check-fn
    long-lived-jwt?]
   (let [exp-vals [(check-jwt-expiry jwt
                                     (or jwt-max-lifetime-in-sec
                                         default-jwt-lifetime-in-sec)
                                     long-lived-jwt?)]
         checks (if (fn? jwt-check-fn)
                  (or (try (seq (jwt-check-fn jwt))
                           (catch Exception e
                             (log/errorf "jwt-check-fn thrown an exception on: %s"
                                         (pr-str jwt))
                             (throw e)))
                      [])
                  [])]
     (seq (remove nil?
                  (concat checks exp-vals)))))

  ([jwt jwt-max-lifetime-in-sec]
   (validate-jwt jwt jwt-max-lifetime-in-sec nil no-long-lived-jwt)))

(defn forbid-no-jwt-header-strategy
  "Forbid all request with no Auth header"
  [handler]
  (constantly (unauthorized "No Authorization Header")))

(def authorize-no-jwt-header-strategy
  "Authorize all request even with no Auth header."
  identity)

(defn jwt->user-id
  "can be used as post-jwt-format-fn"
  [jwt]
  (:sub jwt))

(defn unalias-scopes [dict scopes]
  (let [new-scopes (set
                    (mapcat
                     (fn [s]
                       (if (contains? dict s)
                         ;; keeping high level scope makes
                         ;; the algorithm cycle resistant at low cost
                         (cons s (get dict s))
                         [s]))
                     scopes))]
    (if (= new-scopes (set scopes))
      new-scopes
      (unalias-scopes dict new-scopes))))

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
  ([prefix jwt]
   (jwt->oauth-ids {} prefix jwt))
  ([scope-aliases prefix jwt]
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
         (update-if-contains? :scopes #(unalias-scopes scope-aliases %)) ;; and scopes should be a set, not alist
         ))))

(defn wrap-jwt-auth-fn
  "wrap a ring handler with JWT check"
  [{:keys [pubkey-path
           is-revoked-fn
           jwt-check-fn
           jwt-max-lifetime-in-sec
           post-jwt-format-fn
           no-jwt-handler
           long-lived-jwt?]
    :or {jwt-max-lifetime-in-sec default-jwt-lifetime-in-sec
         is-revoked-fn no-revocation-strategy
         post-jwt-format-fn jwt->user-id
         no-jwt-handler forbid-no-jwt-header-strategy
         long-lived-jwt? no-long-lived-jwt}}]
  (let [pubkey (public-key pubkey-path)
        is-revoked-fn (if (fn? is-revoked-fn)
                        is-revoked-fn
                        (do (log/warn "is-revoked-fn is not a function! no-revocation-strategy is used.")
                            no-revocation-strategy))]
    (fn [handler]
      (let [no-jwt-fn (no-jwt-handler handler)]
        (fn [request]
          (if-let [raw-jwt (get-jwt request)]
            (if-let [jwt (decode raw-jwt pubkey)]
              (if-let [validation-errors
                       (validate-jwt jwt
                                     jwt-max-lifetime-in-sec
                                     jwt-check-fn
                                     long-lived-jwt?)]
                (log-and-refuse (pr-str jwt)
                                (format "(%s) %s"
                                        (or (jwt->user-id jwt) "Unkown User ID")
                                        (str/join ", " validation-errors)))
                (if (try (is-revoked-fn jwt)
                         (catch Exception e
                           (log/errorf "is-revoked-fn thrown an exception for: %s"
                                       (pr-str jwt))
                           (throw e)))
                  (log-and-refuse
                   (pr-str jwt)
                   (format "JWT revoked for %s"
                           (or (jwt->user-id jwt) "Unkown User ID")))
                  (handler (assoc request
                                  :identity (post-jwt-format-fn jwt)
                                  :jwt jwt))))
              (log-and-refuse (str "Bearer:" (pr-str raw-jwt))
                              "Invalid Authorization Header (couldn't decode the JWT)"))
            (no-jwt-fn request)))))))

;; compojure-api restructuring
;; add the :jwt-params in the route description
(defmethod meta/restructure-param :jwt-params [_ jwt-params acc]
  (let [schema  (meta/fnk-schema jwt-params)
        new-letks [jwt-params (meta/src-coerce! schema :jwt :string)]]
    (update-in acc [:letks] into new-letks)))

(defn sub-hash?
  "Return true if the 1st hashmap is a sub hashmap of the second.

  Take into account that if some value is a collection then
  only check if the corresponding value in the first hashmap
  is a sub-collection.

    ~~~clojure
    > (sub-hash? {:foo 1 :bar 2} {:foo 1 :bar 2 :baz 3})
    true
    > (sub-hash? {:foo 1 :bar #{2 3}} {:foo 1 :bar #{1 2 3 4} :baz 3})
    true
    > (sub-hash? {:foo 1 :bar 2} {:foo 1})
    false
    > (sub-hash? {:foo 1 :bar 2} {:foo 1 :bar 3})
    false
    ~~~
  "
  [m1 m2]
  (->> m1
       (map (fn [[k v1]]
              (let [v2 (get m2 k)]
                (if (map? v1)
                  (sub-hash? v1 v2)
                  (if (and (coll? v1) (coll? v2))
                    (set/subset? (set v1) (set v2))
                    (= v1 v2))))))
       (every? true?)))

(defn check-jwt-filter! [required jwt]
  (when (and (some? required)
             (every? #(not (sub-hash? % jwt)) required))
    (log/errorf "Unauthorized access attempt: %s"
                (pr-str
                 {:text ":jwt-filter params mismatch"
                  :required required
                  :identity jwt}))
    (ring.util.http-response/unauthorized!
     {:msg "You don't have the required credentials to access this route"})))

;;
;; add the :jwt-filter
;; to compojure api params
;; it should contains a set of hash-maps
;; example:
;;
;; (POST "/foo" [] :jwt-filter #{{:foo "bar"} {:foo "baz"}})
;;
;; Will be accepted only for people having a jwt such that the value
;; for :foo is either "bar" or "baz"
(defmethod compojure.api.meta/restructure-param :jwt-filter [_ authorized acc]
  (update-in acc
             [:lets]
             into
             ['_ `(check-jwt-filter! ~authorized (:jwt ~'+compojure-api-request+))]))

;; add the :identity in the route description
(defmethod meta/restructure-param :identity [_ identity acc]
  (let [schema  (meta/fnk-schema identity)
        new-letks [identity (meta/src-coerce! schema :identity :string)]]
    (update-in acc [:letks] into new-letks)))

(defn check-identity-filter! [required identity]
  (when (and (some? required)
             (every? #(not (sub-hash? % identity)) required))
    (log/errorf "Unauthorized access attempt: %s"
                (pr-str
                 {:text ":identity-filter params mismatch"
                  :required required
                  :identity identity}))
    (ring.util.http-response/unauthorized!
     {:msg "You don't have the required credentials to access this route"})))

;;
;; add the :identity-filter
;; to compojure api params
;; it should contains a set of hash-maps
;; example:
;;
;; (POST "/foo" [] :identity-filter #{{:foo "bar"} {:foo "baz"}})
;;
;; Will be accepted only for people having a jwt such that the value
;; for :foo is either "bar" or "baz"
(defmethod compojure.api.meta/restructure-param :identity-filter [_ authorized acc]
  (update-in acc
             [:lets]
             into
             ['_ `(check-identity-filter! ~authorized (:identity ~'+compojure-api-request+))]))

(defn to-scope-repr
  "Transform a textual scope as an internal representation to help
  check rules typically

  > \"foo\"
  {:path [\"foo\"]
   :access #{:read :write}}

  > \"foo/bar/baz:write\"
  {:path [\"foo\" \"bar\" \"baz\"]
   :access #{:write}}

  "
  [txt]
  (let [[path access] (str/split txt #":")]
    {:path (str/split path #"/")
     :access (case access
               "read"  #{:read}
               "write" #{:write}
               "rw"    #{:read :write}
               nil     #{:read :write}
               (ring.util.http-response/unauthorized!
                {:msg "bad access part in the scope, must be read or nothing."}))}))
(defn sub-list
  [req-list scope-path-list]
  (let [n (count scope-path-list)]
    (= (take n req-list) scope-path-list)))

(defn match-access
  [required-access access]
  (clojure.set/subset? required-access access))

(defn match-scope
  [required-scope scope]
  (and (match-access (:access required-scope) (:access scope))
       (sub-list (:path required-scope) (:path scope))))

(defn accepted-by-scopes
  "scopes should be strings.
  if none of the string contains a `/` nor a `:`.
  It works as is a subset of.

  :scopes #{\"foo\" \"bar\"}
  only people with scopes which are super sets of
  #{\"foo\" \"bar\"}
  will be allowed to use the route.

  scopes are considered as path with read/write access.
  so \"foo/bar/baz:read\" is a sub-scope of \"foo\"
  and of \"foo:read\".

  So the more precise rule of access is.
  All mandatory scopes must be sub-scopes of at least one user scopes.
  "
  [required scopes]
  (every? (fn [req-scope]
            (some #(match-scope req-scope %) scopes))
          required))

(defn check-scopes
  "This function might be useful to be used directly instead of just relying
  on the :scope."
  ([required scopes]
   (check-scopes required scopes {}))
  ([required scopes scope-aliases]
   (accepted-by-scopes (->> required (unalias-scopes scope-aliases) (map to-scope-repr))
                       (->> scopes (unalias-scopes scope-aliases) (map to-scope-repr)))))

(defn check-scopes! [required scopes]
  (when (and (some? required)
             (not (accepted-by-scopes required (map to-scope-repr scopes))))
    (log/errorf "Unauthorized access attempt: %s"
                (pr-str
                 {:text ":scopes params mismatch"
                  :required-scopes required
                  :identity-scopes scopes}))
    (ring.util.http-response/unauthorized!
     {:msg "You don't have the required credentials to access this route"})))

;; If you use scopes to generate your identities
;; this is helpful to filter routes by scopes
;;
;; (POST "/foo" [] :scopes #{"admin"} ...)
;;
;; (POST "/foo" [] :scopes #{"admin" "foo"}
;;   users must have admin and foo scopes)
(defmethod compojure.api.meta/restructure-param :scopes [_ authorized acc]
  (update-in acc
             [:lets]
             into
             ['_ `(check-scopes! (set (map to-scope-repr ~authorized))
                                 (set (get-in  ~'+compojure-api-request+
                                               [:identity :scopes])))]))
