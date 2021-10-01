(ns ring-jwt-middleware.schemas
  "Schemas used"
  (:require
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
  "Initialized internal Configuration"
  (st/merge
   {:allow-unauthenticated-access?
    (describe s/Bool
              "Set this to true to allow unauthenticated requests")
    :current-epoch
    (describe (s/=> s/Num)
              "A function returning the current time in epoch format")
    :is-revoked-fn
    (describe (s/=> s/Bool JWTClaims)
              "A function that take a JWT and return true if it is revoked")
    :jwt-max-lifetime-in-sec
    (describe s/Num
              "Maximal number of second a JWT does not expires")
    :post-jwt-format-fn
    (describe (s/=> s/Any JWTClaims)
              "A function taking the JWT claims and building an Identity object suitable for your needs")
    :error-handler
    (describe (s/=> s/Any)
              "A function that given a JWTError returns a ring response.")}
   (st/optional-keys
    {:pubkey-fn (describe (s/=> s/Any s/Str)
                          "A function returning a public key (takes precedence over pubkey-path)")
     :pubkey-path (describe s/Str
                            "The path to find the public key that will be used to check the JWT signature")
     :jwt-check-fn
     (describe (s/=> s/Bool JWT JWTClaims)
               (str "A function that take a JWT, claims and return a sequence of string containing errors."
                    "The check is considered successful if this function returns nil, or a sequence containing only nil values."))})))


(s/defschema UserConfig
  "Middleware Configuration"
  (st/optional-keys Config))
