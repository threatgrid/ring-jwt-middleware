(ns ring-jwt-middleware.result
  (:require [schema.core :as s]
            [schema-tools.core :as st]))

(s/defschema JwtError
  (st/open-schema
    {:error s/Keyword
     :error_description s/Str}))

(s/defschema Result
  ;; A result is similar to the Either in Haskell
  ;; It represent either a value or an error
  {(s/optional-key :result) s/Any
   (s/optional-key :jwt-error) JwtError})

(s/defn ->pure :- Result
  "given a value build a result containing this value"
  [v]
  {:result v})

(s/defn ->err :- Result
  "build a Result that contain an error."
  [err-code :- s/Keyword
   err-description :- s/Str
   error-metas :- {s/Any s/Any}]
  {:jwt-error
   (into error-metas
         {:error err-code
          :error_description err-description})})

(s/defn error? :- s/Bool
  "return true if the given result is an Error"
  [m :- Result]
  (boolean (get m :jwt-error)))

(s/defn success? :- s/Bool
  "return true if the given result is not an Error"
  [m :- Result]
  (not (error? m)))

(s/defn <-result :- s/Any
  "Either returns the value or the error contained in the Result"
  [result :- Result]
  (if (error? result)
    result
    (:result result)))
