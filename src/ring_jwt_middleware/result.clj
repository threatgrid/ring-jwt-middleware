(ns ring-jwt-middleware.result
  (:require [schema.core :as s]
            [schema-tools.core :as st]))

(s/defschema Result
  {(s/optional-key :result) s/Any
   (s/optional-key :jwt-error)
   (st/open-schema
    {:error s/Keyword
     :error_description s/Str})})

(s/defn ->pure :- Result
  [v]
  {:result v})

(s/defn ->err :- Result
  [err-code :- s/Keyword
   err-description :- s/Str
   error-metas :- {s/Any s/Any}]
  {:jwt-error
   (into error-metas
         {:error err-code
          :error_description err-description})})

(s/defn error? :- s/Bool
  [m :- Result]
  (boolean (get m :jwt-error)))

(s/defn success? :- s/Bool
  [m :- Result]
  (not (error? m)))

(s/defn <-result :- s/Any
  [result :- Result]
  (if (error? result)
    result
    (:result result)))
