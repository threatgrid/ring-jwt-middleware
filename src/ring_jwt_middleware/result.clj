(ns ring-jwt-middleware.result
  "This ns provide a set of helpers to handle an abstraction similar to Either in Haskell

  The main goal is to provide a mechanism similar to the exceptions but pure without Java Exceptions.

  A function that return a `Result` means the function returned either a successful result or an error with a
  common error structure (`JwtError`).

  As the code is quite minimal I didn't introduce a `let-either` macro to simulate a monadic notation.
  And instead manage the dispatch manually via:

  ```
  (let [x (fn-returning-a-result ,,,)]
    (if (error? x)
       x
       (let [return-value (<-result x)]
         ,,,,)))
  ```

  Which while a bit cumbersome is probably easier to understand.
  And also for some retro-compatibily reason this is not _the_ right monadic pattern
  (we should use (<-result x) in case of error)

  Whatever, this is still a pretty usefule abstraction even without going very deep.
  "
  (:require [schema.core :as s]
            [schema-tools.core :as st]))

(s/defschema JwtError
  (st/open-schema
    {:error s/Keyword
     :error_description s/Str}))

(s/defn result-of
  "Build a schema representing a result expecting succesful result with schema `s`"
  [s]
  {(s/optional-key :result) s
   (s/optional-key :jwt-error) JwtError})

(s/defschema Result
  ;; A result is similar to the Either in Haskell
  ;; It represent either a value or an error
  (result-of s/Any))

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
