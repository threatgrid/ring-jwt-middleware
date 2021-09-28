(ns ring-jwt-middleware.result
  "This ns provide a set of helpers to handle an abstraction similar to Either in Haskell

  The main goal is to provide a mechanism similar to the exceptions but pure without Java Exceptions.

  A function that return a `Result` means the function returned either a successful result or an error with a
  common error structure (`JwtError`).

  The `let-either` macro provides a monadic syntax.
  Mainly:

  ```
  (let-either [result-value-1 (fn-returning-a-result-1 ,,,)
               result-value-2 (fn-returning-a-result-2 ,,,)
               ,,,]
    ,,,)
  ```

  if `fn-returning-a-result-1` return an error then we will not execute the rest of the let-either.
  And return the full `result`.
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

(defmacro let-either
  "The let-either macro can be used to handle cascading results that
  can depend on preceding values.
  If one of the function fail, we return the failed result.
  If all functions are successful we return the content of the
  body."
  {:special-form true
   :forms '[(let-either [bindings*] exprs*)]
   :style/indent 1}
  [bindings & body]
  (assert (vector? bindings) "let-either requires a vector for its bindings")
  (if (empty? bindings)
    `(do ~@body)
    (if (even? (count bindings))
      `(let [result# ~(nth bindings 1)]
         (if (error? result#)
           result#
           (let [~(nth bindings 0) (<-result result#)]
             (let-either ~(subvec bindings 2) ~@body))))
      (throw (IllegalArgumentException.
              "an even number of arguments is expected in the bindings")))))
