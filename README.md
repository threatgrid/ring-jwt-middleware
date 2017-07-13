- [ring-jwt-middleware](#sec-1)
  - [Features](#sec-1-1)
  - [Usage](#sec-1-2)
    - [Middleware & options](#sec-1-2-1)
    - [JWT Format](#sec-1-2-2)
    - [Compojure-api support](#sec-1-2-3)
  - [Generating Certs and a Token](#sec-1-3)
  - [License](#sec-1-4)

# ring-jwt-middleware<a id="sec-1"></a>

A simple middleware to authenticate users using JWT (JSON Web Tokens) currently, only RS256 is supported.

## Features<a id="sec-1-1"></a>

-   RS256 signing
-   uses JWT claims
-   JWT lifetime & Expiration support
-   custom additional validation through a user provided fn
-   custom revokation check through a user provided fn

## Usage<a id="sec-1-2"></a>

### Middleware & options<a id="sec-1-2-1"></a>

Use `wrap-jwt-auth-fn` to create an instance of the middleware, wrap your routes with it:

```clojure
(api (api-data url-prefix)
        (middleware [(wrap-jwt-auth-fn {:pubkey-path jwt-cert-path
                                        :is-revoked-fn revoked?
                                        :jwt-max-lifetime-in-sec jwt-lifetime
                                        :jwt-check-fn check-jwt-fields})]
                    (routes service url-prefix)))
```

| Option                     | Description                                                               | Default |
|-------------------------- |------------------------------------------------------------------------- |------- |
| `:pubkey-path`             | the path to your public key                                               | nil     |
| `:jwt-max-lifetime-in-sec` | set a max lifetime for JWTs to expire                                     | 86400   |
| `:is-revoked-fn`           | a fn to checks if a given JWT should be revoked, should return bool       | nil     |
| `:jwt-check-fn`            | a fn to custom check the JWT, should return a vec of error strings or nil | nil     |

If the request contains a valid JWT auth header, the JWT is merged with the ring request under a `:jwt` key, there is also an `:user-identifier-key` for easy access, else the request is terminated with `unauthorized` HTTP response.

### JWT Format<a id="sec-1-2-2"></a>

Currently this middleware only supportes JWTs using claims registered in the IANA "JSON Web Token Claims", which means you need to generate JWTs using most of the claims described here: <https://tools.ietf.org/html/rfc7519#section-4> namely `jti, exp, iat, nbf sub`

| Claim  | Description                                                          | Format |
|------ |-------------------------------------------------------------------- |------ |
| `:exp` | Expiration time: <https://tools.ietf.org/html/rfc7519#section-4.1.4> | Long   |
| `:iat` | Issued At: <https://tools.ietf.org/html/rfc7519#section-4.1.6>       | Long   |
| `:jti` | JWT ID: <https://tools.ietf.org/html/rfc7519#section-4.1.7>          | String |
| `:nbf` | Not Before: <https://tools.ietf.org/html/rfc7519#section-4.1.5>      | Long   |
| `:sub` | Subject: <https://tools.ietf.org/html/rfc7519#section-4.1.2>         | String |

here is a sample token:

```clojure
{:jti "r3e03ac6e-8d09-4d5e-8598-30e51a26cd2a"
 :exp 1499419023
 :iat 1498814223
 :nbf 1498813923
 :sub "foo@bar.com"

 :user-identifier "foo@bar.com"
 :user_id "f0010924-e1bc-4b03-b600-89c6cf52757c"}
```

### Compojure-api support<a id="sec-1-2-3"></a>

You can check the JWT from the req with schemas and destructure it like the rest of the HTTP query, use `:jwt-params`.

```clojure
(POST "/test" []
      :return {:foo s/Str
               :user_id s/Str}
               :body-params  [{lorem :- s/Str ""}]
               :summary "Does nothing"
               :jwt-params [foo :- s/Str
                            user_id :- s/Str
                            exp :- s/Num
                            {boolean_field :- s/Bool "false"}]                            
  {:status 200
   :body {:foo foo
          :user_id user_id}})
```

## Generating Certs and a Token<a id="sec-1-3"></a>

A simple script is available to generate certs for signing the tokens: `> ./resources/cert/gen_cert.sh` some dummy ones are already available for easy testing.

-   use `ring-jwt-middleware.core-test/make-jwt` to generate a sample token from a map

## License<a id="sec-1-4"></a>

Copyright © 2015-2016 Cisco Systems Eclipse Public License v1.0
