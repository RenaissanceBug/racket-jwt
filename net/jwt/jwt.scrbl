#lang scribble/doc

@(require scribble/manual scribble/eval
          (for-label typed/racket/base
                     (only-in typed/json JSExpr)
                     racket/date
                     net/jwt
                     net/jwt/algorithms
                     net/jwt/base64))

@title[#:tag "jwt"]{JSON Web Token (JWT) and JSON Web Signature (JWS)}

@author[(author+email "Jordan Johnson" "jmj@fellowhuman.com")]

This library provides limited functionality for validating JSON Web Tokens
as specified in RFC 7519 @cite["RFC7519"]. At present, it supports encoding,
decoding, and verifying JWTs that use the Compact JWS Serialization, as
described in RFC 7515 @cite["RFC7515"].

@(define-syntax-rule (deftype name . parts)
   (defidform #:kind "type" name . parts))

@defmodule[net/jwt]{
  Provides functions for decoding and verifying tokens using the Compact JWS
  Serialization.
}

@(define jwt-eval (make-base-eval #:lang 'typed/racket/base))
@interaction-eval[#:eval jwt-eval (require net/jwt)]

@section[#:tag "jwt-representation"]{JWTs as Racket data}

@deftype[JSXHash]{
  Alias for @racket[(HashTable Symbol JSExpr)], for use in encoding and
  signing tokens.
}

@deftype[JWT]{
  Represents an unverified JWT. This is the result of decoding a JWT without
  checking the signature.
}

@deftype[VerifiedJWT]{
  Subtype of @racket[JWT], for which the JWT's signature has been verified.
}

@deftogether[(@defproc[(JWT? [x Any]) Boolean]
              @defproc[(VerifiedJWT? [x Any]) Boolean])]{
  Type predicates for @racket[JWT] and @racket[VerifiedJWT] data.
}

JWTs support the following accessors, which correspond to the JWT claim
names specified in RFC 7519 @cite["RFC7519"].

@defproc[(header [jwt JWT]) JSXHash]{
  Produces the JWT's header as a hashtable.
}

@defproc[(signature [jwt JWT]) String]{
  Produces the signature that was presented with the JWT.
}

@defproc[(issuer [jwt JWT]) (Option String)]{
  Produces an identifier for the entity that issued the JWT, or @racket[#f]
  if unspecified by the JWT.
}

@defproc[(subject [jwt JWT]) (Option String)]{
  Produces a string identifying the principal that is the subject of
  @racket[jwt], or @racket[#f] if unspecified by the JWT.
}

@defproc[(audiences [jwt JWT]) (Listof String)]{
  Produces a (possibly empty) list of identifiers for the intended
  audience(s) for this JWT.
}

@defproc[(expiration-date [jwt JWT]) (Option date)]{
  Produces the date/time (as a @racket[date] struct) after which
  @racket[jwt] should no longer be accepted, or @racket[#f] if @racket[jwt]
  carries no expiration date.
}

@defproc[(not-before [jwt JWT]) (Option date)]{
  Produces a date/time @italic{before} which @racket[jwt] should not be
  considered valid, or @racket[#f] if @racket[jwt] does not specify such a
  time.
}

@defproc[(issued-at [jwt JWT]) (Option date)]{
  Produces the date/time at which @racket[jwt] was produced by its issuer,
  or @racket[#f] if @racket[jwt] does not carry that information. 
}

@defproc[(jwt-id [jwt JWT]) (Option String)]{
  Produces the JWT ID for @racket[jwt], if one is present, or @racket[#f]
  otherwise.
}

@defproc[(claims-ref [jwt JWT]
                     [key Symbol])
         (Option JSExpr)]{
  Looks up @racket[key] in the claims presented by @racket[jwt], where
  @racket[key] is some symbol other than the ones defined by RFC 7515
  @cite["RFC7515"]; that is, some symbol other than @tt{iss}, @tt{sub},
  @tt{aud}, @tt{exp}, @tt{nbf}, @tt{iat}, and @tt{jti}. Produces @racket[#f]
  if @racket[key] is not present in the claims.
}

@; ------------------------------------------------------------------------

@section[#:tag "jwt-encoding"]{Encoding and signing JWTs}

@defproc[(encode/sign [algorithm String]
                      [secret String]
                      [#:extra-headers headers JSXHash (hasheq)]
                      [#:iss iss (Option String) #f]
                      [#:sub sub (Option String) #f]
                      [#:aud aud (U String (Listof String)) '()]
                      [#:exp exp (Option (U date Exact-Integer)) #f]
                      [#:nbf nbf (Option (U date Exact-Integer)) #f]
                      [#:iat iat (Option (U date Exact-Integer)) #f]
                      [#:jti jti (Option String) #f]
                      [#:other other JSXHash (hasheq)])
         String]{
  Encodes a JWT using the Compact JSON Serialization, signing it using the given
  secret and algorithm. Any data passed in @racket[headers] will become a part
  of the JWT's header (along with @racket[algorithm], for the @tt{alg} key); any
  data passed in @racket[other] will become a part of the payload; and all other
  keyword parameters are for passing values for the claims defined by the JWS
  RFC @cite["RFC7515"].

  Raises an @racket[exn:fail:unsupported-algorithm] if @racket[algorithm] is
  not supported.

  If a @racket[date] struct is given for the @racket[exp], @racket[nbf], or
  @racket[iat] parameter, it should represent a date after the epoch (1/1/1970);
  if it represents an earlier date, @racket[encode/sign] will ignore the field.

  Notably, @racket[encode/sign] does @italic{not} examine any of the key/value
  pairs in @racket[headers] or @racket[other], so it is possible to create
  invalid JWTs by providing invalid values for the header parameters and
  claims defined in the JWS RFC. Refer to the RFC if you need to customize
  your header parameters or use the @racket[other] parameter.

  The RFC prohibits duplicate claims with the same keyword; here, if any of
  the parameters @racket[iss], @racket[sub], @racket[aud], @racket[exp],
  @racket[nbf], @racket[iat], or @racket[jti] are provided, not @racket[#f]
  or @racket['()], and @bold{also} occur as keys in @racket[other], the keyword
  parameters will replace the entries in @racket[other].

  @examples[
  #:eval jwt-eval
  (define compact-jwt1
    (encode/sign "HS256" "swordfish"
                 #:extra-headers
                 (ann (hasheq 'kid "1234xbzsfgd54321") JSXHash)
                 #:iss "http://fellowhuman.com/"
                 #:sub "jmj"
                 #:aud "http://example.com/"
                 #:exp (+ (current-seconds) 86400)
                 #:iat (current-seconds)
                 #:other (ann (hasheq 'uid 12345) JSXHash)))
  compact-jwt1]
}

@defproc[(encode-jwt [#:headers headers JSXHash (hasheq)]
                     [#:iss iss (Option String) #f]
                     [#:sub sub (Option String) #f]
                     [#:aud aud (U String (Listof String)) '()]
                     [#:exp exp (Option (U date Exact-Integer)) #f]
                     [#:nbf nbf (Option (U date Exact-Integer)) #f]
                     [#:iat iat (Option (U date Exact-Integer)) #f]
                     [#:jti jti (Option String) #f]
                     [#:other other JSXHash (hasheq)])
         String]{
  Encodes an unsecured JWT as a string using the Compact JSON Serialization;
  the resulting string does @italic{not} contain a signature, and the @tt{alg}
  header will contain @racket["none"]. Equivalent to
  @racket[(encode/sign "none" "" ...)].

  @examples[
  #:eval jwt-eval
  (define compact-jwt2
    (encode-jwt #:iss "http://example.com/"
                #:sub "user12345"
                #:aud '("http://fellowhuman.com/"
                        "http://www.fellowhuman.com/")))
  compact-jwt2]
}

@; ------------------------------------------------------------------------

@section[#:tag "jwt-decoding"]{Decoding JWTs (Compact JSON Serialization)}

@defproc[(decode-jwt [jwt String])
         (Option JWT)]{
  Decodes the given Compact JWS Serialization, producing an unverified JWT.
  @examples[
  #:eval jwt-eval
  (define uv-jwt1
    (let ([decoded (decode-jwt compact-jwt1)])
      (if decoded decoded (error "couldn't decode"))))
  (JWT? uv-jwt1)
  (VerifiedJWT? uv-jwt1)
  (header uv-jwt1)
  (issuer uv-jwt1)
  (subject uv-jwt1)
  (expiration-date uv-jwt1)
  (audiences uv-jwt1)
  (not-before uv-jwt1)
  (define uv-jwt2
    (let ([decoded (decode-jwt compact-jwt2)])
      (if decoded decoded (error "couldn't decode"))))
  (issuer uv-jwt2)
  (audiences uv-jwt2)
  ]
}

@defproc[(verify-jwt [jwt JWT]
                     [algorithm String]
                     [secret String]
                     [#:aud audience (Option String) #f]
                     [#:iss expected-issuer (Option String) #f]
                     [#:clock-skew skew Exact-Nonnegative-Integer 30])
         (Option VerifiedJWT)]{
  Checks a decoded JWT to verify that the signature can be verified using
  the given algorithm and secret.

  If @racket[audience] is not @racket[#f] and the JWT has an @tt{aud} field,
  checks that @racket[audience] matches one of the JWT's audiences. If
  @racket[expected-issuer] is not @racket[#f] and the JWT has an @tt{iss}
  field, checks that the JWT's issuer matches @racket[expected-issuer].
  Also checks the current time against the JWT's @tt{exp} and @tt{nbf} fields,
  if those are present. @racket[skew] specifies a tolerance for those checks;
  a token will be accepted up to @racket[skew] seconds after its expiration,
  and up to @racket[skew] seconds before its @tt{nbf} time.

  This procedure produces @racket[#f] if for any reason the JWT can't be
  verified. This includes when the given algorithm @bold{or} the JWT's algorithm
  is @racket["none"]; in that circumstance the JWT is unsecured and can't
  truthfully be said to be verified.
  @examples[
  #:eval jwt-eval
  (verify-jwt uv-jwt1 "HS256" "wrong password")
  (verify-jwt uv-jwt1 "HS256" "swordfish" #:aud "wrong audience")
  (verify-jwt uv-jwt1 "HS256" "swordfish" #:iss "wrong issuer")
  (define v-jwt1 (verify-jwt uv-jwt1 "HS256" "swordfish"
                             #:aud "http://example.com/"
                             #:iss "http://fellowhuman.com/"))
  (JWT? v-jwt1)
  (VerifiedJWT? v-jwt1)
  (and v-jwt1 (subject v-jwt1))
  ]

  Note that the @tt{aud} and @tt{iss} checks won't be performed unless the
  @racket[#:aud] and @racket[#:iss] keyword arguments are present, although
  the JWT will pass verification nonetheless:
  @examples[
  #:eval jwt-eval
  (equal? (verify-jwt uv-jwt1 "HS256" "swordfish")
          v-jwt1)
  ]
}

@defproc[(decode/verify [jwt String]
                        [algorithm String]
                        [secret String]
                        [#:aud audience (Option String) #f]
                        [#:iss expected-issuer (Option String) #f]
                        [#:clock-skew skew Exact-Nonnegative-Integer 30])
         (Option VerifiedJWT)]{
  Decodes and verifies a JWS compact serialization. Checks the signature using
  @racket[algorithm], and produces a verified JWT if possible. The keyword
  parameters are interpreted as in @racket[verify-jwt], and like that function,
  this one produces @racket[#f] if the JWT fails decoding or verification for
  any reason (including when the JWT's algorithm is @racket["none"]).

  @examples[
  #:eval jwt-eval
  (equal? (decode/verify compact-jwt1 "HS256" "swordfish")
          v-jwt1)
  ]
}

@; ------------------------------------------------------------------------

@section[#:tag "jwt-algorithms"]{Algorithms: Signing and Verifying}

@defmodule[net/jwt/algorithms]{
  Provides functions related to signing JWTs and verifying JWT signatures.
  Currently the only supported algorithms are HMAC-SHA256, via @racket[hs256],
  and the no-op algorithm @racket[none] (see RFC7515 Appendix A.5
  @cite["RFC7515"]). Any additional algorithms that may be implemented in future
  will be accessible via a @racket[SigningFunction] defined in this module.

  All of the names listed for this module are also exported by
  @racket[net/jwt].
}

@defstruct*[(exn:fail:unsupported-algorithm exn:fail) ()]{
  Exception indicating that encoding cannot proceed because the requested
  algorithm is not supported.
}

@deftype[SigningFunction]{
  Represents a signing function, which takes two strings (a secret and a
  message) and produces a byte string representing a message signature.
}

@defproc[(none [secret String] [message String])
         Bytes]{
  A no-op @racket[SigningFunction].
}

@defproc[(hs256 [secret String] [message String])
         Bytes]{
  A @racket[SigningFunction] for the HMAC-SHA256 algorithm.
}

@defproc[(ok-signature? [sig String]
                        [secret String]
                        [message String]
                        [sign SigningFunction hs256])
         Boolean]{
  Produces true iff the given @racket[message] produces the given signature
  @racket[sig] when signed with @racket[sign] using the given @racket[secret].
}

@defproc[(supported? [algorithm-name String]) Boolean]{
  Produces true iff the algorithm with the given @tt{alg} Header Parameter name,
  defined in RFC 7518 @cite["RFC7518"], is supported. Currently only
  @racket["HS256"] is supported.
}

@defproc[(signing-function [algorithm-name String]) (Option SigningFunction)]{
  Produces a @racket[SigningFunction] if @racket[algorithm-name] (again, an
  RFC 7518 @cite["RFC7518"] Header Parameter name) is supported, @racket[#f]
  otherwise.
}

@; ------------------------------------------------------------------------

@section[#:tag "jwt-base64"]{Base-64 URL Encoding}

@defmodule[net/jwt/base64]{
  Provides functions for the URL-safe base-64 encoding/decoding required by
  RFC 7515 @cite["RFC7515"], as described in Section 5 of RFC 4648
  @cite["RFC4648"]. These functions are used internally and by
  @racket[net/jwt/algorithms], but are not likely necessary for client code
  using the @racket[net/jwt] library.
}

@defproc[(base64-url-encode [bs Bytes]) String]{
  Base64-URL-encodes the byte string, differing from @racket[net/base64]'s
  encoding as follows:
  @itemlist[@item{"-" and "+" are replaced by "_" and "/", respectively,}
            @item{whitespace is removed, and}
            @item{the end is padded with "=" if needed.}]
}

@defproc[(base64-url-decode [s String]) (Option Bytes)]{
  Decodes a string @racket[s] that was encoded by a process equivalent to
  @racket[base64-url-encode]. Produces @racket[#f] if @racket[s] is not a
  valid encoding.
}

@; ------------------------------------------------------------------------

@(bibliography
  (bib-entry #:key "RFC4648"
             #:title "The Base16, Base32, and Base64 Data Encodings"
             #:author "S. Josefsson"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc4648"
             #:date "1987")
  (bib-entry #:key "RFC7515"
             #:title "JSON Web Signature (JWS)"
             #:author "M. Jones, J. Bradley, and N. Sakimura"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7515"
             #:date "1987")
  (bib-entry #:key "RFC7516"
             #:title "JSON Web Encryption (JWE)"
             #:author "M. Jones and J. Hildebrand"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7516"
             #:date "1987")
  (bib-entry #:key "RFC7518"
             #:title "JSON Web Algorithms (JWA)"
             #:author "M. Jones"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7518"
             #:date "1987")
  (bib-entry #:key "RFC7519"
             #:title "JSON Web Token (JWT)"
             #:author "M. Jones, J. Bradley, and N. Sakimura"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7519"
             #:date "1987")

  #;(bib-entry #:key "RFC"
             #:title ""
             #:author ""
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc____.html"
             #:date "1987")
  )
