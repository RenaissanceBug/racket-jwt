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
as specified in RFC 7519 @cite["RFC7519"]. At present, it supports only
decoding and verifying JWTs that use the Compact JWS Serialization, as
described in RFC 7515 @cite["RFC7515"].

@(define-syntax-rule (deftype name . parts)
   (defidform #:kind "type" name . parts))

@defmodule[net/jwt]{
  Provides functions for decoding and verifying tokens using the Compact JWS
  Serialization.
}

@section[#:tag "jwt-representation"]{JWTs as Racket data}

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

@defproc[(header [jwt JWT]) (HashTable Symbol JSExpr)]{
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

@defproc[(special-claims-ref [jwt JWT]
                             [key Symbol])
         (Option JSExpr)]{
  Looks up @racket[key] in the claims presented by @racket[jwt], where
  @racket[key] is some symbol other than the ones defined by RFC 7515
  @cite["RFC7515"]; that is, some symbol other than @tt{iss}, @tt{sub},
  @tt{aud}, @tt{exp}, @tt{nbf}, @tt{iat}, and @tt{jti}. Produces @racket[#f]
  if @racket[key] is not present in the claims.
}

@; ------------------------------------------------------------------------

@section[#:tag "jwt-decoding"]{Decoding JWTs (Compact JSON Serialization)}

@defproc[(decode-jwt [jwt String])
         (Option JWT)]{
  Decodes the given Compact JWS Serialization, producing an unverified JWT.
}

@defproc[(verify-jwt [jwt JWT]
                     [secret String]
                     [audience (Option String) #f])
         (Option VerifiedJWT)]{
  Checks a decoded JWT to verify that the signature can be verified using
  the given secret and viewed by the given audience.
}

@defproc[(decode/verify [jwt String]
                        [secret String]
                        [audience (Option String) #f])
         (Option VerifiedJWT)]{
  Decodes and verifies a JWS compact serialization. Checks the signature, and
  if @racket[audience] is not @racket[#f] and the JWT has an @tt{aud} field,
  checks that the given audience matches one of the JWT's audiences.
  Produces #f if for any reason the JWT can't be validated.
}

@; ------------------------------------------------------------------------

@defmodule[net/jwt/algorithms]{
  Provides functions related to signing JWTs and verifying JWT signatures.
  Currently the only supported algorithm is HMAC-SHA256, via @racket[hs256].
  Any additional algorithms that may be implemented in future will be
  accessible via a @racket[SigningFunction] defined in this module.
}

@deftype[SigningFunction]{
  Represents a signing function, which takes two strings (a secret and a
  message) and produces a byte string representing a message signature.
}

@defproc[(hs256 [secret String]
                [message String])
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
  RFC 7515 @cite["RFC7515"]. These functions are used internally and by
  @racket[net/jwt/algorithms], but are not likely necessary for client code
  using the @racket[net/jwt] library.
}

@defproc[(base64-url-encode [bs Bytes]) String]{
  Encodes the byte string using base64, replacing "-" and "+" with "_" and "/",
  respectively, and padding the end with "=" if needed.
}

@defproc[(base64-url-decode [s String]) (Option Bytes)]{
  Decodes a string @racket[s] that was encoded by the a process equivalent to
  @racket[base64-url-encode]. Produces @racket[#f] if @racket[s] is not a
  valid encoding.
}

@; ------------------------------------------------------------------------

@(bibliography
  (bib-entry #:key "RFC7515"
             #:title "JSON Web Signature (JWS)"
             #:author "M. Jones, J. Bradley, and N. Sakimura"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7515"
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
  (bib-entry #:key "RFC7516"
             #:title "JSON Web Encryption (JWE)"
             #:author "M. Jones and J. Hildebrand"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7516"
             #:date "1987")

  #;(bib-entry #:key "RFC"
             #:title ""
             #:author ""
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc____.html"
             #:date "1987")
  )
