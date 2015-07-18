#lang typed/racket

(require typed/json
         net/jwt/encode-decode
         net/jwt/structs
         )

(provide JWT JWT?
         VerifiedJWT VerifiedJWT?
         header
         signature issuer subject audiences
         expiration-date not-before issued-at
         jwt-id
         special-claims-ref
         decode-jwt verify-jwt decode/verify)

(: JWT? (Any -> Boolean : JWT))
(define JWT? decoded-jwt?)

(: VerifiedJWT? (Any -> Boolean : VerifiedJWT))
(define VerifiedJWT? verified-jwt?)

(: header (JWT -> (HashTable Symbol JSExpr)))
(define header decoded-jwt-header)

(: signature (JWT -> String))
(define signature decoded-jwt-signature)

(: issuer (JWT -> (Option String)))
(define issuer (compose JWTClaimsSet-iss decoded-jwt-claims))

(: subject (JWT -> (Option String)))
(define subject (compose JWTClaimsSet-sub decoded-jwt-claims))

(: audiences (JWT -> (Listof String)))
(define audiences (compose JWTClaimsSet-aud decoded-jwt-claims))

(: expiration-date (JWT -> (Option date)))
(define expiration-date (compose JWTClaimsSet-exp decoded-jwt-claims))

(: not-before (JWT -> (Option date)))
(define not-before (compose JWTClaimsSet-nbf decoded-jwt-claims))

(: issued-at (JWT -> (Option date)))
(define issued-at (compose JWTClaimsSet-iat decoded-jwt-claims))

(: jwt-id (JWT -> (Option String)))
(define jwt-id (compose JWTClaimsSet-jti decoded-jwt-claims))

(: special-claims-ref (JWT Symbol -> (Option JSExpr)))
(define (special-claims-ref jwt key)
  (hash-ref (JWTClaimsSet-other (decoded-jwt-claims jwt))
            key
            (lambda _ #f)))
