#lang typed/racket/base

(require (only-in grommet/crypto/hmac hmac-sha256)
         "base64.rkt")

(provide SigningFunction
         ok-signature?
         hs256
         supported?
         signing-function)

(define-type SigningFunction (String String -> Bytes))

(: ok-signature? (->* (String String String) (SigningFunction) Boolean))
(define (ok-signature? sig secret message [sign hs256])
  (equal? (sign secret message) (base64-url-decode sig)))

(: hs256 SigningFunction)
(define (hs256 secret message) (hmac-sha256 secret message))

(module+ test
  (require typed/rackunit
           "base64.rkt")
  (check-true
   (ok-signature? "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
                  "secret"
                  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Metadata for users

(: supported-algorithms (Listof String))
(define supported-algorithms '("HS256"))

(: supported? (String -> Boolean))
(define (supported? alg-name) (and (member alg-name supported-algorithms) #t))

(: signing-functions (Listof SigningFunction))
(define signing-functions (list hs256))

(: algorithm-table (HashTable String SigningFunction))
(define algorithm-table
  (for/hash : (HashTable String SigningFunction)
    ([name supported-algorithms]
     [fn signing-functions])
    (values name fn)))

(: signing-function (String -> (Option SigningFunction)))
(define (signing-function algorithm-name)
  (hash-ref algorithm-table algorithm-name (lambda () #f)))

