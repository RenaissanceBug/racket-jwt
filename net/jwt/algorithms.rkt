#lang typed/racket/base

(require (only-in grommet/crypto/hmac hmac-sha256)
         "base64.rkt")

(provide (struct-out exn:fail:unsupported-algorithm)
         SigningFunction
         ok-signature?
         none hs256
         supported?
         signing-function)

(define-type SigningFunction (String String -> Bytes))

(struct exn:fail:unsupported-algorithm exn:fail [])

(: ok-signature? (->* (String String String) (SigningFunction) Boolean))
(define (ok-signature? sig secret message [sign hs256])
  (equal? (sign secret message) (base64-url-decode sig)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Signing functions.

#| To implement another signing function:
1. Add the definition here.
2. Add its name to supported-algorithms, below.
3. Add it to signing-functions, below
|#

(: none SigningFunction)
(define (none secret message) #"")

(: hs256 SigningFunction)
(define (hs256 secret message) (hmac-sha256 secret message))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Metadata for users

(: supported-algorithms (Listof String))
(define supported-algorithms '("none" "HS256"))

(: supported? (String -> Boolean))
(define (supported? alg-name) (and (member alg-name supported-algorithms) #t))

(: signing-functions (Listof SigningFunction))
(define signing-functions (list none hs256))

(: algorithm-table (HashTable String SigningFunction))
(define algorithm-table
  (for/hash : (HashTable String SigningFunction)
    ([name supported-algorithms]
     [fn signing-functions])
    (values name fn)))

(: signing-function (String -> (Option SigningFunction)))
(define (signing-function algorithm-name)
  (hash-ref algorithm-table algorithm-name (lambda () #f)))

