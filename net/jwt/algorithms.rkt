#lang typed/racket/base

(require (only-in sha hmac-sha256)
         "base64.rkt")

(require/typed sha
               [#:opaque Lib-SHA256 sha256?])

(define-type SHA256 (Intersection Lib-SHA256 Bytes))

(require/typed sha
               [hmac-sha256
                (-> Bytes Bytes SHA256)])

(provide (struct-out exn:fail:unsupported-algorithm)
         current-string-converter
         SigningFunction
         ok-signature?
         none hs256
         supported?
         signing-function
         SHA256)

(: current-string-converter (Parameterof (-> String Bytes)))
(define current-string-converter (make-parameter string->bytes/utf-8))

(define-type SorB (U String Bytes))

(define-type SigningFunction (SorB SorB -> Bytes))

(struct exn:fail:unsupported-algorithm exn:fail [])

(: ok-signature? (->* (String SorB SorB) (SigningFunction) Boolean))
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
(define (hs256 secret message)
  (hmac-sha256 (as-bytes secret) (as-bytes message)))

(: as-bytes ((U String Bytes) -> Bytes))
(define (as-bytes s/b) (if (bytes? s/b) s/b ((current-string-converter) s/b)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Metadata for users

(: supported-algorithms (Listof (U Symbol String)))
(define supported-algorithms '("none" none "HS256" HS256))

(: supported? (String -> Boolean))
(define (supported? alg-name) (and (member alg-name supported-algorithms) #t))

(: signing-functions (Listof SigningFunction))
(define signing-functions (list none hs256))

(: algorithm-table (HashTable (U Symbol String) SigningFunction))
(define algorithm-table
  (for/hash : (HashTable (U Symbol String) SigningFunction)
    ([name supported-algorithms]
     [fn signing-functions])
    (values name fn)))

(: signing-function ((U Symbol String) -> (Option SigningFunction)))
(define (signing-function algorithm-name)
  (hash-ref algorithm-table algorithm-name (lambda () #f)))

