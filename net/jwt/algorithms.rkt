#lang typed/racket/base

(require "base64.rkt")

(require/typed crypto
  [#:opaque Pk-Key pk-key?]
  [#:opaque Crypto-Factory crypto-factory?]
  [crypto-factories (Parameter (List Crypto-Factory))]
  [datum->pk-key (-> Bytes Symbol Crypto-Factory Pk-Key)]
  [digest (-> Symbol Bytes Bytes)]
  [pk-sign (-> Pk-Key Bytes #:pad Symbol #:digest Symbol Bytes)])

(require/typed crypto/libcrypto
  [libcrypto-factory Crypto-Factory])

(require/typed sha
               [#:opaque Lib-SHA256 sha256?]
               [#:opaque Lib-SHA384 sha384?]
               [#:opaque Lib-SHA512 sha512?])

;; XXX is there a better way to obtain a type based on sha256? that
;; documents that if (sha256? x) then (bytes? x) as well?
(define-type SHA256 (Intersection Lib-SHA256 Bytes))
(define-type SHA384 (Intersection Lib-SHA384 Bytes))
(define-type SHA512 (Intersection Lib-SHA512 Bytes))

(require/typed sha
               [hmac-sha256 (-> Bytes Bytes SHA256)]
               [hmac-sha384 (-> Bytes Bytes SHA384)]
               [hmac-sha512 (-> Bytes Bytes SHA512)])

(provide (struct-out exn:fail:unsupported-algorithm)
         current-string-converter
         SigningFunction
         ok-signature?
         none hs256 hs384 hs512 rs256
         rs256 rs384 rs512
         supported?
         signing-function
         SHA256 SHA384 SHA512)

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
1. Add the definition here, specified as type SigningFunction.
2. Add its name to supported-algorithms, below.
3. Add it to signing-functions, below
|#

(: none SigningFunction)
(define (none secret message) #"")

(: hs256 SigningFunction)
(define (hs256 secret message) (hmac-sha256 (as-bytes secret) (as-bytes message)))

(: hs384 SigningFunction)
(define (hs384 secret message) (hmac-sha384 (as-bytes secret) (as-bytes message)))

(: hs512 SigningFunction)
(define (hs512 secret message) (hmac-sha512 (as-bytes secret) (as-bytes message)))

(: rs256 SigningFunction)
(define (rs256 secret message)
  (rsa-sign 'sha256 secret message))

(: rs384 SigningFunction)
(define (rs384 secret message)
  (rsa-sign 'sha384 secret message))

(: rs512 SigningFunction)
(define (rs512 secret message)
  (rsa-sign 'sha512 secret message))

(: rsa-sign (-> Symbol SorB SorB Bytes))
(define (rsa-sign digester secret message)
  (parameterize ((crypto-factories (list libcrypto-factory)))
    (pk-sign
     (datum->pk-key (as-bytes secret) 'PrivateKeyInfo libcrypto-factory)
     (digest digester (as-bytes message))
     #:pad 'pkcs1-v1.5
     #:digest digester)))

(: as-bytes (SorB -> Bytes))
(define (as-bytes s/b) (if (bytes? s/b) s/b ((current-string-converter) s/b)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Metadata for users

;; All algorithm names listed below should be strings trimmed of whitespace
;; containing only the name of one of the "alg" header parameter values from
;; the JWA RFC Section 3.1.
(: supported-algorithms (Listof String))
(define supported-algorithms '("none" "HS256" "HS384" "HS512" "RS256" "RS384" "RS512"))

(: supported? ((U Symbol String) -> Boolean))
(define (supported? alg-name)
  (define alg-name/s (alg-as-string alg-name))
  (for/or ([alg (in-list supported-algorithms)])
    (string-ci=? alg alg-name/s)))

(: signing-functions (Listof SigningFunction))
(define signing-functions (list none hs256 hs384 hs512 rs256 rs384 rs512))

(: algorithm-table (HashTable (U Symbol String) SigningFunction))
(define algorithm-table
  (for/hash : (HashTable (U Symbol String) SigningFunction)
    ([name supported-algorithms]
     [fn signing-functions])
    (values name fn)))

(: signing-function ((U Symbol String) -> (Option SigningFunction)))
(define (signing-function algorithm-name)
  (hash-ref algorithm-table (alg-as-string algorithm-name) (λ () #f)))

(: alg-as-string ((U Symbol String) -> String))
(define (alg-as-string alg)
  (if (symbol? alg) (symbol->string alg) alg))
