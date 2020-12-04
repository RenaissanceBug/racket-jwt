#lang typed/racket/base

(require typed/rackunit
         net/jwt/algorithms
         net/jwt/base64
         )

(require/typed crypto
  [#:opaque Pk-Key pk-key?]
  [#:opaque Crypto-Factory crypto-factory?]
  [generate-private-key (-> Symbol (List Any) Pk-Key)]
  [crypto-factories (Parameter (List Crypto-Factory))]
  [digest (-> Symbol Bytes Bytes)]
  [pk-key->datum (-> Pk-Key Symbol Bytes)]
  [pk-key->public-only-key (-> Pk-Key Pk-Key)]
  [pk-verify (-> Pk-Key Bytes Bytes #:pad Symbol #:digest Symbol Boolean)]
  [pk-sign (-> Pk-Key Bytes #:pad Symbol #:digest Symbol Bytes)])

(require/typed crypto/libcrypto
  [libcrypto-factory Crypto-Factory])

(define sig1 "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ")
(define secret1 "secret")
(define msg1
  (string-append
   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
   "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9"))

;; Test default HS256 signature verification.
(check-equal? (hs256 secret1 msg1) (base64-url-decode sig1))
(check-true (ok-signature? sig1 secret1 msg1))
(check-false (ok-signature? sig1 "wrong" msg1))

;; no-op algorithm:
(check-equal? (none secret1 msg1) #"")
(check-equal? (none "foo" "bar") #"")

(check-true (supported? "none"))
(check-true (supported? "HS256"))
(check-false (supported? "HS257"))

;; RS algorithms

(parameterize ((crypto-factories (list libcrypto-factory)))
  (define key-pair 
    (generate-private-key 'rsa '((nbits 2048))))
  (define public-key (pk-key->public-only-key key-pair))
  (check-true (supported? "RS256"))
  (check-true (pk-verify 
               public-key
               (digest 'sha256 (string->bytes/latin-1 msg1))
               (rs256 (pk-key->datum key-pair 'PrivateKeyInfo) (string->bytes/latin-1 msg1))
               #:digest 'sha256
               #:pad 'pkcs1-v1.5)))
             
                       

