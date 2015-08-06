#lang typed/racket/base

(require typed/rackunit
         net/jwt/algorithms
         net/jwt/base64)

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
