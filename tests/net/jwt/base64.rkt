#lang typed/racket

(require net/jwt/base64 typed/rackunit)

(check-equal? (base64-url-encode (list->bytes (list 3 236 255 224 193)))
              "A-z_4ME") ;; From Appendix C of RFC7515
(check-equal? (base64-url-encode #"") "")
(check-equal? (base64-url-decode "") #"")
(check-equal? (base64-url-encode
               (bytes-append
                #"{\"sub\":\"blahblah\","
                #"\"iss\":\"http://www.example.com\","
                #"\"aud\":\"http://www.fellowhuman.com\"}")
               )
              (string-append
               "eyJzdWIiOiJibGFoYmxhaCIsImlzcyI6Imh0dHA6Ly93d3cuZXhhbXBsZS5j"
               "b20iLCJhdWQiOiJodHRwOi8vd3d3LmZlbGxvd2h1bWFuLmNvbSJ9"))
