#lang typed/racket

(require typed/net/base64)
(provide base64-url-encode
         base64-url-decode)

(: base64-url-encode (Bytes -> String))
(define (base64-url-encode bs)
  (define encoded : (Listof String)
    (string-split (bytes->string/utf-8 (base64-encode bs))
                                      "="))
  (if (pair? encoded)
      (string-replace (string-replace (car encoded) "+" "-")
                      "/" "_")
      ""))

(: base64-url-decode (String -> (Option Bytes)))
(define (base64-url-decode s)
  (define padded : (Option String)
    (pad (string-replace (string-replace s "-" "+") "_" "/")))
  (and (string? padded)
       (base64-decode (string->bytes/utf-8 padded))))

(: pad (String -> (Option String)))
(define (pad s)
  (define fourity (modulo (string-length s) 4))
  (if (= fourity 1)
      #f
      (string-append s
                     (case fourity
                       [(0) ""]
                       [(2) "=="]
                       [(3) "="]
                       [else (error 'pad "can't happen")]))))

(module+ test
  (require typed/rackunit)
  (check-equal? (base64-url-encode (list->bytes (list 3 236 255 224 193)))
                "A-z_4ME") ;; From Appendix C of RFC7515
  (check-equal? (base64-url-encode #"") "")
  (check-equal? (base64-url-decode "") #"")
  )
