#lang typed/racket/base

(provide .join)

(: .join (String String String -> String))
#|
Joins the three given strings with periods.
|#
(define (.join header payload signature)
  (string-append header "." payload "." signature))

