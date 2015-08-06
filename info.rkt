#lang info

(define collection 'multi)

(define deps '("srfi-lite-lib" "base" "typed-racket-more" "grommet"))

(define build-deps
  '("rackunit-lib" "web-server-lib" "racket-doc" "scribble-lib"
    "typed-racket-more" "typed-racket-doc" ;; for typed/json
    "option-bind"
    ;"net-doc"
    ))

(define version "1.0")
