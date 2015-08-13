#lang info

(define collection 'multi)

(define deps '("srfi-lite-lib"
               "base"
               "typed-racket-lib"
               "typed-racket-more"
               "unstable-contract-lib"
               "grommet"))

(define build-deps
  '("rackunit-lib" "web-server-lib" "racket-doc" "scribble-lib"
    "typed-racket-lib" "typed-racket-more" "typed-racket-doc"
    "option-bind"
    ;"net-doc"
    ))

(define version "1.0.1")
