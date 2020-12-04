#lang info

(define collection 'multi)

(define deps '("srfi-lite-lib"
               ("base" #:version "6.10")
               "typed-racket-lib"
               "typed-racket-more"
               "sha"
               "crypto"))

(define build-deps
  '("rackunit-lib" "web-server-lib" "racket-doc" "scribble-lib"
    "typed-racket-lib" "typed-racket-more" "typed-racket-doc"
    "option-bind"
    ;"net-doc"
    ))

(define version "1.1.1")
