#lang scribble/manual

@(require scribble/manual scribble/eval)

@title[#:tag "jwt"]{JSON Web Token and JSON Web Signature}

@author[(author+email "Jordan Johnson" "jmj@fellowhuman.com")]

This library provides limited functionality for validating JSON Web Tokens as
specified in RFC 7519 @cite["RFC7519"].

@;defmodule[net/jwt]{}
@;defmodule[net/jwt/algorithms]{}
@;defmodule[net/jwt/base64]{}

@; ------------------------------------------

@(bibliography
  (bib-entry #:key "RFC7515"
             #:title "JSON Web Signature (JWS)"
             #:author "M. Jones, J. Bradley, and N. Sakimura"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7515"
             #:date "1987")
  (bib-entry #:key "RFC7518"
             #:title "JSON Web Algorithms (JWA)"
             #:author "M. Jones"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7518"
             #:date "1987")
  (bib-entry #:key "RFC7519"
             #:title "JSON Web Token (JWT)"
             #:author "M. Jones, J. Bradley, and N. Sakimura"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7519"
             #:date "1987")
  (bib-entry #:key "RFC7516"
             #:title "JSON Web Encryption (JWE)"
             #:author "M. Jones and J. Hildebrand"
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc7516"
             #:date "1987")

  #;(bib-entry #:key "RFC"
             #:title ""
             #:author ""
             #:location "RFC"
             #:url "http://tools.ietf.org/html/rfc____.html"
             #:date "1987")
  )
