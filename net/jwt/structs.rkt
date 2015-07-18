#lang typed/racket

(provide JWT (struct-out decoded-jwt)
         VerifiedJWT (struct-out verified-jwt)
         JWTClaimsSet (struct-out JWTClaimsSet)
         jshash->claims
         claims->jshash
         string64/utf-8->jsexpr)

(require typed/json "base64.rkt")
(require/typed racket/date [date->seconds (-> date Integer)])

;; HeaderParam represents a JSON Header Parameter.
;; From RFC7515 "JSON Web Signature (JWS)", http://tools.ietf.org/html/rfc7515
;; as of May 2015
#;
(define-type HeaderParam
  (U 'alg ; Algorithm - MUST be present
     'jku ; JWK Set URL  - OPTIONAL
     'jwk ; JSON Web Key - OPTIONAL
     'kid ; Key ID       - OPTIONAL, value MUST be a case-sensitive string
     'x5u ; X.509 URL    - OPTIONAL
     'x5c ; X.509 Cert/Chain - OPTIONAL; we MUST validate (RFC5280) if present
          ; Corresponds to the key used to sign the JWS.
     'x5t ; X.509 Cert SHA-1 Thumbprint - OPTIONAL
     'x5t#S256 ; X.509 Certificate SHA-256 Thumbprint - OPTIONAL
     'typ ; MIME Media Type of JWS - OPTIONAL, safe to ignore
     'cty ; Content Type (MIME type of payload) - OPTIONAL;
          ;   MUST be "JWT" if this JWT carries a nested JWT; otherwise ignore.
     'crit ; Critical - OPTIONAL, but indicates extensions are being used
           ; that MUST be understood by our impl; if not, the JWS is invalid.
     JWTClaimName
     ))

;(define-type JWTClaimName (U 'iss 'sub 'aud 'exp 'nbf 'iat 'jti))

(struct JWTClaimsSet ([iss : (Option String)]
                      [sub : (Option String)]
                      [aud : (Listof String)]
                      [exp : (Option date)]
                      [nbf : (Option date)]
                      [iat : (Option date)]
                      [jti : (Option String)]
                      [other : (HashTable Symbol JSExpr)])
  #:transparent)

(struct decoded-jwt ([header : (HashTable Symbol JSExpr)]
                     [raw-header : String]  ; encoding of header field
                     [claims : JWTClaimsSet]
                     [raw-payload : String] ; encoding of claims field
                     [signature : String])
  #:transparent)
(define-type JWT decoded-jwt)

(struct verified-jwt decoded-jwt () #:transparent)
(define-type VerifiedJWT verified-jwt)

(: jshash->claims ((HashTable Symbol JSExpr) -> JWTClaimsSet))
(define (jshash->claims claims-table)
  (: str (-> JSExpr (Option String)))
  (define (str jsx)
    (or (and (string? jsx) jsx)
        (and (number? jsx) (number->string jsx)))) ; rkt JSON lib autoconverts #s
  (: maybe-date (-> JSExpr (Option date) (Option date)))
  (define (maybe-date jsx default)
    (or (and (exact-integer? jsx) (seconds->date jsx)) default))
  (define-values (iss sub aud exp nbf iat jti etc)
    (for/fold ([iss : (Option String) #f]
               [sub : (Option String) #f]
               [aud : (Listof String) '()]
               [exp : (Option date) #f]
               [nbf : (Option date) #f]
               [iat : (Option date) #f]
               [jti : (Option String) #f]
               [etc : (HashTable Symbol JSExpr) (hasheq)])
              ([([k : Symbol] [v : JSExpr]) (in-hash claims-table)])
      (case k
        [(iss) (values (str v) sub aud exp nbf iat jti etc)]
        [(sub) (values iss (str v) aud exp nbf iat jti etc)]
        [(aud) (values iss sub
                       (let* ([maybe-s (str v)]
                              [v-aud : (Listof String)
                                     (or (and maybe-s (list maybe-s))
                                         (and (list? v)
                                              (filter-map str v))
                                         '())])
                         (append aud v-aud))
                       exp nbf iat jti etc)]
        [(exp) (values iss sub aud (maybe-date v exp) nbf iat jti etc)]
        [(nbf) (values iss sub aud exp (maybe-date v nbf) iat jti etc)]
        [(iat) (values iss sub aud exp nbf (maybe-date v iat) jti etc)]
        [(jti) (values iss sub aud exp nbf iat (or (and (string? v) v) jti) etc)]
        [else
         (values iss sub aud exp nbf iat jti
                 (hash-set etc k v))])))
  (JWTClaimsSet iss sub aud exp nbf iat jti etc))

(: claims->jshash (JWTClaimsSet -> JSExpr))
(define (claims->jshash claims)
  (match-define (JWTClaimsSet iss sub aud exp nbf iat jti claims-hash) claims)
  (define-syntax extend
    (syntax-rules ()
      [(_ hash) hash]
      [(_ hash [field-name convert] . etc)
       (extend (if field-name
                   (hash-set hash 'field-name (convert field-name))
                   hash)
               . etc)]
      [(_ hash field-name . etc)
       (extend (if field-name (hash-set hash 'field-name field-name) hash)
               . etc)]))
  (define ch2 (extend claims-hash iss sub
                      [exp date->seconds]
                      [nbf date->seconds]
                      [iat date->seconds]
                      jti))
  (cond [(null? aud) ch2]
        [(null? (cdr aud)) (hash-set ch2 'aud (car aud))]
        [else (hash-set ch2 'aud aud)]))

(: string64/utf-8->jsexpr (String -> (Option JSExpr)))
;; Attempts to interpret the given string as a Base64url encoding of
;; UTF-8-encoded text representing a valid JSON object, and produces that JSON
;; object if possible. Otherwise, produces #f.
(define (string64/utf-8->jsexpr s)
  (with-handlers ([exn:fail:read? (lambda _ #f)])
    (define b/f (base64-url-decode s))
    (and b/f
         (let ([obj/f (read-json (open-input-bytes b/f))])
           (and (not (eof-object? obj/f))
                obj/f)))))



