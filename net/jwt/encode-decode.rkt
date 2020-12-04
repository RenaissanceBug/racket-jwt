#lang typed/racket

(require typed/json
         "structs.rkt"
         "algorithms.rkt"
         (only-in "base64.rkt" base64-url-encode)
         )

(require/typed racket/date [date->seconds (-> date Integer)])

(provide decode-jwt
         verify-jwt
         decode/verify
         encode/sign
         encode-jwt
         )

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Decoding and verifying

;; Because there are a lot of failure cases, I use this shorthand in the
;; verifying/decoding functions below. See verify-jwt for example use.
(define-syntax-rule (fail-with def-keyword failure-expr)
  (define-syntax def-keyword
    ;; Try to define the given names to have the given value subject to
    ;; the given condition; if the condition is not met, decode/verify fails.
    (syntax-rules ()
      [(_ (name (... ...)) value condition)
       (define-values (name (... ...))
         (call-with-values (lambda () value)
           (lambda (name (... ...))
             (if condition (values name (... ...)) failure-expr))))]
      [(_ name value condition)
       (define name
         (let ([name value])
           (if condition name failure-expr)))])))

(: decode-jwt (String -> (Option JWT)))
#|
Decodes the given Compact JWS Serialization, producing an unverified JWT.
|#
(define (decode-jwt jwt)
  (let/ec fail : False
    (define-values (header-string payload-string signature)
      (match (string-split jwt ".")
        [(list h p)   (values h p "")] ; XXX this is *slightly* too permissive;
        [(list h p s) (values h p s)]  ; it would accept JWTs with only one "."
        [_ (fail #f)]))
    (fail-with define-or-fail (fail #f))
    
    (define-or-fail header (string64/utf-8->jsexpr header-string)
      (and header (hash? header)))
    (define-or-fail claims (string64/utf-8->jsexpr payload-string)
      (and claims (hash? claims)))
    ;; TODO If the JOSE Header contains "cty" value of "JWT", then the Message
    ;; is a JWT; process the Message recursively.
    (and header claims signature
         (decoded-jwt header                  header-string
                      (jshash->claims claims) payload-string
                      signature))))

(: verify-jwt (->* (JWT String (U String Bytes))
                   (#:aud (Option String)
                    #:iss (Option String)
                    #:clock-skew Exact-Nonnegative-Integer)
                   (Option VerifiedJWT)))
#|
Checks a decoded JWT to verify that the signature can be verified using
the given secret and is intended for the given audience.
|#
(define (verify-jwt jwt algorithm secret
                    #:aud [audience #f]
                    #:iss [expected-issuer #f]
                    #:clock-skew [skew 30])
  (let/ec fail : False
    (match-define (decoded-jwt header rh claims payload sig) jwt)
    (fail-with define-or-fail (fail #f))
    
    ;; Check that the JWT's "alg" field matches the expected algorithm.
    (unless (and (supported? algorithm)
                 (not (string=? algorithm "none"))
                 (equal? algorithm (hash-ref header 'alg (lambda _ ""))))
      (fail #f))
    
    (: sign SigningFunction)
    (define-or-fail sign (signing-function algorithm) sign)

    ;; Re-decode the JWT, to check that the header and claims actually came
    ;; from the raw Compact JWS components (rh, rc) in the JWT struct.
    ;; This kinda sucks -- so does storing the raw strings in the structs --
    ;; but I don't see an easy way around it, since the process of converting
    ;; header and payload to JSExprs may reorder the fields, and there's no
    ;; canonical order in the RFC; it's not easily possible to reconstruct the
    ;; original compact JWS string because of that.

    (define rch (string64/utf-8->jsexpr payload))
    (and (equal? (string64/utf-8->jsexpr rh) header)
         (hash? rch)
         (equal? (jshash->claims rch) claims)
         (or (not audience) (audience-ok? audience claims))
         (or (not expected-issuer) (issuer-ok? expected-issuer claims))
         (date-ok? claims skew)
         (ok-signature? sig secret (string-append rh "." payload) sign)
         (verified-jwt header rh claims payload sig))))

(: decode/verify (->* (String String (U String Bytes))
                      (#:aud (Option String)
                       #:iss (Option String)
                       #:clock-skew Exact-Nonnegative-Integer)
                      (Option VerifiedJWT)))
(define (decode/verify s algorithm secret
                       #:aud [audience #f]
                       #:iss [expected-issuer #f]
                       #:clock-skew [skew 30])
  (let/ec fail : False
    (when (regexp-match #px"\\s" s)   (fail #f))
    (when (string=? algorithm "none") (fail #f))
    
    (fail-with define-or-fail (fail #f))
    
    (with-handlers ([exn:fail:contract? (lambda (e) (fail #f))]
                    [exn:fail:read? (lambda (e) (fail #f))])
      (: JWS-protected-header String)
      (: JOSE-header (HashTable Symbol JSExpr))
      (: JWS-payload String)
      (: signature String)
      (define-or-fail (JWS-protected-header JOSE-header JWS-payload signature)
        (match (string-split s ".")
          [(list h p s) (values h (string64/utf-8->jsexpr h) p s)]
          [(list h p s _ _)
           (fail #f) ; JWE -- unsupported
           ]
          [_ (fail #f)])
        (and (jsexpr? JOSE-header)
             (hash? JOSE-header)
             (hash-has-key? JOSE-header 'alg)))
      
      ;; At this point we know decode/verify has been given a JWS. Great!
      ;; XXX The RFC requires verifying that the header does not contain
      ;; duplicate header param names, and we don't do that here.
      ;; As it stands, if a header contains the same name twice, the
      ;; read-json function keeps the last value for that name, and silently
      ;; discards the other values.

      ;; Check that the JWT's "alg" field matches our algorithm.
      (unless (and (supported? algorithm)
                   (equal? algorithm (hash-ref JOSE-header 'alg (lambda _ ""))))
        (fail #f))

      (: sign SigningFunction)
      (define-or-fail sign
        (signing-function algorithm)
        sign)
      
      ;; 5 verify that we understand and can process all fields required
      ;;   by the JWS spec, the algorithm designated in the header, and
      ;;   the 'crit header parameter (if present), and that the fields'
      ;;   values are all understood & supported. TODO
      (when (hash-has-key? JOSE-header 'crit) ;; XXX we don't support extensions
        (fail #f))

      ;; 6 Decode the payload
      (define-or-fail payload (string64/utf-8->jsexpr JWS-payload)
        (and (jsexpr? payload)
             (hash? payload)))
      (define claims (jshash->claims payload))

      ;; 7-8 decode the sig (done by ok-signature?, not here), and check the
      ;; header and payload against it
      (unless (ok-signature? signature secret
                             (string-append JWS-protected-header
                                            "." JWS-payload)
                             sign)
        (fail #f))
      ;; TODO If the JOSE Header contains "cty" value of "JWT", then the Message
      ;; is a JWT; process the Message recursively.

      (when audience
        (unless (audience-ok? audience claims) (fail #f)))
      (when expected-issuer
        (unless (issuer-ok? expected-issuer claims) (fail #f)))
      (unless (date-ok? claims skew)
        (fail #f))

      (verified-jwt JOSE-header JWS-protected-header claims JWS-payload
                    signature))))

(: audience-ok? (String JWTClaimsSet -> Boolean))
;; aud check
(define (audience-ok? this-audience claims)
  (define ok-audiences (JWTClaimsSet-aud claims))
  (or (null? ok-audiences)
      (and (member this-audience ok-audiences) #t)))

(: issuer-ok? (String JWTClaimsSet -> Boolean))
;; iss check
(define (issuer-ok? expected-issuer claims)
  (define JWT-issuer (JWTClaimsSet-iss claims))
  (or (not JWT-issuer) (string=? expected-issuer JWT-issuer)))

(: date-ok? (JWTClaimsSet Exact-Nonnegative-Integer -> Boolean))
;; exp and nbf check
(define (date-ok? claims skew)
  (define expiration (JWTClaimsSet-exp claims))
  (define nbf (JWTClaimsSet-nbf claims))
  (and (or (not expiration)
           (<= (- (current-seconds) skew) (date->seconds expiration)))
       (or (not nbf)
           (>= (+ (current-seconds) skew) (date->seconds nbf)))))

;; TODO add a way to check why decoding/verifying fails.

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Encoding

(: encode/sign (->* (String (U String Bytes))
                    (#:extra-headers (HashTable Symbol JSExpr)
                     #:iss (Option String)
                     #:sub (Option String)
                     #:aud (U String (Listof String))
                     #:exp (Option (U date Integer))
                     #:nbf (Option (U date Integer))
                     #:iat (Option (U date Integer))
                     #:jti (Option String)
                     #:other (HashTable Symbol JSExpr))
                   String))
;; See Section 5.1 of RFC7515, http://tools.ietf.org/html/rfc7515#section-5.1
(define (encode/sign algorithm secret
                     #:extra-headers [headers
                                      #{#hasheq() :: (HashTable Symbol JSExpr)}]
                     #:iss [iss #f]
                     #:sub [sub #f]
                     #:aud [aud '()]
                     #:exp [exp #f]
                     #:nbf [nbf #f]
                     #:iat [iat (current-seconds)]
                     #:jti [jti #f]
                     #:other [claims #{#hasheq() :: (HashTable Symbol JSExpr)}])
  (define sign : SigningFunction
    (or (signing-function algorithm)
        (raise (exn:fail:unsupported-algorithm
                (format "Unsupported signing algorithm ~a" algorithm)
                (current-continuation-marks)))))
  (define-syntax extend-hash (syntax-rules ()
                               [(_ ht name) (?hash-set ht 'name name)]
                               [(_ ht name name2 ...)
                                (extend-hash (?hash-set ht 'name name)
                                             name2 ...)]))
  
  (define all-claims : (HashTable Symbol JSExpr) ;; JWS Payload content
    (let ([exp (to-seconds exp)]
          [nbf (to-seconds nbf)]
          [iat (if (date? iat) (date->seconds iat) iat)])
      (extend-hash claims iss sub aud exp nbf iat jti)))
  (define all-headers : (HashTable Symbol JSExpr) ;; JOSE Header content
    (hash-set headers 'alg algorithm))
  (define header/payload
    (string-append (jsexpr->string64/utf-8 all-headers) ; BASE64URL(Payload)
                   "."
                   (jsexpr->string64/utf-8 all-claims))); BASE64URL(UTF8(Header))

  (string-append header/payload
                 "."
                 (base64-url-encode (sign secret header/payload)))) ; Signature

(: to-seconds (-> (Option (U date Integer))
                  (Option Integer)))
;; Coerces dates to NumericDate format (aka seconds since the epoch). Used
;; by encode/sign.
(define (to-seconds d/s)
  (and d/s
       (let ([s (if (date? d/s) (date->seconds d/s) d/s)])
         (and (not (negative? s)) s))))

(: ?hash-set (-> (HashTable Symbol JSExpr) Symbol (Option JSExpr)
                 (HashTable Symbol JSExpr)))
;; Adds {key,val} to ht if val is not #f or '().
(define (?hash-set ht key val)
  (if (and val (not (null? val)))
      (hash-set ht key val)
      ht))

(: encode-jwt (->* ()
                   (#:headers (HashTable Symbol JSExpr)
                    #:iss (Option String)
                    #:sub (Option String)
                    #:aud (U String (Listof String))
                    #:exp (Option (U date Integer))
                    #:nbf (Option (U date Integer))
                    #:iat (Option (U date Integer))
                    #:jti (Option String)
                    #:other (HashTable Symbol JSExpr))
                   String))
(define (encode-jwt
         #:headers [headers #{#hasheq() :: (HashTable Symbol JSExpr)}]
         #:iss [iss #f]
         #:sub [sub #f]
         #:aud [aud '()]
         #:exp [exp #f]
         #:nbf [nbf #f]
         #:iat [iat #f]
         #:jti [jti #f]
         #:other [claims
                  #{#hasheq() :: (HashTable Symbol JSExpr)}])
  (encode/sign "none" ""
               #:extra-headers headers
               #:iss iss #:sub sub #:aud aud
               #:exp exp #:nbf nbf #:iat iat
               #:jti jti
               #:other claims))
