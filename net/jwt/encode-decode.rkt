#lang typed/racket

(require typed/json
         "structs.rkt"
         "algorithms.rkt"
         )

(require/typed racket/date [date->seconds (-> date Integer)])

(provide decode-jwt
         verify-jwt
         decode/verify
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
        [(list h p s) (values h p s)]
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

(: verify-jwt (->* (JWT String) ([Option String])
                   (Option VerifiedJWT)))
#|
Checks a decoded JWT to verify that the signature can be verified using
the given secret and is intended for the given audience.
|#
(define (verify-jwt jwt secret [audience #f])
  (let/ec fail : False
    (match-define (decoded-jwt header rh claims rc sig) jwt)
    (fail-with define-or-fail (fail #f))
    
    (define-or-fail algorithm
      (hash-ref header 'alg (lambda _ ""))
      (and (string? algorithm) (supported? algorithm)))
    (: sign SigningFunction)
    (define-or-fail sign (signing-function algorithm) sign)

    ;; Re-decode the JWT, to check that the header and claims actually came
    ;; from the raw Compact JWS components (rh, rc) in the JWT struct.
    ;; This kinda sucks -- so does storing the raw strings in the structs --
    ;; but I don't see an easy way around it, since the process of converting
    ;; header and payload to JSExprs may reorder the fields, and there's no
    ;; canonical order in the RFC; it's not easily possible to reconstruct the
    ;; original compact JWS string because of that.

    ;; TODO also check the audience
    (define rch (string64/utf-8->jsexpr rc))
    (and (equal? (string64/utf-8->jsexpr rh) header)
         (hash? rch)
         (equal? (jshash->claims rch) claims)
         (ok-signature? sig secret (string-append rh "." rc) sign)
         (verified-jwt header rh claims rc sig))))

(: decode/verify (->* (String String) ((Option String)) (Option VerifiedJWT)))
#|
Decodes and verifies a JWS compact serialization. Checks the signature, and
if @racket[audience] is not @racket[#f] and the JWT has an "aud" field, checks
that the given audience matches one of the JWT's audiences.
Produces #f if for any reason the JWT can't be validated.
|#
(define (decode/verify s secret [audience #f])
  (let/ec fail : False
    (when (regexp-match #px"\\s" s)
      (fail #f))
    
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
      (define-or-fail algorithm (hash-ref JOSE-header 'alg (lambda _ ""))
        (and (string? algorithm) (supported? algorithm)))

      ;; TODO also check the audience
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

      ;; 7-8 decode the sig (done by ok-signature?, not here), and check the
      ;; header and payload against it
      (unless (ok-signature? signature secret
                             (string-append JWS-protected-header
                                            "." JWS-payload)
                             sign)
        (fail #f))
      ;; TODO If the JOSE Header contains "cty" value of "JWT", then the Message
      ;; is a JWT; process the Message recursively.
      (verified-jwt JOSE-header JWS-protected-header
                    (jshash->claims payload) JWS-payload
                    signature))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Encoding

;; TODO
#;#;
(: encode/sign (-> SigningFunction JWTClaimsSet String
                   String))
(define (encode/sign sign claims secret)
  "")

;; TODO
#;#;
(: encode-unsigned (-> JWTClaimsSet String))
(define (encode-unsigned claims)
  "")
