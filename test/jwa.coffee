
should = require "should"

jwa = require "../lib/jwa"

#
# Based on [JSON Web Algorithms (JWA) v02](https://www.ietf.org/id/draft-ietf-jose-json-web-algorithms-02.txt)
#
# The JSON Web Algorithms (JWA) specification enumerates cryptographic
# algorithms and identifiers to be used with the JSON Web Signature
# (JWS) [JWS] and JSON Web Encryption (JWE) [JWE] specifications.
# Enumerating the algorithms and identifiers for them in this
# specification, rather than in the JWS and JWE specifications, is
# intended to allow them to remain unchanged in the face of changes in
# the set of required, recommended, optional, and deprecated algorithms
# over time.  This specification also describes the semantics and
# operations that are specific to these algorithms and algorithm
# families.
#
#   +--------------------+----------------------------------------------+
#   | alg Parameter      | Digital Signature or MAC Algorithm           |
#   | Value              |                                              |
#   +--------------------+----------------------------------------------+
#   | HS256              | HMAC using SHA-256 hash algorithm            |
#   | HS384              | HMAC using SHA-384 hash algorithm            |
#   | HS512              | HMAC using SHA-512 hash algorithm            |
#   | RS256              | RSA using SHA-256 hash algorithm             |
#   | RS384              | RSA using SHA-384 hash algorithm             |
#   | RS512              | RSA using SHA-512 hash algorithm             |
#   | ES256              | ECDSA using P-256 curve and SHA-256 hash     |
#   |                    | algorithm                                    |
#   | ES384              | ECDSA using P-384 curve and SHA-384 hash     |
#   |                    | algorithm                                    |
#   | ES512              | ECDSA using P-521 curve and SHA-512 hash     |
#   |                    | algorithm                                    |
#   | none               | No digital signature or MAC value included   |
#   +--------------------+----------------------------------------------+
#
#  Of these algorithms, only HMAC SHA-256 and "none" MUST be implemented
#  by conforming JWS implementations.  It is RECOMMENDED that
#  implementations also support the RSA SHA-256 and ECDSA P-256 SHA-256
#  algorithms.  Support for other algorithms and key sizes is OPTIONAL.


describe 'JWA Implementation for MAC with HMAC SHA-256, HMAC SHA-384, or HMAC SHA-512', ->
  #with a known key
  hmacKey = "hmac-key"
  # and a known JSON String
  dataJS = JSON.stringify(
    data =
      att1 : "value"
      att2 : 1 )

  # and a known set of Algorithms to test
  knownAlg = ["HS256", "HS384", "HS512"]

  # and a set of expectations (mapped to the actual algorithms, note that they are already urlencoded)
  expectations =
    HS256 : "6SN4r6MZmNNKkok0iK0E8bu9H7zoRHYZXXhPLr5M6eU%3D"
    HS384 : "Mqzvb4sukLBQ9MTVroERBO%2FPMUwwe03hi4BVQoEPo0lc3z32vd8mX0YSfsM%2FhX96"
    HS512 : "qG1p5FRVIbAG02OSFc%2F3JlRflbLeVyBe5jJmejM8%2F%2BJHVD56ia2A5JOFJ3p%2F0uulG7fQQ4M%2FswGvqMlukUOhNw%3D%3D"

  # we generate permutations per known algorithm to assert the creation of the HMAC instance
  # and digestion of the data.
  ( (alg) =>
    it "supports #{alg}", ->
      hmac = new jwa.HMACAlgorithm alg, hmacKey
      should.exist hmac
      # update the hmac algorithm instance with the kown data 
      hmac.update(dataJS)
      # digest the data with the current algorithm (alg) and key (hmacKey)
      digest = hmac.digest()
      # assert the value against the expected value.
      digest.should.equal expectations[alg]
  
  )(alg) for alg in ["HS256", "HS384", "HS512"]


