crypto      = require "crypto"
querystring = require "querystring"

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
#
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
#

class HMACAlgorithm

  _algOssl =
    HS256 : "SHA256"
    HS384 : "SHA384"
    HS512 : "SHA512"

    #
    # Creates and returns a hmac object, a cryptographic hmac with the given algorithm and key.
    # algorithm is dependent on the available algorithms supported by OpenSSL - see createHash above. key is the hmac key to be used.
    #
  constructor: (@alg = "HS256" , @key) ->
    osslAlg = _algOssl[@alg]
    new Error "Algorithm #{alg} is not supported by the specification." unless osslAlg
    try
      @hmac = crypto.createHmac osslAlg, @key
    catch error
      throw new Error "HMAC does not support algorithm #{@alg} => #{osslAlg}!"

  update: (data) ->
    throw new Error "There is no reference to the hmac object!" unless @hmac
    @hmac.update data
    @

  digest: (encoding = "base64") ->
    throw new Error "There is no reference to the hmac object!" unless @hmac
    querystring.escape @hmac.digest(encoding)

  sign: (encoding) -> @digest(encoding)

 
module.exports.HMACAlgorithm =  HMACAlgorithm

class SigningAlgorithm

  _createSigner = (alg) ->
    try
      @signer = crypto.createSign(alg)
    catch error
      throw new Error "Unable to create a signer with algorithm #{alg}!"

  _createVerifier = (alg) ->
    try
      verifier = crypto.createVerifier(alg)
      return verifier
    catch error
      throw new Error "Unable to create a verifier with algorithm #{alg}!"

  _assertSigner = () ->
    throw new Error "The `signer` reference is undefined!" unless @signer

  constructor: (@alg = "RSA-SHA256", @key_PEM) ->
    _createSigner(@alg)
  
  update: (data) ->
    _assertSigner()
    @signer.update data

  sign: (format = "base64") ->
    _assertSigner()
    @signer.sign(@key_PEM, format)
  
  verify: (publicKey, data, format) ->
    verifier = _createVerifier(@alg)
    @keyPEM.verifyString(@data, b64urltohex(sig))
 
class VerifierAlgorithm
  
  _createVerifier = (alg) ->
    try
      verifier = crypto.createVerifier(alg)
      return verifier
    catch error
      throw new Error "Unable to create a verifier with algorithm #{alg}!"

  _assertState = () ->
    throw new Error "The `verifier` reference is undefined!" unless @verifier

  constructor: (@alg = "RSA-SHA256") ->
    _createVerifier(@alg)
  
  update: (data) ->
    _assertState()
    @verifier.update data

  verify: (objPEM, signature, format = "base64") ->
    _assertState()
    @verifier.verify(objPEM, signature, format)
 



