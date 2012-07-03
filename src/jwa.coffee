crypto      = require "crypto"
querystring = require "querystring"

#
# The following is based on [JSON Web Algorithms (JWA) v02](https://www.ietf.org/id/draft-ietf-jose-json-web-algorithms-02.txt):
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
#

jwa_to_openssl = (alg) ->
  _algOssl =
    # HMAC
    HS256 : "SHA256"
    HS384 : "SHA384"
    HS512 : "SHA512"
    # RSA
    RS256 : "RSA-SHA256"
    RS384 : "RSA-SHA384"
    RS512 : "RSA-SHA512"

  _algOssl[alg]

jwa_table =
    HMAC :
      HS256 : "SHA256"
      HS384 : "SHA384"
      HS512 : "SHA512"
    RSA :
      RS256 : "RSA-SHA256"
      RS384 : "RSA-SHA384"
      RS512 : "RSA-SHA512"

  #
  # To support use cases where the content is secured by a means other
  # than a digital signature or MAC value, JWSs MAY also be created
  # without them.  These are called "Plaintext JWSs".  Plaintext JWSs
  # MUST use the "alg" value "none", and are formatted identically to
  # other JWSs, but with an empty JWS Signature value.
  #
class NoneAlgorithm

  update: () ->

  digest: () -> ""

  sign: () -> @digest()


NONE_ALG = new NoneAlgorithm

exports.newNone = newNone = ( ) -> NONE_ALG


  # Provides the HMAC implementation of the **HS256**, **HS384** and **HS512** algorithms.
  # Cryptographic algorithms are provided by **Node's** [Crypto library](http://nodejs.org/api/crypto.html)
  #
  # As mentioned in the specification the HMAC (Hash-based Message Authentication Codes) enable the usage
  # of a *known secret*, this can be used to demonstrate that the MAC matches the hashed content, 
  # in this case the JWS Secured Input, which therefore demonstrates that whoever generated the MAC was in
  # possession of the secret. 
  #
  # To review the specifics of the algorithms please review chapter
  # "3.2.  MAC with HMAC SHA-256, HMAC SHA-384, or HMAC SHA-512" of
  # the [Specification](https://www.ietf.org/id/draft-ietf-jose-json-web-algorithms-02.txt).
  #
class HMACAlgorithm

  _algs = jwa_table.HMAC

    #
    # Creates and returns an HMAC object, a cryptographic HMAC binded to the given algorithm and key.
    # The supported algorithm is dependent on the available algorithms in *OpenSSL* - to get the list
    # type `openssl list-message-digest-algorithms` in the terminal. If you provide an algorithm that is
    # not supported an error will be thrown.
    #
  constructor: (alg = "HS256" , @key) ->
    throw Error "A defined algorithm is required." unless alg

    @alg = alg.toUpperCase()
    throw Error "Algorithm #{@alg} is not supported by HMAC." unless _algs[@alg]

    @osslAlg = jwa_to_openssl @alg
    new Error "Algorithm #{@alg} is not supported by the specification." unless @osslAlg

    try
      @hmac = crypto.createHmac @osslAlg, @key
    catch error
      throw new Error "HMAC does not support algorithm #{@alg} => #{@osslAlg}!"

  update: (data) ->
    throw new Error "There is no reference to the hmac object!" unless @hmac
    @hmac.update data
    @

  digest: (encoding = "base64") ->
    throw new Error "There is no reference to the hmac object!" unless @hmac
    querystring.escape @hmac.digest(encoding)

  sign: (encoding) -> @digest(encoding)

module.exports.newHMAC = newHMAC = (alg, key) ->  new HMACAlgorithm(alg, key)


  #  
  #  Implementation of digital signature with RSA SHA-256, RSA SHA-384, or RSA SHA-512
  #
  #  To review the specifics of the algorithms please review chapter
  #  "3.3.  Digital Signature with RSA SHA-256, RSA SHA-384, or RSA SHA-512" of
  #  the [Specification](https://www.ietf.org/id/draft-ietf-jose-json-web-algorithms-02.txt).
  #  
  #  Important elements to understand are.
  #  * RSASSA-PKCS1-v1_5 digital signature algorithm (commonly known as PKCS#1), 
  #  using SHA-256, SHA-384, or SHA-512 as the hash function. 
  #  
  #  The *"alg"* (algorithm) header parameter values used in the JWS Header to indicate that 
  #  the *Encoded JWS Signature* contains a **base64url** encoded **RSA digital signature* using the
  #  respective hash function are:
  #  * "RS256"
  #  * "RS384"
  #  * "RS512" 
  #
  #  **A key of size 2048 bits or larger MUST be used with these algorithms.**
  #
  #
class RSAlgorithm
  _algs = jwa_table.RSA

  _assertSigner : () ->
    throw Error "Signer is not defined!" unless @signer

  constructor: (alg = "RSA-SHA256", @key_PEM) ->
    throw Error "A defined algorithm is required." unless alg

    @alg = alg.toUpperCase()
    throw Error "Algorithm #{@alg} is not supported by RSA." unless _algs[@alg]

    @osslAlg = jwa_to_openssl @alg
    new Error "Algorithm #{@alg} is not supported by the specification." unless @osslAlg

    try
      @signer = crypto.createSign(@osslAlg)
    catch error
      throw new Error "Unable to create a signer with algorithm #{@osslAlg}!"
  
  update: (data) ->
    @_assertSigner()
    @signer.update data

  sign: (format = "base64") ->
    @_assertSigner()
    querystring.escape @signer.sign(@key_PEM, format)

module.exports.newRS = newRS = (alg, key_PEM) -> new RSAlgorithm( alg, key_PEM )

  #  
  #  Implementation of digital signature verifier for RSA SHA-256, RSA SHA-384, or RSA SHA-512
  #  that uses a *Public Key* to assert the content.
  #
  #  To review the specifics of the algorithms please review chapter
  #  "3.3.  Digital Signature with RSA SHA-256, RSA SHA-384, or RSA SHA-512" of
  #  the [Specification](https://www.ietf.org/id/draft-ietf-jose-json-web-algorithms-02.txt).
  #  
  #  The *Encoded JWS Signature* contains a **base64url** encoded **RSA digital signature*. The
  #  following hash functions are available:
  #  * "RS256"
  #  * "RS384"
  #  * "RS512" 
  #
  #  **A key of size 2048 bits or larger MUST be used with these algorithms.**
  #
class RSVerifier
  
  _assertState : () ->
    throw new Error "The `verifier` reference is undefined!" unless @verifier

  constructor: (@alg = "RSA-SHA256") ->
    try
      @verifier = crypto.createVerifier(@alg)
    catch error
      throw new Error "Unable to create a verifier with algorithm #{@alg}!"
  
  update: (data) ->
    _assertState()
    @verifier.update data

  verify: (objPEM, signature, format = "base64") ->
    _assertState()
    @verifier.verify(objPEM, signature, format)
 

#
# TODO: Implement 
#       3.4.  Digital Signature with ECDSA P-256 SHA-256, ECDSA P-384 SHA-384,
#             or ECDSA P-521 SHA-512
#
#   The Elliptic Curve Digital Signature Algorithm (ECDSA) is defined by
#   FIPS 186-3 [FIPS.186-3].  ECDSA provides for the use of Elliptic
#   Curve cryptography, which is able to provide equivalent security to
#   RSA cryptography but using shorter key sizes and with greater
#   processing speed.  This means that ECDSA digital signatures will be
#   substantially smaller in terms of length than equivalently strong RSA
#   digital signatures.
#
#   This specification defines the use of ECDSA with the P-256 curve and
#   the SHA-256 cryptographic hash function, ECDSA with the P-384 curve
#   and the SHA-384 hash function, and ECDSA with the P-521 curve and the
#   SHA-512 hash function.  The P-256, P-384, and P-521 curves are also
#   defined in FIPS 186-3.  The "alg" (algorithm) header parameter values
#   "ES256", "ES384", and "ES512" are used in the JWS Header to indicate
#   that the Encoded JWS Signature contains a base64url encoded ECDSA
#   P-256 SHA-256, ECDSA P-384 SHA-384, or ECDSA P-521 SHA-512 digital
#   signature, respectively.
#
#   A key of size 160 bits or larger MUST be used with these algorithms.
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
module.exports.provider = jwa_provider = (code) ->
  switch code
    when "none" then () => newNone()
    
    when "HS256", "HS384", "HS512" then (key) => newHMAC(code, key)
    
    when "RS256", "RS384", "RS512" then (key) => newRS(code, key)
    
    when "ES256", "ES384", "ES512" then throw new Error "ECDSA not yet implemented."

    else throw new Error "There is no JWA Provider for #{code}!"



