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

jwaToOpenSSL = (alg) ->
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
#  The HMAC SHA-256 MAC is generated as follows:
#
#  1.  Apply the HMAC SHA-256 algorithm to the bytes of the UTF-8
#   representation of the JWS Secured Input (which is the same as the
#   ASCII representation) using the shared key to produce an HMAC
#   value.
#
#  2.  Base64url encode the resulting HMAC value.
#
#  The output is the Encoded JWS Signature for that JWS.
#
#  The HMAC SHA-256 MAC for a JWS is validated as follows:
#
#  1.  Apply the HMAC SHA-256 algorithm to the bytes of the UTF-8
#   representation of the JWS Secured Input (which is the same as the
#   ASCII representation) of the JWS using the shared key.
#
#  2.  Base64url encode the resulting HMAC value.
#
#  3.  If the Encoded JWS Signature and the base64url encoded HMAC value
#   exactly match, then one has confirmation that the shared key was
#   used to generate the HMAC on the JWS and that the contents of the
#   JWS have not be tampered with.
#
#  4.  If the validation fails, the JWS MUST be rejected.
#
#  Alternatively, the Encoded JWS Signature MAY be base64url decoded to
#  produce the JWS Signature and this value can be compared with the
#  computed HMAC value, as this comparison produces the same result as
#  comparing the encoded values.
#
#  Securing content with the HMAC SHA-384 and HMAC SHA-512 algorithms is
#  performed identically to the procedure for HMAC SHA-256 - just with
#  correspondingly larger minimum key sizes and result values.
#
class HMACAlgorithm

  _algs = [ "HS256", "HS384", "HS512" ]

    #
    # Creates and returns an HMAC object, a cryptographic HMAC binded to the given algorithm and key.
    # The supported algorithm is dependent on the available algorithms in *OpenSSL* - to get the list
    # type `openssl list-message-digest-algorithms` in the terminal. If you provide an algorithm that is
    # not supported and error will be thrown.
    #
    # The following table maps the algorithm from the *JWA Spec* to the one provided by *OpenSSL*
    #
    #
  constructor: (alg = "HS256" , @key) ->
    throw Error "A defined algorithm is required." unless alg

    @alg = alg.toUpperCase()
    throw Error "Algorithm #{@alg} is not supported by HMAC." unless _algs.indexOf(@alg) >= 0

    @osslAlg = jwaToOpenSSL @alg
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

module.exports.HMACFactory =  (alg, key) ->  new HMACAlgorithm(alg, key)


  #  
  #  Digital Signature with RSA SHA-256, RSA SHA-384, or RSA SHA-512
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
  #  The RSA SHA-256 digital signature is generated as follows:
  #
  #  1.  Generate a digital signature of the bytes of the UTF-8
  #     representation of the JWS Secured Input (which is the same as the
  #     ASCII representation) using RSASSA-PKCS1-V1_5-SIGN and the SHA-256 
  #     hash function with the desired private key.  The output will
  #     be a byte array.
  #
  #  2.  Base64url encode the resulting byte array.
  #
  #  The output is the Encoded JWS Signature for that JWS.
  #
  #  The RSA SHA-256 digital signature for a JWS is validated as follows:
  #
  #  1.  Take the Encoded JWS Signature and base64url decode it into a
  #     byte array.  If decoding fails, the JWS MUST be rejected.
  #
  #  2.  Submit the bytes of the UTF-8 representation of the JWS Secured
  #     Input (which is the same as the ASCII representation) and the
  #     public key corresponding to the private key used by the signer to
  #     the RSASSA-PKCS1-V1_5-VERIFY algorithm using SHA-256 as the hash
  #     function.
  #
  #  3.  If the validation fails, the JWS MUST be rejected.
  #
  #  Signing with the RSA SHA-384 and RSA SHA-512 algorithms is performed
  #  identically to the procedure for RSA SHA-256 - just with
  #  correspondingly larger result values.
  # 
  #
class RSAlgorithm
  _algs = [ "RS256", "RS384", "RS512" ]

  _assertSigner : () ->
    throw Error "Signer is not defined!" unless @signer

  constructor: (alg = "RSA-SHA256", @key_PEM) ->
    throw Error "A defined algorithm is required." unless alg

    @alg = alg.toUpperCase()
    throw Error "Algorithm #{@alg} is not supported by RSA." unless _algs.indexOf(@alg) >= 0

    @osslAlg = jwaToOpenSSL @alg
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

module.exports.RSFactory = (alg, key_PEM) -> new RSAlgorithm( alg, key_PEM )
 
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
 



