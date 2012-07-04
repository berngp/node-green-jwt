#
# * [JWT](http://tools.ietf.org/html/draft-jones-json-web-token-10) draft-jones-json-web-token-10
# * [JWA](https://www.ietf.org/id/draft-ietf-jose-json-web-algorithms-02.txt) draft-ietf-jose-json-web-algorithms-02
# * [JWS](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-02) draft-ietf-jose-json-web-signature-02
# * [JWE](http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-02) draft-ietf-jose-json-web-encryption-02
# * [JWK](http://tools.ietf.org/html/draft-ietf-jose-json-web-key-02) draft-ietf-jose-json-web-key-02
#
#
#

# Dependencies
# ============
# Node
crypto  = require "crypto"
qstring = require "querystring"

# Lip
jwa = require "./jwa"
ju  = require "./utils"


# version of the specification we are based on. 
module.exports.specVersion = "draft-jones-json-web-token-10"

  #
  #
  #
  #
module.exports.jwt_decode = jwt_decode = (token) ->
  # check seguments
  segments = token.split '.'

  throw new Error 'Not enough or too many segments' if segments.length != 3
  
  # All segment should be base64
  headerSeg = segments[0]
  payloadSeg = segments[1]
  signatureSeg = segments[2]
  # base64 decode and parse JSON
  header    = JSON.parse ju.base64urlDecode(headerSeg)
  claim     = JSON.parse ju.base64urlDecode(payloadSeg)
  # return
  new JwtRequest( header, claim, segments )

 # 
 # 
 #
module.exports.jwt_encode = (claim, key, algorithm = "HS256") ->
  throw new Error 'Argument key is require' unless key

  jwa_provider  = jwa.provider algorithm
  throw new Error "Algorithm #{algorithm} is not yet supported." unless jwa_provider

  jwa_signer = jwa_provider key

  header =
    typ: 'JWT'
    alg: algorithm

  #create segments, all segment should be base64 string
  segments = []
  segments.push ju.base64urlEncode(JSON.stringify(header))
  segments.push ju.base64urlEncode(JSON.stringify(claim))

  jwa_signer.update( segments.join "." )
  segments.push( jwa_signer.sign() )
  
  segments.join('.')


class JwtRequest
  
  constructor: (@header, @claim, @segments) ->
    throw new Error "Unable to read `typ` form header or it doesn't match the expected 'JWT' value " unless @header.typ == 'JWT'

  verify: (key) ->
    _alg = @header?.alg
    _alg = "none" unless _alg

    _verifier = jwa.verifier _alg
    throw new Error "Unable to find a verifier for algorithm #{_alg}" unless _verifier

    _verifier.verify @, key
  



    
