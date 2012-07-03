###
# (The MIT License)
#
# Copyright (c) 2011 Kazuhito Hokamura <k.hokamura@gmail.com>
# Copyright (c) 2012 Bernardo &lt;bernardo.gomezpalacio@gmail.com&gt;
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# 'Software'), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###

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
  #  
  { header: header, claim: claim, signature: signatureSeg, encoded_jwt : token }

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
  segments.push( ju.base64urlEscape(jwa_signer.sign()) )
  
  segments.join('.')

