crypto = require  'crypto'

specVersion = ""

algorithms =
  HS256: 'sha256'
  HS384: 'sha384'
  HS512: 'sha512'
  RS256: 'rs256'


  #  function NoSuchAlgorithmException(message) {
  #  this.message = message
  #  this.toString = function() { return "No such algorithm: "+this.message }
  #}
  #function NotImplementedException(message) {
  #  this.message = message
  #  this.toString = function() { return "Not implemented: "+this.message }
  #}
  #function InputException(message) {
  #  this.message = message
  #  this.toString = function() { return "Malformed input: "+this.message }
  #}

  #  Decode jwt 
  # @param {Object} token
  # @param {String} key 
  # @param {Boolean} noVerify 
  # @return {Object} payload
  # @api public

jwt_decode = (token, key, noVerify) ->
  # check seguments
  segments = token.split '.'

  throw new Error 'Not enough or too many segments' if segments.length != 3
  
  # All segment should be base64
  headerSeg = segments[0]
  payloadSeg = segments[1]
  signatureSeg = segments[2]

  # base64 decode and parse JSON
  header = JSON.parse base64urlDecode(headerSeg)
  payload = JSON.parse base64urlDecode(payloadSeg)
  
  unless noVerify
    signingMethod = algorithmMap[header.alg]

    throw new Error('Algorithm not supported') unless signingMethod
    # verify signature. `sign` will return base64 string.
    signingInput = [headerSeg, payloadSeg].join '.'
    throw new Error('Signature verification failed') unless (signatureSeg == sign(signingInput, key, signingMethod)) 
    
  payload


 #
 # Encode jwt
 #
 # @param {Object} payload
 # @param {String} key 
 # @param {String} algorithm 
 # @return {String} token
 # @api public
 #
 #
jwt_encode = (payload, key, algorithm = "HS256") ->
  throw new Error 'Argument key is require' unless key
  # Check algorithm, default is HS256

  signingMethod = algorithmMap[algorithm]
  throw new Error "Algorithm #{algorithm} is not yet supported." unless signingMethod

  #header, typ is fixed value.
  header =
    typ: 'JWT'
    alg: algorithm

  #create segments, all segment should be base64 string
  segments = []
  segments.push(base64urlEncode(JSON.stringify(header)))
  segments.push(base64urlEncode(JSON.stringify(payload)))
  segments.push(sign(segments.join('.'), key, signingMethod))
  
  segments.join('.')


sign = (input, key, method) ->
  base64str = crypto.createHmac(method, key).update(input).digest('base64')
  base64urlEscape(base64str)


base64urlDecode = (str) ->
  new Buffer(base64urlUnescape(str), 'base64').toString()

base64urlUnescape = (str) ->
  str += Array(5 - str.length % 4).join('=')
  str.replace(/\-/g, '+').replace(/_/g, '/')

base64urlEncode = (str) ->
  base64urlEscape(new Buffer(str).toString('base64'))

base64urlEscape = (str) ->
  str.replace(///+///g, '-')#.replace(/\//g, '_').replace(/=/g, '')

base64urlEncode = (arg) ->
    s = window.atob(arg) # Standard base64 encoder
    s = s.split('=')[0]  # Remove any trailing '='s
    s = s.replace('+', '-', 'g') # 62nd char of encoding
    s = s.replace('/', '_', 'g') # 63rd char of encoding

base64urldecode = (arg) ->
  s = arg
  s = s.replace('-', '+', 'g') # 62nd char of encoding
  s = s.replace('_', '/', 'g') # 63rd char of encoding
  switch s.length % 4 # Pad with trailing '='s
    #No pad chars in this case
    when 0 then
    # Two pad chars
    when 2 then s += "=="
    # One pad char
    when 3 then s += "="
    # else
    else throw new InputException("Illegal base64url string!")
  
  return window.btoa(s) #Standard base64 decoder

