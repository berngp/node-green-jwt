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

# Tests
should = require "should"
# Self
jwt = require "../lib/jwt"



describe 'JWT Implementation ', ->

  fixtures =
    hmac_key : "key"

    jwt_header :
      typ  : "JWT"
      alg  : "HS256"

    jwt_claim :
      iss  : "joe"
      exp  : 1300819380
      "http://example.com/is_root" : true

    encoded_jwt : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.h7SvUGw_y4DJBMZiAiF49BAkkWhovB7B5HmztFAq6s0"

  it "should decode ...", ->
    jwt_request = jwt.jwt_decode fixtures.encoded_jwt
    jwt_request.header.should.be.eql fixtures.jwt_header
    jwt_request.claim.should.be.eql fixtures.jwt_claim

  it "should encode ...", ->
    token = jwt.jwt_encode fixtures.jwt_claim, fixtures.hmac_key
    token.should.be.eql fixtures.encoded_jwt
    

