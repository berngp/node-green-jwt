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


exports.base64urlEncode = base64urlEncode = (str) ->
  base64urlEscape(new Buffer(str).toString('base64'))

exports.base64urlDecode = base64urlDecode = (str) ->
  new Buffer(base64urlUnescape(str), 'base64').toString()

exports.base64urlEscape = base64urlEscape = (str) ->
  str.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '')

exports.base64urlUnescape = base64urlUnescape = (str) ->
  str += Array(5 - str.length % 4).join('=')
  str.replace(/\-/g, '+').replace(/_/g, '/')


