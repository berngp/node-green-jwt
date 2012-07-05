# Tests
should = require "should"
# Self
jwt = require "../lib/jwt"

# Global Test Fixtures
g_fixtures =
  jwt_claim :
    iss  : "joe"
    exp  : 1300819380
    "http://example.com/is_root" : true


describe 'JWT Implementation with HMAC encryption ', ->

  # Suite specific fixtures
  fixtures =
    key : "key"

    jwt_header :
      typ  : "JWT"
      alg  : "HS256"

    encoded_jwt : "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.h7SvUGw_y4DJBMZiAiF49BAkkWhovB7B5HmztFAq6s0"

  it "should encode", ->
    request = jwt.jwt_encode g_fixtures.jwt_claim, fixtures.key
    request.should.be.eql fixtures.encoded_jwt
    
  it "should decode and verify", ->
    jwt_request = jwt.jwt_decode fixtures.encoded_jwt
    # asserts the request Header
    jwt_request.header.should.be.eql fixtures.jwt_header
    # asserts the request Claim.
    jwt_request.claim.should.be.eql g_fixtures.jwt_claim
    # verify through JWS given the known key.
    jwt_request.verify(fixtures.key).should.be.true


#
# Describes the behaviour of the JWT with RSA Encryption
#
describe 'JWT Implementation with RSA encryption ', ->

  fixtures =
    private_PEM_key : """-----BEGIN RSA PRIVATE KEY-----
MIIEpgIBAAKCAQEAuBLG/WubpeE3HaLMUTyqqTDCfQpg/bqXDeUr6P8k54jNNLad
Nq+TXl/xtKqZ8SMdwYJsQ2BenENbsx80rJJJ4YTorrBYV1atyrW6hb+9llildKKF
54LsTGO4fp4qwucHXBGPt7rKOyZgHTfBNjmuygwU4h2XqZCrv18x2EfZ1m7r+Kcy
5pRvgL37aknXJSVRsspi0hiKmyG1JCi9p3ZVqFHXJUtI4qYq0yvQVmTKtZI4cFk6
6je1wIpRQWP3B5r70nhpCFLk2GqduTJu0mRDTUJE0Q4UgBHifXhA3I11LyxMcSao
Y8ugMBkYR0LSGkDDTLI8BP4FUWXoqcdieXt2GwIDAQABAoIBAQCyZxCRwV+jj/o5
MPXRrnjBbk6xngOPJu8MOpcqRU9hUEeC1ZLd06GDEH5U2hxFiAFo8Z04WAiabvZL
Tu1gbJBKkORrmuKkE5BxLVzQEJwRQW1q87HQRiX7i5LetTFAoWWSqDqgmdszJOh2
qPkMMy/jB36eAIxjfaHX4s2Oj2Tj3AwU0ae4aU/RjvxvT3500VB/TCRqlkrjNUlu
Xh5hngnyneRt3adci2ZeEYq7SoVQFXg6HTqRB2GCexdbhKqz20/w2OqT3kY0wHZM
ahCP5SjVT7gjH7PaO+A+y8oiJMKIZEnSownwXPfaQi5SRa3zxLTGk4gFL2Wfhoqf
5tyiALYxAoGBAOd5uYPVLHnbFyIpNCkrgy3rjMZLqNwb3lryPtUAo0VYjONX5Md4
Vywm/vsn5ZqCWuxdjlYobD6i/++TeIhyfn9LT/eZFIKkQWRfpB51afokU0L1SvV/
PSsXp+/LsAn7NXeuN4KDDqmEwub3klyQ7NYz+xBORpnO4ql2xnbLevMXAoGBAMuT
XxiItV2YLddiCYJEytU9h2qaLI/u1KTc2dMdUK775fkNA+LJrgbhaI0htR665hOD
Wr4CFlKqWcKRDd3NT3qykcpyHjBYGd04cOmfH/2nQkCdn3LTqOmfC2wNq1W5gKsX
iS+NmrqWf+eJsbMXGM6GcdaU65f6HeYki3U1P0edAoGBALAclp7M48fafyFIhB0G
tAmN+08rZVACDAzZ3iAlGhO6qYaW6sMwtfIrwTfJRRFnOFI5Y//9RU3qqhrW8o+t
vLyQykixOT+kRPRfJ/jckEL2vDpnch6SLjHJD8aMDGWrsSRbcnRjzhX/omIj3kF7
KhZW+h+PzntbQmx4p8reSa8FAoGBAIl+9/OyIg0dA5k9df6uR/DOpe+yQfbU8HqJ
T/XvDteg+yrDR6SdYxTymZL4+UPQKCV1yowbDMi4lfd70UnFqbDNevqpKQqt9oob
3OdtukWv+md6Dn+XxbZE3YoVkWtM50KnmtirY54ymCDiN0smhnK3C5xK6PS00gzn
EeoQFLVhAoGBAJxo1aB8981XI7SHxf2cjktXObsQwT5zgMtguqjiCxRoXaHzhbw9
hrnnw07pfG7XHI8piSgq7nruQ+OQVClbtng5SWkX63FIXItSoHOFTG/3YWf7wp9c
3ipkznYxJ8eGEOXNRtoZPXwM6BMYhwsswiPvxSX1hUUpr0HN/wXMaIL8
-----END RSA PRIVATE KEY-----"""

    public_PEM_key : """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuBLG/WubpeE3HaLMUTyq
qTDCfQpg/bqXDeUr6P8k54jNNLadNq+TXl/xtKqZ8SMdwYJsQ2BenENbsx80rJJJ
4YTorrBYV1atyrW6hb+9llildKKF54LsTGO4fp4qwucHXBGPt7rKOyZgHTfBNjmu
ygwU4h2XqZCrv18x2EfZ1m7r+Kcy5pRvgL37aknXJSVRsspi0hiKmyG1JCi9p3ZV
qFHXJUtI4qYq0yvQVmTKtZI4cFk66je1wIpRQWP3B5r70nhpCFLk2GqduTJu0mRD
TUJE0Q4UgBHifXhA3I11LyxMcSaoY8ugMBkYR0LSGkDDTLI8BP4FUWXoqcdieXt2
GwIDAQAB
-----END PUBLIC KEY-----"""
      
    jwt_header :
      typ  : "JWT"
      alg  : "RS256"

    encoded_jwt : "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.Fxj4HudpAfGKccMqBzEFSsa-2kz1iEl4J0bdg0EmOQ0CIe0yJNa5Th-_EYKtUJ1UDdyqNKkMXhM9qGnuQcpqqTdG5FECxgiZl2OykwI47EBr-FINF4U-MpuQtdz7Hd2sMD8ldW6WAfZ8vBt4quhuo_YdnzBejD1b9m-_iG88xL-rKWL1_Vj2FeT6usxTGJRuEEHGuLmKvaAOxXAvMHxQDGI8ZelFMYl-IB3mDAllzv6YZnfx2jMYzv3pixN_RXXEeG886UP3OzdDm2PEecDnC_19d2uKJgHlGv5DZa_Ysds8EcyHpnZH9UmhlCA7Nu3Dr11n0rmmevJbeYmsQEXXcA"


  it "should encode ...", ->
    request = jwt.jwt_encode( g_fixtures.jwt_claim, fixtures.private_PEM_key, "RS256" )
    request.should.be.eql fixtures.encoded_jwt
    
  it "should decode and verify ...", ->
    jwt_request = jwt.jwt_decode fixtures.encoded_jwt
    jwt_request.header.should.be.eql fixtures.jwt_header
    jwt_request.claim.should.be.eql g_fixtures.jwt_claim
    
    jwt_request.verify(fixtures.public_PEM_key).should.be.true


