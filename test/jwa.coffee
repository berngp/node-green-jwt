# Node
fs  = require "fs"
# Tests
should = require "should"
# Self
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

fixtures =
  dataString : JSON.stringify( {att1 : "value", att2 : 1} )


describe 'JWA Implementation for MAC', ->

  # Known Algorithms that should be asserted as defined by the JWA specification 
  knownAlg = ["HS256", "HS384", "HS512"]
  # Known HMAC Key
  hmacKey = "hmac-key"

  # Precalculated expectations, note that they are base64 - URL Encoded
  expectations =
    HS256 : "6SN4r6MZmNNKkok0iK0E8bu9H7zoRHYZXXhPLr5M6eU%3D"
    HS384 : "Mqzvb4sukLBQ9MTVroERBO%2FPMUwwe03hi4BVQoEPo0lc3z32vd8mX0YSfsM%2FhX96"
    HS512 : "qG1p5FRVIbAG02OSFc%2F3JlRflbLeVyBe5jJmejM8%2F%2BJHVD56ia2A5JOFJ3p%2F0uulG7fQQ4M%2FswGvqMlukUOhNw%3D%3D"

  # We generate permutations per known algorithm to assert the creation of the HMAC instance
  # and digestion of the data.
  ( (alg) =>
    # specification of the supporting algorithm
    it "supports #{alg}", ->
      #instance of the HMAC given the algorithm and key
      hmac = jwa.provider(alg)(hmacKey)
      should.exist hmac
      # update the hmac algorithm instance with the kown data 
      hmac.update(fixtures.dataString)
      # digest the data with the current algorithm (alg) and key (hmacKey)
      digest = hmac.digest()
      # assert the value against the expected value.
      digest.should.equal expectations[alg]
  
  )(alg) for alg in knownAlg


  it "should throw an error if an invalid algorithm is provided", ->
    ( () -> jwa.HMACFactory "HS124", hmacKey ).should.throw()



describe 'JWA Implementation for RSA', ->

  # Known Algorithms that should be asserted as defined by the JWA specification
  kownAlg = ["RS256", "RS384", "RS512"]
  # Known RSA Private Key
  key_PEM = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----  
"""
  # Precalcualted Expectations (note that they are already base64 - URL Encoded)
  expectations =
    RS256: "NrkVPyb9Uux7bZNKrj4k5lK1tgYU8qom8q7m0tGfFAxRxESeEi6E60Aq1zO8fFwJDANLh8Ny1qO29xbv3jkFUoGB5OOYbFmCOW%2FJZMPX%2BDBZzp6DpCvM8vFuo5PSbgZrh4oYhS7PAObU9prekIRCWeVl52tecc3bJFTunP7l35Ot%2BBMSkiG2tZ2sMMGxa08TsF1DML%2FPAbYeO0u%2BGZ2M4bZe5PA1upnpPCHdV%2FWjaX3uUtcr4cQ2IeeLi5Ajo1MDr%2Boc1Qub%2FOaBERXwsYD2mhllBtIXsiJyNX8D3lWsaK4TeNWLQ62hvJcsXIkGaVaXoPgJOjrKumcQ5YtyUynDhQ%3D%3D"

    RS384: "TfO2Y7smnasGGhy4Y0gMQ7aZb739KmaQzbYOFK%2BVZ7QssxRSzeJvCL4YfoJybPwsYb6UyqHtBmhIc6KnwBhFmH5HIm%2FstvvXjCdykkHG4%2FlsA%2FjO%2FmAEFABhXZFr1Iu4MPJvXfs3%2BxIOsnVFkbUtv7%2FB8Lbt9yglYFgRUCNacgRDUm8UvY9zi1iM%2BwEmxKYAJiYhlqsxaa0zk36x67B5QPf6jvcd%2FdiPLuw7JRuprR%2Fd11QBLZSW%2B4cXi6KIF%2FH07O%2Bg6pvMOLtiIpESOdNzcGcxk5uCZIsONbE%2BJVde20mhILshjYnqS7Npz0Vy%2BrwmiLF%2FPaHyR%2FVcP4Cl8A5utQ%3D%3D"

    RS512: "SgSO79ZDzvzFbiVM%2BXIMSf8FLQooWpdqQIFm0yX9469La%2FWl3YaZ%2BBcsDlHXQbi2M3%2FDAyfR0sSNeLMj2sWkga21Rj2u7xb7bvW689hHTvol4uP1pv88kZDUmJ1qjz7jeGfV78glPAJE4B3Sl1Lj71SgpaFeB9MkKM6VbZL1l98VjjcmNc9Qz9oRqQQyQtTWj4bV2r1lRqobPzmC5yfd5ZrSMqN5O09Z7MZkNLePyhX3x%2FqhC9qvSNdE1oj%2BRVa71QOy6tsrloTRtBmfJDd66rC7WnFkcGxU%2Fv0jlaWpCWX%2FqsG518nJwSz2EvSDNQPMd17oiMBY7syX8KJLCbum9Q%3D%3D"

    # We generate the assertions by the given permutations of the known algorithms defined above.
  ( (alg) =>
    it "supports #{alg}", ->
      rsSigner = jwa.provider(alg)(key_PEM)
      rsSigner.update(fixtures.dataString)
      signed = rsSigner.sign()

      signed.should.equal expectations[alg]
  
  )(alg) for alg in kownAlg



