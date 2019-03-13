/* eslint-env mocha */
const Assert = require('assert')
const Utils = require('../utils')
const FS = require('fs')

describe('Utils', function () {
  const jwkEC = {'kty': 'EC', 'crv': 'P-256', 'x': 'P77Gc65MCzCAFSL3ym4jzVkBHPFRk2wREBVmi94ga74', 'y': 'qjzjb7UInV3zDzN0wwkCaVqtyOLGaCmLBdLee9SXKQw'}
  const pemEC = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP77Gc65MCzCAFSL3ym4jzVkBHPFR
k2wREBVmi94ga76qPONvtQidXfMPM3TDCQJpWq3I4sZoKYsF0t571JcpDA==
-----END PUBLIC KEY-----`
  const hexEC = '043fbec673ae4c0b30801522f7ca6e23cd59011cf151936c111015668bde206bbeaa3ce36fb5089d5df30f3374c30902695aadc8e2c668298b05d2de7bd497290c'
  const jwkRSA = {'kty': 'RSA', 'n': 'zghKyUzealTP0yG2JlTcBSeYkA_WNKLCMZTQRbtEr9K11oaDsDmUSY-s3clehbbZ9SWNy9xydQfzb0BMdY2-omWT6kodYX8f-6p-4OCno3LHE5yM4UOkEZnc1lOz5VzUa-deMEwkLJXiquE1wQbnA6yaQIdy8vADNhIDhQKxIRFOFDbk1S01sEl-Oc3VFcY0VsoapCVpAEfr1LDCetOe6RxsvFDFex09nuvW5ehFbjioOvY6_jG-1ZcTKBasDVMWFLoECzlYfPBQfBiip2rWUzWW9chCnB0-b29Qg4R9n1glTVqqNQj0F9grWetJXw2NXQOVMKn-w81WzwH4s3IZQw', 'e': 'AQAB'}
  const pemRSA = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzghKyUzealTP0yG2JlTc
BSeYkA/WNKLCMZTQRbtEr9K11oaDsDmUSY+s3clehbbZ9SWNy9xydQfzb0BMdY2+
omWT6kodYX8f+6p+4OCno3LHE5yM4UOkEZnc1lOz5VzUa+deMEwkLJXiquE1wQbn
A6yaQIdy8vADNhIDhQKxIRFOFDbk1S01sEl+Oc3VFcY0VsoapCVpAEfr1LDCetOe
6RxsvFDFex09nuvW5ehFbjioOvY6/jG+1ZcTKBasDVMWFLoECzlYfPBQfBiip2rW
UzWW9chCnB0+b29Qg4R9n1glTVqqNQj0F9grWetJXw2NXQOVMKn+w81WzwH4s3IZ
QwIDAQAB
-----END PUBLIC KEY-----`

  context('serial', function () {
    it('Converts serialNo to address', function () {
      Assert.strictEqual(Utils.serialToAddress('e3b0c44298fc1c149afbf4c8996fb92427ae41e4'), '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4')
      Assert.strictEqual(Utils.serialToAddress('b0c44298fc1c149afbf4c8996fb92427ae41e4'), '0x00b0c44298fc1c149afbf4c8996fb92427ae41e4')
      Assert.strictEqual(Utils.serialToAddress('4'), '0x0000000000000000000000000000000000000004')
    })
    it('Is a NOP for addresses', function () {
      Assert.strictEqual(Utils.serialToAddress('0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4'), '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4')
    })
  })

  context('address', function () {
    it('Passes for valid addresses', function () {
      Assert.strictEqual(Utils.isAddress('0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4'), true)
      Assert.strictEqual(Utils.isAddress('0xE3b0c44298fC1c149afbf4D8996fb92427ae41e4'), true)
    })
    it('Fails for invalid addresses', function () {
      Assert.strictEqual(Utils.isAddress('asdf'), false)
      Assert.strictEqual(Utils.isAddress('0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), false)
    })
  })

  context('jwkToHex', function () {
    it('converts RSA public key', function () {
      const hexRSA = 'ce084ac94cde6a54cfd321b62654dc052798900fd634a2c23194d045bb44afd2b5d68683b03994498facddc95e85b6d9f5258dcbdc727507f36f404c758dbea26593ea4a1d617f1ffbaa7ee0e0a7a372c7139c8ce143a41199dcd653b3e55cd46be75e304c242c95e2aae135c106e703ac9a408772f2f0033612038502b121114e1436e4d52d35b0497e39cdd515c63456ca1aa425690047ebd4b0c27ad39ee91c6cbc50c57b1d3d9eebd6e5e8456e38a83af63afe31bed597132816ac0d531614ba040b39587cf0507c18a2a76ad6533596f5c8429c1d3e6f6f5083847d9f58254d5aaa3508f417d82b59eb495f0d8d5d039530a9fec3cd56cf01f8b3721943'
      Assert.strictEqual(Utils.jwkToHex(jwkRSA), hexRSA)
    })
    it('converts EC public key', function () {
      Assert.strictEqual(Utils.jwkToHex(jwkEC), hexEC)
    })
    it('throws on invalid jwk', function () {
      Assert.throws(() => Utils.jwkToHex({kty: 'RSA'}), /Unsupported/)
      Assert.throws(() => Utils.jwkToHex({}), /Unsupported/)
    })
    it('throws on RSA jwk with PK', function () {
      Assert.throws(() => Utils.jwkToHex({d: 's83ZmuWKtcqbpnME5112vxZqpKpCFctE4Jye_BneVxE', ...jwkEC}))
      Assert.throws(() => Utils.jwkToHex({d: 's83ZmuWKtcqbpnME5112vxZqpKpCFctE4Jye_BneVxE', ...jwkRSA}))
    })
  })

  context('hexToJwk', function () {
    it('EC public key', function () {
      const jwk = Utils.hexToJwk(hexEC)
      Assert.deepEqual(jwk, jwkEC)
    })
  })

  context('pemToJwk', function () {
    it('converts RSA public key', function () {
      Assert.deepStrictEqual(Utils.pemToJwk(pemRSA), jwkRSA)
      Assert.deepStrictEqual(Utils.pemToJwk(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNXFJO5cFMie4oQraVqnniopSW
V9hCut6WluPVbHblvqyH90dCqfZo+M6uABxixrxyWE/U6KJlAAnoSTW0qEuuAYlH
ZPFsmMv+kw7D1ZBoPBDsPvua0djiiVSyMzaaZHV/d2vABchUoCdp/CVPjpsSqnjH
xcbCgN76nCO1NGBgbQIDAQAB
-----END PUBLIC KEY-----`), {
        'e': 'AQAB',
        'kty': 'RSA',
        'n': 'zVxSTuXBTInuKEK2lap54qKUllfYQrrelpbj1Wx25b6sh_dHQqn2aPjOrgAcYsa8clhP1OiiZQAJ6Ek1tKhLrgGJR2TxbJjL_pMOw9WQaDwQ7D77mtHY4olUsjM2mmR1f3drwAXIVKAnafwlT46bEqp4x8XGwoDe-pwjtTRgYG0'
      })
    })
    it('converts EC public key', function () {
      Assert.deepStrictEqual(Utils.pemToJwk(pemEC), jwkEC)
    })
    it('converts small RSA public key', function () {
      Assert.deepStrictEqual(Utils.pemToJwk(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMiwb6VuAvJwHJyRZq1PJO8PpaaYjOXp
iUpBdB8ZntA5vj9KB/ke4HU3gO/hqLEXZ7JkBW6O+ID0ZWlubkqkD7UCAwEAAQ==
-----END PUBLIC KEY-----`),
      {
        'kty': 'RSA',
        'n': 'yLBvpW4C8nAcnJFmrU8k7w-lppiM5emJSkF0Hxme0Dm-P0oH-R7gdTeA7-GosRdnsmQFbo74gPRlaW5uSqQPtQ',
        'e': 'AQAB'
      })
    })
    it('converts small RSA public key, e=3', function () {
      Assert.deepStrictEqual(Utils.pemToJwk(`-----BEGIN PUBLIC KEY-----
MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBAM0cWN/vHXq5p6kIGCQ68JALYAUlUI/2
RcAR4NrO2TIb2+H5XpY6aLi27oedXXLq6EfYGEfSLxQ8jpkLFeG5BIkCAQM=
-----END PUBLIC KEY-----`),
      {
        'kty': 'RSA',
        'n': 'zRxY3-8dermnqQgYJDrwkAtgBSVQj_ZFwBHg2s7ZMhvb4fleljpouLbuh51dcuroR9gYR9IvFDyOmQsV4bkEiQ',
        'e': 'Aw'
      })
    })
    it('throws on invalid PEM', function () {
      Assert.throws(() => Utils.pemToJwk(``), /Unsupported/)
    })
  })

  context('jwkToPem', function () {
    it('converts RSA public key', function () {
      Assert.strictEqual(Utils.jwkToPem(jwkRSA), pemRSA)
    })
    it('converts EC public key', function () {
      Assert.strictEqual(Utils.jwkToPem(jwkEC), pemEC)
    })
    it('converts EC private key', function () {
      const jwk = {...jwkEC, d: 's83ZmuWKtcqbpnME5112vxZqpKpCFctE4Jye_BneVxE'}
      Assert.strictEqual(Utils.jwkToPem(jwk), `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILPN2ZrlirXKm6ZzBOdddr8WaqSqQhXLROCcnvwZ3lcRoAoGCCqGSM49
AwEHoUQDQgAEP77Gc65MCzCAFSL3ym4jzVkBHPFRk2wREBVmi94ga76qPONvtQid
XfMPM3TDCQJpWq3I4sZoKYsF0t571JcpDA==
-----END EC PRIVATE KEY-----`)
    })
  })

  context('mergeQueryParams', function () {
    it('accepts null arg', function () {
      Assert.strictEqual(Utils.mergeQueryParams('abc', null), 'abc')
    })
    it('merges params', function () {
      Assert.strictEqual(Utils.mergeQueryParams('abc', {a: 2, b: 'b c'}), 'abc?a=2&b=b%20c')
    })
  })

  context('sha256', function () {
    it('accepts and returns buffer', function () {
      Assert.ok(Utils.sha256(Buffer.from('')) instanceof Buffer, 'Expected instanceof Buffer')
    })
    it('takes optional encoding', function () {
      Assert.strictEqual(Utils.sha256('', 'hex'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
      Assert.strictEqual(Utils.sha256('', 'base64'), '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
    })
  })

  context('keccak256', function () {
    it('accepts and returns buffer', function () {
      Assert.ok(Utils.keccak256(Buffer.from('')) instanceof Buffer, 'Expected instanceof Buffer')
    })
    it('takes optional encoding', function () {
      Assert.strictEqual(Utils.keccak256('', 'hex'), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
      Assert.strictEqual(Utils.keccak256('', 'base64'), 'xdJGAYb3IzySfn2y3McDwOUAtlPKgic7e/rYBF2FpHA=')
    })
  })

  context('base64url', function () {
    it('takes Buffer, returns string', function () {
      const base64urlTest = '_-w'
      Assert.strictEqual(Utils.base64url(Buffer.from(base64urlTest, 'base64')), base64urlTest)
    })
  })

  context('jws', function () {
    const msg = 'msg'

    context('none', function () {
      it('verifyJws', function () {
        Assert.strictEqual(Utils.verifyJws('eyJhbGciOiJub25lIn0.bXNn.', '').toString(), msg)
      })
      it('verifyJws callback', function () {
        Assert.strictEqual(Utils.verifyJws('eyJhbGciOiJub25lIn0.bXNn.', jose => {
          Assert.deepStrictEqual(jose, {alg: 'none'})
          return ''
        }).toString(), msg)
      })
      it('verifyJws fail if sig present', function () {
        Assert.strictEqual(Utils.verifyJws('eyJhbGciOiJub25lIn0.bXNn.e8OZURoOjKajjBlfApR_nT8jbjdZakDJEfMDdqJhZhQ', ''), null)
      })
      it('verifyJws fail if secret given', function () {
        Assert.strictEqual(Utils.verifyJws('eyJhbGciOiJub25lIn0.bXNn.', 'secret'), null)
      })
    })

    context('ES256', function () {
      let cred
      before(async () => {
        cred = await Utils.generateKeyPair()
      })

      it('createEcdsaJws with credential', function () {
        const jws = Utils.createEcdsaJws(msg, cred)
        const [h, m, s] = jws.split('.').map(p => Buffer.from(p, 'base64').toString('binary'))
        Assert.strictEqual(h, '{"alg":"ES256"}')
        Assert.strictEqual(m, msg)
        Assert.strictEqual(s.length, 64)
      })
      it('createEcdsaJws+verifyJws', function () {
        const jws = Utils.createEcdsaJws(msg, cred)
        Assert.strictEqual(Utils.verifyJws(jws, cred).toString(), msg)
      })
      it('createEcdsaJws+verifyJws callback', function () {
        const jws = Utils.createEcdsaJws(msg, cred)
        Assert.strictEqual(Utils.verifyJws(jws, jose => {
          Assert.deepStrictEqual(jose, {alg: 'ES256'})
          return cred.pubKeyHex
        }).toString(), msg)
      })
      it('createEcdsaJws+verifyJws with JWK', function () {
        const jwk = Utils.hexToJwk(cred.pubKeyHex)
        const jws = Utils.createEcdsaJws(msg, cred)
        Assert.strictEqual(Utils.verifyJws(jws, jwk).toString(), msg)
      })
      it('createEcdsaJws+verifyJws JWT', function () {
        const payload = {iat: 1234, msg}
        const jws = Utils.createEcdsaJws(payload, cred, {typ: 'JWT'})
        Assert.deepEqual(Utils.verifyJws(jws, cred), payload)
      })
      it('createEcdsaJws+verifyJws pubKeyHex', function () {
        const jws = Utils.createEcdsaJws(msg, cred)
        Assert.strictEqual(Utils.verifyJws(jws, cred.pubKeyHex).toString(), msg)
      })
    })

    context('HS256', function () {
      const JWS = 'eyJhbGciOiJIUzI1NiJ9.bXNn.e8OZURoOjKajjBlfApR_nT8jbjdZakDJEfMDdqJhZhQ'
      const secret = 'secret'

      it('createHmacJws with secret', function () {
        const jws = Utils.createHmacJws(msg, secret)
        Assert.strictEqual(jws, JWS)
        const [h, m, s] = jws.split('.').map(p => Buffer.from(p, 'base64').toString('binary'))
        Assert.strictEqual(h, '{"alg":"HS256"}')
        Assert.strictEqual(m, msg)
        Assert.strictEqual(s.length, 32)
      })
      it('verifyJws', function () {
        Assert.strictEqual(Utils.verifyJws(JWS, secret).toString(), msg)
      })
      it('verifyJws callback', function () {
        Assert.strictEqual(Utils.verifyJws(JWS, jose => {
          Assert.deepStrictEqual(jose, {alg: 'HS256'})
          return secret
        }).toString(), msg)
      })
      it('verifyJws with wrong secret', function () {
        Assert.strictEqual(Utils.verifyJws(JWS, 'wrong secret'), null)
      })
      it('createHmacJws+verifyJws JWT', function () {
        const payload = {iat: 1234, msg}
        const jws = Utils.createHmacJws(payload, secret, {typ: 'JWT'})
        Assert.deepStrictEqual(Utils.verifyJws(jws, secret), payload)
      })
    })
  })

  context('parseHexString', function () {
    it('parses hex into string', function () {
      Assert.strictEqual(Utils.parseHexString('00'), '\0')
    })
  })

  context('parseX509Date', function () {
    it('parses string into date', function () {
      Assert.ok(Utils.parseX509Date('141213110908Z') instanceof Date)
    })
    it('parses short string into date', function () {
      Assert.strictEqual(Utils.parseX509Date('141213110908Z').toUTCString(), 'Sat, 13 Dec 2014 11:09:08 GMT')
    })
    it('parses long string into date', function () {
      Assert.strictEqual(Utils.parseX509Date('19141213110908Z').toUTCString(), 'Sun, 13 Dec 1914 11:09:08 GMT')
    })
  })

  context('dateToString', function () {
    it('turns current Date into string', function () {
      Assert.strictEqual(typeof Utils.dateToString(new Date()), 'string')
    })
    it('turns past Date into short string', function () {
      Assert.strictEqual(Utils.dateToString(new Date(Date.UTC(1970, 0, 1, 0, 2, 3))), '700101000203Z')
    })
    it('turns future Date into long string', function () {
      Assert.strictEqual(Utils.dateToString(new Date(Date.UTC(2080, 0, 1, 0, 0, 0))), '20800101000000Z')
    })
  })

  it('has path to tkroot', function () {
    const tkroot = Utils.getRootPemPath()
    Assert.ok(/^\/.+\/tkroot.pem$/.test(tkroot), 'Not an absolute path to tkroot.pem')
  })

  context('getJwkThumbprint', function () {
    it('getJwkThumbprint(jwkEC)', function () {
      const thumbprint = Utils.getJwkThumbprint(jwkEC)
      Assert.strictEqual(thumbprint, 't0SeLs6tHEgrSplyGDH-Sb600WfOgDWFbxfJsWnFlVQ')
    })

    it('getJwkThumbprint(jwkRSA)', function () {
      const thumbprint = Utils.getJwkThumbprint(jwkRSA)
      Assert.strictEqual(thumbprint, 'E74oqrEZWBKPrFTjsNLeIUtnVKMm2EW5ZhpNEaV-4RY')
    })

    it('ignore optional members (jwkEC)', function () {
      const thumbprint = Utils.getJwkThumbprint({...jwkEC, opt: 123})
      Assert.strictEqual(thumbprint, 't0SeLs6tHEgrSplyGDH-Sb600WfOgDWFbxfJsWnFlVQ')
    })

    it('ignore optional members (jwkRSA)', function () {
      const thumbprint = Utils.getJwkThumbprint({...jwkRSA, opt: 123})
      Assert.strictEqual(thumbprint, 'E74oqrEZWBKPrFTjsNLeIUtnVKMm2EW5ZhpNEaV-4RY')
    })

    it('key order doesn\'t matter', function () {
      const jwkEC2 = Object.entries(jwkEC).reduceRight((p, [k, v]) => ({...p, [k]: v}), {})
      const thumbprint = Utils.getJwkThumbprint(jwkEC2)
      Assert.strictEqual(thumbprint, 't0SeLs6tHEgrSplyGDH-Sb600WfOgDWFbxfJsWnFlVQ')
    })
  })

  const CommonNamePEM = `-----BEGIN CERTIFICATE-----
MIIC3zCCAkqgAwIBAgIUXirhK4wUAJPiLMOaKoNm7LPygJ0wCwYJKoZIhvcNAQEL
MHIxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdTZWF0dGxlMRAwDgYDVQQHDAdTZWF0
dGxlMRkwFwYDVQQKDBBUcnVzdGVkIEtleSB0ZXN0MQswCQYDVQQLDAJJVDEXMBUG
A1UEAwwOdHJ1c3RlZGtleS5jb20wHhcNMTgwODE1MDUyMzE5WhcNMTkwODE1MDUy
MzE5WjB+MTIwMAYKKwYBBAGZtqUXAQwidGVzdDAuNTQ0MDI2NTY1MTI5MTk0MkBl
eGFtcGxlLmNvbTEVMBMGCisGAQQBmbalFwYMBUVtYWlsMTEwLwYJKoZIhvcNAQkB
DCJ0ZXN0MC41NDQwMjY1NjUxMjkxOTQyQGV4YW1wbGUuY29tMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEdspUievqnYouHiMH59o3WBf0T0N8u1/o/T+1v0quVGp1
8loTHIx4Z61y0oWpFZhB2s3KrKObWcqHLKPB8c7Pr6OBsDCBrTAfBgNVHSMEGDAW
gBQejFCw55gOlNPaar6PfScFCRqe8jAMBgNVHRMBAf8EAjAAMEQGA1UdHwQ9MDsw
OaA3oDWGM2V0aGVyZXVtOjB4NDg2MjRiZWFhZDE0ZWEzODZlMjE4NTgzOWFhMTBj
MWZhZjZiOTczYTA2BggrBgEFBQcBAQQqMCgwJgYIKwYBBQUHMAGGGmh0dHA6Ly9v
Y3NwLnRydXN0ZWRrZXkuY29tMAsGCSqGSIb3DQEBCwOBgQAmwx5os70/C15SA5HQ
fOTUINYvhyedJDoeE/SoEXMIfweeTDCzQ/p6/QavYo1MdH2xXeiAoFHnA7kMZLr1
JB/s48mt2utkQblZCGaEqdwJMWJtbqa0fP6Rrl7Gj1c/CetnYUHyqR7tXHBOefTB
NBtwmvc2VcFjR3HVBpjtVtxnkA==
-----END CERTIFICATE-----`

  const IssuerPEM = `-----BEGIN CERTIFICATE-----
MIIC9TCCAl6gAwIBAgIJAOlzOVIJxpMrMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNV
BAYTAlVTMRAwDgYDVQQIDAdTZWF0dGxlMRAwDgYDVQQHDAdTZWF0dGxlMRkwFwYD
VQQKDBBUcnVzdGVkIEtleSB0ZXN0MQswCQYDVQQLDAJJVDEXMBUGA1UEAwwOdHJ1
c3RlZGtleS5jb20wHhcNMTgwODE0MjMwNjQzWhcNMTgwODE1MjMwNjQzWjByMQsw
CQYDVQQGEwJVUzEQMA4GA1UECAwHU2VhdHRsZTEQMA4GA1UEBwwHU2VhdHRsZTEZ
MBcGA1UECgwQVHJ1c3RlZCBLZXkgdGVzdDELMAkGA1UECwwCSVQxFzAVBgNVBAMM
DnRydXN0ZWRrZXkuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDYIP4g
x5CpzYawSeEMgtqqmDginuynxo3kikWyup+fo3Fq9qNT5P9+yEbXkzWB9ExwQ6Dq
TOqQGr2ErUp99fTuvbnfuXfICUgSH6brsM2siETLgZIH7A72zPRL8HOBC+2qaeGG
1yppZrIJBcAsAK5WxSKVmDGZGGDzsmJF6xFnnQIDAQABo4GSMIGPMBIGA1UdEwEB
/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgIEMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NM
IEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQUHoxQsOeYDpTT2mq+j30n
BQkanvIwHwYDVR0jBBgwFoAUHoxQsOeYDpTT2mq+j30nBQkanvIwDQYJKoZIhvcN
AQELBQADgYEAH7Go0o8PGkS2QUXMSiFAm2UKU0GUFI17B6D1zxRyDpo6BI0AkbVl
7320vYzyGU8RpINRUb+A4zGvBKre32hOAIEluECNSQzwKdjibKzQ0FrLFj3UBeE8
bPCx2Tty0FQNeijKZWRnH7H9dwqFS1eDYm2DRyAt/FDYQPdFz/hRtVo=
-----END CERTIFICATE-----`

  context('parsePem', function () {
    it('parse EC PEM and attributes', function () {
      const parsed = Utils.parsePem(CommonNamePEM)
      Assert.deepStrictEqual(parsed, {
        'subjectaddress': '0xc0a4afdef2b560e61576117d4c8e6b38cdf68467',
        'serialNo': '0x5e2ae12b8c140093e22cc39a2a8366ecb3f2809d',
        'notAfter': new Date('2019-08-15T05:23:19.000Z'),
        'notBefore': new Date('2018-08-15T05:23:19.000Z'),
        'issuer': '/C=US/ST=Seattle/L=Seattle/O=Trusted Key test/OU=IT/CN=trustedkey.com',
        'issuerPem': null,
        'attributes': [{
          'oid': '1.3.6.1.4.1.53318295.1',
          'value': 'test0.5440265651291942@example.com'
        },
        {
          'oid': '1.3.6.1.4.1.53318295.6',
          'value': 'Email'
        },
        {
          'oid': '1.2.840.113549.1.9.1',
          'value': 'test0.5440265651291942@example.com'
        }],
        'caissuer': [],
        'crl': ['ethereum:0x48624beaad14ea386e2185839aa10c1faf6b973a'],
        'ocsp': ['http://ocsp.trustedkey.com']
      })
    })

    it('parse RSA PEM', function () {
      Assert.doesNotThrow(() => Utils.parsePem(IssuerPEM))
    })

    it('parse PEM without header', function () {
      Assert.doesNotThrow(() => Utils.parsePem(CommonNamePEM.replace(/-----[^-]+-----|\r|\n/g, '')))
    })

    it('parse PEM and fail without CA certs', function () {
      Assert.throws(() => Utils.parsePem(CommonNamePEM, []), /Signature verification failed$/)
    })

    it('parse PEM and fail with unknown issuer', function () {
      Assert.throws(() => Utils.parsePem(CommonNamePEM, [CommonNamePEM]), /Signature verification failed$/)
    })

    it('parse PEM and succeed with valid signature', function () {
      Assert.doesNotThrow(() => Utils.parsePem(CommonNamePEM, [IssuerPEM]))
    })

    it('parse PEM and succeed with multiple issuers', function () {
      Assert.strictEqual(Utils.parsePem(CommonNamePEM, [CommonNamePEM, IssuerPEM]).issuerPem, IssuerPEM)
    })

    it('parse issuer PEM', function () {
      const parsed = Utils.parsePem(IssuerPEM)
      Assert.deepStrictEqual(parsed, {
        'attributes': [
          {
            'oid': '2.5.4.6',
            'value': 'US'
          },
          {
            'oid': '2.5.4.8',
            'value': 'Seattle'
          },
          {
            'oid': '2.5.4.7',
            'value': 'Seattle'
          },
          {
            'oid': '2.5.4.10',
            'value': 'Trusted Key test'
          },
          {
            'oid': '2.5.4.11',
            'value': 'IT'
          },
          {
            'oid': '2.5.4.3',
            'value': 'trustedkey.com'
          }
        ],
        'issuer': '/C=US/ST=Seattle/L=Seattle/O=Trusted Key test/OU=IT/CN=trustedkey.com',
        'issuerPem': null,
        'notAfter': new Date('2018-08-15T23:06:43.000Z'),
        'notBefore': new Date('2018-08-14T23:06:43.000Z'),
        'serialNo': '0x000000000000000000000000e973395209c6932b',
        'subjectaddress': undefined,
        'caissuer': [],
        'crl': [],
        'ocsp': []
      })
    })

    it('parse tkroot', function () {
      const tkroot = FS.readFileSync(Utils.getRootPemPath(), 'ascii')
      Assert.doesNotThrow(() => Utils.parsePem(tkroot, [tkroot]))
    })

    it('validate self-signed PEM', function () {
      Assert.doesNotThrow(() => Utils.parsePem(IssuerPEM, [IssuerPEM]))
    })
  })

  context('wait*', function () {
    it('wait', async function () {
      const now = new Date()
      await Utils.wait(50)
      Assert.ok(new Date().getTime() - now >= 50)
    })

    it('waitUntil immediate', async function () {
      const now = new Date()
      Assert.strictEqual(await Utils.waitUntil(500, () => 2), 2)
      Assert.ok(new Date().getTime() - now < 500)
    })

    it('waitUntil timeout', async function () {
      const now = new Date()
      Assert.strictEqual(await Utils.waitUntil(50, () => false), false)
      Assert.ok(new Date().getTime() - now >= 50)
    })
  })

  context('validateClaim', function () {
    let claim

    before(function () {
      claim = Utils.parsePem(CommonNamePEM, [IssuerPEM])
    })

    it('validates', () => {
      Assert.strictEqual(Utils.validateClaim(claim, new Date('2018-08-15T15:23:19.000Z')), true)
    })

    it('validates notBefore', () => {
      Assert.strictEqual(Utils.validateClaim(claim, new Date('2018-08-15T04:23:19.000Z')), false)
    })

    it('validates notAfter', () => {
      Assert.strictEqual(Utils.validateClaim(claim, new Date('2019-08-16T05:23:19.000Z')), false)
    })

    it('validates issuer notBefore', () => {
      Assert.strictEqual(Utils.validateClaim(claim, new Date('2018-08-14T05:23:19.000Z')), false)
    })

    it('validates issuer notAfter', () => {
      Assert.strictEqual(Utils.validateClaim(claim, new Date('2018-08-16T05:23:19.000Z')), false)
    })
  })

  context('verifyChain', function () {
    const OtherIssuer = `-----BEGIN CERTIFICATE-----
MIIDKTCCApKgAwIBAgIJAJD3lnm9KEylMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNV
BAYTAlVTMRAwDgYDVQQIDAdTZWF0dGxlMRAwDgYDVQQHDAdTZWF0dGxlMRkwFwYD
VQQKDBBUcnVzdGVkIEtleSB0ZXN0MQswCQYDVQQLDAJJVDEXMBUGA1UEAwwOdHJ1
c3RlZGtleS5jb20wHhcNMTkwMjI2MDA1NjIzWhcNMTkwMjI3MDA1NjIzWjByMQsw
CQYDVQQGEwJVUzEQMA4GA1UECAwHU2VhdHRsZTEQMA4GA1UEBwwHU2VhdHRsZTEZ
MBcGA1UECgwQVHJ1c3RlZCBLZXkgdGVzdDELMAkGA1UECwwCSVQxFzAVBgNVBAMM
DnRydXN0ZWRrZXkuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDJ0ZiA
lCqQ4BhdmtS1gZG9QaU8bgq7OzBuU2TRrSHcYHQ8FsUY7ODlj0WX7OAjSsUgzZDM
KIoHlslfOA+o1R8kbBOM+VwsaYXqy46KeYoaldqyKajk9Wi/oG9lJxRvgbwLNZyW
Z3hmiX4zOqYMjpBPgy/mPeZAyMXRPAyDxllaTwIDAQABo4HGMIHDMBIGA1UdEwEB
/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgIEMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NM
IEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU9+P74t278atxUxOQRp5X
jkItuGwwHwYDVR0jBBgwFoAU9+P74t278atxUxOQRp5XjkItuGwwMgYIKwYBBQUH
AQEEJjAkMCIGCCsGAQUFBzABhhZodHRwOi8vbG9jYWxob3N0OjMwMDEvMA0GCSqG
SIb3DQEBCwUAA4GBAAmQzCx4U+vorJ7sfIPTVo+Dsy2zccsa4K7sKKJexDiEm17x
096elIYekKW1uhnNp8Tvtvi8v8mc/TUawKpT3gITosa+xrkCfhHLDHKMYa1H+Ffb
rpJ7fDZTnj4PPe2O0Af1GwBngShMfghoemeH1/vgyhKnxhjqxqHu0UWDfjt0
-----END CERTIFICATE-----`

    it('parse chain with self signed (Issuer)', function () {
      Assert.strictEqual(Utils.verifyChain([IssuerPEM]), true)
    })

    it('parse chain with self signed (OtherIssuer)', function () {
      Assert.strictEqual(Utils.verifyChain([OtherIssuer]), true)
    })

    it('parse chain should fail without self signed cert', function () {
      Assert.strictEqual(Utils.verifyChain([CommonNamePEM]), false)
    })

    it('parse chain should fail with invalid chain', function () {
      Assert.strictEqual(Utils.verifyChain([CommonNamePEM, OtherIssuer]), false)
    })

    it('parse chain should fail with incorrect order', function () {
      Assert.strictEqual(Utils.verifyChain([IssuerPEM, CommonNamePEM]), false)
    })

    it('parse chain with correct issuer', function () {
      Assert.strictEqual(Utils.verifyChain([CommonNamePEM, IssuerPEM]), true)
    })
  })
})
