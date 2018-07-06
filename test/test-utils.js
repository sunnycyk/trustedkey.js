/* eslint-env mocha */
const Assert = require('assert')
const Utils = require('../utils')
const FS = require('fs')

describe('Utils', () => {
  const jwkEC = {'kty': 'EC', 'crv': 'P-256', 'x': 'P77Gc65MCzCAFSL3ym4jzVkBHPFRk2wREBVmi94ga74', 'y': 'qjzjb7UInV3zDzN0wwkCaVqtyOLGaCmLBdLee9SXKQw'}
  const pemEC = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP77Gc65MCzCAFSL3ym4jzVkBHPFR
k2wREBVmi94ga76qPONvtQidXfMPM3TDCQJpWq3I4sZoKYsF0t571JcpDA==
-----END PUBLIC KEY-----`
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

  context('serial', () => {
    it('Converts serialNo to address', () => {
      Assert.strictEqual(Utils.serialToAddress('e3b0c44298fc1c149afbf4c8996fb92427ae41e4'), '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4')
      Assert.strictEqual(Utils.serialToAddress('b0c44298fc1c149afbf4c8996fb92427ae41e4'), '0x00b0c44298fc1c149afbf4c8996fb92427ae41e4')
      Assert.strictEqual(Utils.serialToAddress('4'), '0x0000000000000000000000000000000000000004')
    })
    it('Is a NOP for addresses', () => {
      Assert.strictEqual(Utils.serialToAddress('0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4'), '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4')
    })
  })

  context('address', () => {
    it('Passes for valid addresses', () => {
      Assert.strictEqual(Utils.isAddress('0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4'), true)
      Assert.strictEqual(Utils.isAddress('0xE3b0c44298fC1c149afbf4D8996fb92427ae41e4'), true)
    })
    it('Fails for invalid addresses', () => {
      Assert.strictEqual(Utils.isAddress('asdf'), false)
      Assert.strictEqual(Utils.isAddress('0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), false)
    })
  })

  context('jwkToHex', () => {
    it('converts RSA key', () => {
      const hex = 'ce084ac94cde6a54cfd321b62654dc052798900fd634a2c23194d045bb44afd2b5d68683b03994498facddc95e85b6d9f5258dcbdc727507f36f404c758dbea26593ea4a1d617f1ffbaa7ee0e0a7a372c7139c8ce143a41199dcd653b3e55cd46be75e304c242c95e2aae135c106e703ac9a408772f2f0033612038502b121114e1436e4d52d35b0497e39cdd515c63456ca1aa425690047ebd4b0c27ad39ee91c6cbc50c57b1d3d9eebd6e5e8456e38a83af63afe31bed597132816ac0d531614ba040b39587cf0507c18a2a76ad6533596f5c8429c1d3e6f6f5083847d9f58254d5aaa3508f417d82b59eb495f0d8d5d039530a9fec3cd56cf01f8b3721943'
      Assert.strictEqual(Utils.jwkToHex(jwkRSA), hex)
    })
    it('converts EC key', () => {
      const hex = '043fbec673ae4c0b30801522f7ca6e23cd59011cf151936c111015668bde206bbeaa3ce36fb5089d5df30f3374c30902695aadc8e2c668298b05d2de7bd497290c'
      Assert.strictEqual(Utils.jwkToHex(jwkEC), hex)
    })
    it('throws on invalid jwk', () => {
      Assert.throws(() => Utils.jwkToHex({kty: 'RSA'}), /Unsupported/)
      Assert.throws(() => Utils.jwkToHex({}), /Unsupported/)
    })
    it('throws on RSA jwk with PK', () => {
      Assert.throws(() => Utils.jwkToHex(Object.assign({d: 's83ZmuWKtcqbpnME5112vxZqpKpCFctE4Jye_BneVxE'}, jwkEC)))
      Assert.throws(() => Utils.jwkToHex(Object.assign({d: 's83ZmuWKtcqbpnME5112vxZqpKpCFctE4Jye_BneVxE'}, jwkRSA)))
    })
  })

  context('pemToJwk', () => {
    it('converts RSA key', () => {
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
    it('converts EC key', () => {
      Assert.deepStrictEqual(Utils.pemToJwk(pemEC), jwkEC)
    })
    it('converts small RSA key', () => {
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
    it('converts small RSA key, e=3', () => {
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
    it('throws on invalid PEM', () => {
      Assert.throws(() => Utils.pemToJwk(``), /Unsupported/)
    })
  })

  context('jwkToPem', () => {
    it('converts RSA key', () => {
      Assert.strictEqual(Utils.jwkToPem(jwkRSA), pemRSA)
    })
    it('converts EC key', () => {
      Assert.strictEqual(Utils.jwkToPem(jwkEC), pemEC)
    })
  })

  context('mergeQueryParams', () => {
    it('accepts null arg', () => {
      Assert.strictEqual(Utils.mergeQueryParams('abc', null), 'abc')
    })
    it('merges params', () => {
      Assert.strictEqual(Utils.mergeQueryParams('abc', {a: 2, b: 'b c'}), 'abc?a=2&b=b%20c')
    })
  })

  context('sha256', () => {
    it('accepts and returns buffer', () => {
      Assert.ok(Utils.sha256(Buffer.from('')) instanceof Buffer)
    })
    it('takes optional encoding', () => {
      Assert.strictEqual(Utils.sha256('', 'hex'), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    })
  })

  context('base64url', () => {
    it('takes Buffer, returns string', () => {
      Assert.strictEqual(Utils.base64url(Buffer.from('_-w', 'base64')), '_-w')
    })
  })

  context('parseHexString', () => {
    it('parses hex into string', () => {
      Assert.strictEqual(Utils.parseHexString('00'), '\0')
    })
  })

  context('parseX509Date', () => {
    it('parses string into date', () => {
      Assert.ok(Utils.parseX509Date('141213110908Z') instanceof Date)
    })
    it('parses short string into date', () => {
      Assert.strictEqual(Utils.parseX509Date('141213110908Z').toUTCString(), 'Sat, 13 Dec 2014 11:09:08 GMT')
    })
    it('parses long string into date', () => {
      Assert.strictEqual(Utils.parseX509Date('19141213110908Z').toUTCString(), 'Sun, 13 Dec 1914 11:09:08 GMT')
    })
  })

  context('dateToString', () => {
    it('turns current Date into string', () => {
      Assert.strictEqual(typeof Utils.dateToString(new Date()), 'string')
    })
    it('turns past Date into short string', () => {
      Assert.strictEqual(Utils.dateToString(new Date(Date.UTC(1970, 0, 1, 0, 2, 3))), '700101000203Z')
    })
    it('turns future Date into long string', () => {
      Assert.strictEqual(Utils.dateToString(new Date(Date.UTC(2080, 0, 1, 0, 0, 0))), '20800101000000Z')
    })
  })

  it('has path to tkroot', () => {
    const tkroot = Utils.getRootPemPath()
    Assert.ok(/^\/.+\/tkroot.pem$/.test(tkroot), 'Not an absolute path to tkroot.pem')
  })

  context('parsePem', () => {
    const CommonName = `-----BEGIN CERTIFICATE-----
MIIC+zCCAeWgAwIBAgIUPVlIf+L8kP4jMojpa4ga/Jra+n0wCwYJKoZIhvcNAQEL
MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdT
ZWF0dGxlMSMwIQYDVQQKExpUcnVzdGVkIEtleSBTb2x1dGlvbnMgSW5jLjEjMCEG
A1UEAxMaVHJ1c3RlZCBLZXkgRGVtbyBBdXRob3JpdHkwHhcNMTYxMDI1MDMxODA5
WhcNMTYxMTAxMDAwMDAwWjA8MSMwIQYKKwYBBAGZtqUXAQwTV0EgRHJpdmVyJ3Mg
TGljZW5zZTEVMBMGA1UEAwwMUm9iZXJ0YSBXb25nMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAES9YTcTzRKCY590x1jXa0bdaDrsiw/NcBjOGQcl1VWMeU5VgvudG2
vzaW+5Ju6FnyDwkYF+vTUPYxjcJa/Fr65aOBgTB/MAkGA1UdEwQCMAAwCwYDVR0P
BAQDAgbAMB8GA1UdIwQYMBaAFO68m9/ft3F1ynsyqyGq9TqLsfaiMEQGA1UdHwQ9
MDswOaA3oDWGM2V0aGVyZXVtOjB4NzFlNGM5MTRkZGM4ZDAxMjdmNGIyZGU3ZjVl
ZTBkMDU4YzYwMTg5MDALBgkqhkiG9w0BAQsDggEBAHetkZo9pjY22WHs5fpaDIjx
beHtscgOV47diVQiZqVVep9XjZ1NLQ6InZ+Iu6IwCuBPHYY13ItiLFVXexCPUNfY
L2ugY2vY3Rx5ywC2DPY8U5w3n72zkW7gQpi1J/xxq4gBTQ0p1Y0oLRz2U1z7UXwo
l1d6MfN+5n3I4xZ9EQ04UD6AzVq7TL3pz6rTVWz4f3geJVOLZ3/hk4MBBX8BzHiG
HQ4PIlgKkxOnoxz2G2rxFF+eZi9W4upvT4umwijgTRMSq7lE1nyZ3iejIeh1C/T/
Zg1WLttDTehDBl89HjfY/b8HcPFQMqJJ3k0s9K2T1V/vXOCnDBOEFisi5/Km+jw=
-----END CERTIFICATE-----`
    const Issuer = `-----BEGIN CERTIFICATE-----
MIIFgTCCA2mgAwIBAgIJAMoJWj+EpMt1MA0GCSqGSIb3DQEBBQUAMH0xCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdTZWF0dGxlMSMw
IQYDVQQKExpUcnVzdGVkIEtleSBTb2x1dGlvbnMgSW5jLjEiMCAGA1UEAxMZVHJ1
c3RlZCBLZXkgQ0EgKDQwOTYgYml0KTAeFw0xNjA5MTQxMDE4MDFaFw0xNzA5MTQx
MDE4MDFaMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD
VQQHEwdTZWF0dGxlMSMwIQYDVQQKExpUcnVzdGVkIEtleSBTb2x1dGlvbnMgSW5j
LjEjMCEGA1UEAxMaVHJ1c3RlZCBLZXkgRGVtbyBBdXRob3JpdHkwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOCErJTN5qVM/TIbYmVNwFJ5iQD9Y0osIx
lNBFu0Sv0rXWhoOwOZRJj6zdyV6Fttn1JY3L3HJ1B/NvQEx1jb6iZZPqSh1hfx/7
qn7g4KejcscTnIzhQ6QRmdzWU7PlXNRr514wTCQsleKq4TXBBucDrJpAh3Ly8AM2
EgOFArEhEU4UNuTVLTWwSX45zdUVxjRWyhqkJWkAR+vUsMJ6057pHGy8UMV7HT2e
69bl6EVuOKg69jr+Mb7VlxMoFqwNUxYUugQLOVh88FB8GKKnatZTNZb1yEKcHT5v
b1CDhH2fWCVNWqo1CPQX2CtZ60lfDY1dA5Uwqf7DzVbPAfizchlDAgMBAAGjggEB
MIH+MBIGA1UdEwEB/wQIMAYBAf8CAQAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIw
HQYDVR0OBBYEFO68m9/ft3F1ynsyqyGq9TqLsfaiMIGwBgNVHSMEgagwgaWAFKWk
kv2Io6I+s4NCUP/8txnVUzL8oYGBpH8wfTELMAkGA1UEBhMCVVMxEzARBgNVBAgT
Cldhc2hpbmd0b24xEDAOBgNVBAcTB1NlYXR0bGUxIzAhBgNVBAoTGlRydXN0ZWQg
S2V5IFNvbHV0aW9ucyBJbmMuMSIwIAYDVQQDExlUcnVzdGVkIEtleSBDQSAoNDA5
NiBiaXQpggkAnFIAoCPisjswDQYJKoZIhvcNAQEFBQADggIBADeHZjPBIepD6u74
PymvazA2moXp/qZvUyfr/velUUZCNi7B0ys2gDdfCtC0AmdbndbMvtmDDK9nzVFQ
AXUINRyKTrtscsRGRarKEaqU9NCUQa2oxyVmSB/iBKxhndle0tnIHX8uplIhKoY5
w84jA3qvahZkEiuf6UP2ZQ7mPc3XAS2LKggL7GVhlvjdU+XZnjSp6JSAJHgdCSkI
GcNlOM89aeBlBEXG/v8aJ+IieKNcXiK6tdKNGrAvEjIP0xdTaONX2JdQKFyoVtCB
vaarZ9kwmD6ClP450zRGNeRDDvzB0ml42SgXGCtHUb/to/vmY7lFNiRoa6Gz8aHC
etcFlN1y4EPQ0hvHD/CTw9QbMmBuezsprcQS/gVqfjLO/VSoLrmx1wd2ZrhC5Att
odq/9ZrQcGEBz7RNC3hedRPWyY8JrdK9/mKzMMnwfILgWEo0TNp0jZDwTeu/BG6d
RcPIP35iSdW+xHzZic4/whYdYcJh9sc1JJqdMen881Y26fO4hA3HEnIH1RSBYyO+
rCvubAggXGXVzyvo0IM3retxdXa7Rq9aGbmBVJURYiuLr0tsGOmtpwbb0xNTFiq0
jCBI1DO2Fg2FVAssiLbDnWdoRs1O8UjynCijjIQaLlW7/w8gzrgboiZY4zEDyhTE
0YkCpbL9wGc8WYfnPCKwmCPJi0/j
-----END CERTIFICATE-----`

    it('parse EC PEM and attributes', () => {
      const parsed = Utils.parsePem(CommonName)
      Assert.deepStrictEqual(parsed, {
        subjectaddress: '0xb5171dd3f853683bf3f5eba793a7b4cbe0d35e06',
        serialNo: '0x3d59487fe2fc90fe233288e96b881afc9adafa7d',
        notAfter: new Date('2016-11-01T00:00:00.000Z'),
        notBefore: new Date('2016-10-25T03:18:09.000Z'),
        issuer: '/C=US/ST=Washington/L=Seattle/O=Trusted Key Solutions Inc./CN=Trusted Key Demo Authority',
        attributes: [{
          oid: '1.3.6.1.4.1.53318295.1',
          value: "WA Driver's License"
        },
        {
          oid: '2.5.4.3',
          value: 'Roberta Wong'
        }]
      })
    })

    it('parse RSA PEM', () => {
      Assert.doesNotThrow(() => Utils.parsePem(Issuer))
    })

    it('parse PEM without header', () => {
      Assert.doesNotThrow(() => Utils.parsePem(CommonName.replace(/-----[^-]+-----|\r|\n/g, '')))
    })

    it('parse PEM and fail without CA certs', () => {
      Assert.throws(() => Utils.parsePem(CommonName, []), 'Signature verification failed')
    })

    it('parse PEM and fail with unknown issuer', () => {
      Assert.throws(() => Utils.parsePem(CommonName, [CommonName]), 'Signature verification failed')
    })

    it('parse PEM and succeed with valid signature', () => {
      Assert.doesNotThrow(() => Utils.parsePem(CommonName, [Issuer]))
    })

    it('parse PEM and succeed with multiple issuers', () => {
      Assert.doesNotThrow(() => Utils.parsePem(CommonName, [CommonName, Issuer]))
    })

    it('parse issuer PEM', () => {
      const parsed = Utils.parsePem(Issuer)
      Assert.deepStrictEqual(parsed, {
        'attributes': [
          {
            'oid': '2.5.4.6',
            'value': 'US'
          },
          {
            'oid': '2.5.4.8',
            'value': 'Washington'
          },
          {
            'oid': '2.5.4.7',
            'value': 'Seattle'
          },
          {
            'oid': '2.5.4.10',
            'value': 'Trusted Key Solutions Inc.'
          },
          {
            'oid': '2.5.4.3',
            'value': 'Trusted Key Demo Authority'
          }
        ],
        'issuer': '/C=US/ST=Washington/L=Seattle/O=Trusted Key Solutions Inc./CN=Trusted Key CA (4096 bit)',
        'notAfter': new Date('2017-09-14T10:18:01.000Z'),
        'notBefore': new Date('2016-09-14T10:18:01.000Z'),
        'serialNo': '0x000000000000000000000000ca095a3f84a4cb75',
        'subjectaddress': undefined
      })
    })

    it('parse tkroot', () => {
      const tkroot = FS.readFileSync(Utils.getRootPemPath(), 'ascii')
      Assert.doesNotThrow(() => Utils.parsePem(tkroot))
    })

    it('validate issuer PEM', () => {
      const tkroot = FS.readFileSync(Utils.getRootPemPath(), 'ascii')
      Assert.doesNotThrow(() => Utils.parsePem(Issuer, [tkroot]))
    })
  })
})
