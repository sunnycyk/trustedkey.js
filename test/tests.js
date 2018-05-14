const OID = require('../oid')
const Assert = require('assert')
const Utils = require('../utils')
const Http = require('../services/http')
const Express = require('express')

describe("OID", _ => {
    it("all have dotted notation", () => {
        Object.values(OID).forEach(oid => oid.split('.').forEach(i => Assert.ok(i > 0 && i < 100000000)))
    })
    it("are all unique", () => {
        var inv = {}
        Object.values(OID).forEach(oid => {
            Assert.strictEqual(inv[oid], undefined)
            inv[oid] = oid
        })
    })
})

describe("Utils", _ => {

    const jwkEC = {"kty":"EC","crv":"P-256","x": "P77Gc65MCzCAFSL3ym4jzVkBHPFRk2wREBVmi94ga74","y": "qjzjb7UInV3zDzN0wwkCaVqtyOLGaCmLBdLee9SXKQw"}
    const pemEC = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP77Gc65MCzCAFSL3ym4jzVkBHPFR
k2wREBVmi94ga76qPONvtQidXfMPM3TDCQJpWq3I4sZoKYsF0t571JcpDA==
-----END PUBLIC KEY-----`
    const jwkRSA = {"kty":"RSA","n":"zghKyUzealTP0yG2JlTcBSeYkA_WNKLCMZTQRbtEr9K11oaDsDmUSY-s3clehbbZ9SWNy9xydQfzb0BMdY2-omWT6kodYX8f-6p-4OCno3LHE5yM4UOkEZnc1lOz5VzUa-deMEwkLJXiquE1wQbnA6yaQIdy8vADNhIDhQKxIRFOFDbk1S01sEl-Oc3VFcY0VsoapCVpAEfr1LDCetOe6RxsvFDFex09nuvW5ehFbjioOvY6_jG-1ZcTKBasDVMWFLoECzlYfPBQfBiip2rWUzWW9chCnB0-b29Qg4R9n1glTVqqNQj0F9grWetJXw2NXQOVMKn-w81WzwH4s3IZQw","e":"AQAB"}
    const pemRSA = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzghKyUzealTP0yG2JlTc
BSeYkA/WNKLCMZTQRbtEr9K11oaDsDmUSY+s3clehbbZ9SWNy9xydQfzb0BMdY2+
omWT6kodYX8f+6p+4OCno3LHE5yM4UOkEZnc1lOz5VzUa+deMEwkLJXiquE1wQbn
A6yaQIdy8vADNhIDhQKxIRFOFDbk1S01sEl+Oc3VFcY0VsoapCVpAEfr1LDCetOe
6RxsvFDFex09nuvW5ehFbjioOvY6/jG+1ZcTKBasDVMWFLoECzlYfPBQfBiip2rW
UzWW9chCnB0+b29Qg4R9n1glTVqqNQj0F9grWetJXw2NXQOVMKn+w81WzwH4s3IZ
QwIDAQAB
-----END PUBLIC KEY-----`

    context("address", () => {
        it("Passes for valid addresses", () => {
            Assert.strictEqual(Utils.isAddress("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4"), true)
            Assert.strictEqual(Utils.isAddress("0xE3b0c44298fC1c149afbf4D8996fb92427ae41e4"), true)
        })
        it("Fails for invalid addresses", () => {
            Assert.strictEqual(Utils.isAddress("asdf"), false)
            Assert.strictEqual(Utils.isAddress("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), false)
        })
    })

    describe("jwkToHex", () => {
        it("converts RSA key", () => {
            const hex = 'ce084ac94cde6a54cfd321b62654dc052798900fd634a2c23194d045bb44afd2b5d68683b03994498facddc95e85b6d9f5258dcbdc727507f36f404c758dbea26593ea4a1d617f1ffbaa7ee0e0a7a372c7139c8ce143a41199dcd653b3e55cd46be75e304c242c95e2aae135c106e703ac9a408772f2f0033612038502b121114e1436e4d52d35b0497e39cdd515c63456ca1aa425690047ebd4b0c27ad39ee91c6cbc50c57b1d3d9eebd6e5e8456e38a83af63afe31bed597132816ac0d531614ba040b39587cf0507c18a2a76ad6533596f5c8429c1d3e6f6f5083847d9f58254d5aaa3508f417d82b59eb495f0d8d5d039530a9fec3cd56cf01f8b3721943'
            Assert.strictEqual(Utils.jwkToHex(jwkRSA), hex)
        })
        it("converts EC key", () => {
            const hex = '043fbec673ae4c0b30801522f7ca6e23cd59011cf151936c111015668bde206bbeaa3ce36fb5089d5df30f3374c30902695aadc8e2c668298b05d2de7bd497290c'
            Assert.strictEqual(Utils.jwkToHex(jwkEC), hex)
        })
        it("throws on invalid jwk", () => {
            Assert.throws(() => Utils.jwkToHex({kty:"RSA"}), /Unsupported/)
            Assert.throws(() => Utils.jwkToHex({}), /Unsupported/)
        })
        it("throws on RSA jwk with PK", () => {
            Assert.throws(() => Utils.jwkToHex(Object.assign({d:"s83ZmuWKtcqbpnME5112vxZqpKpCFctE4Jye_BneVxE"}, jwkEC)))
            Assert.throws(() => Utils.jwkToHex(Object.assign({d:"s83ZmuWKtcqbpnME5112vxZqpKpCFctE4Jye_BneVxE"}, jwkRSA)))
        })
    })

    describe("pemToJwk", () => {
        it("converts RSA key", () => {
            Assert.deepStrictEqual(Utils.pemToJwk(pemRSA), jwkRSA)
            Assert.deepStrictEqual(Utils.pemToJwk(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDNXFJO5cFMie4oQraVqnniopSW
V9hCut6WluPVbHblvqyH90dCqfZo+M6uABxixrxyWE/U6KJlAAnoSTW0qEuuAYlH
ZPFsmMv+kw7D1ZBoPBDsPvua0djiiVSyMzaaZHV/d2vABchUoCdp/CVPjpsSqnjH
xcbCgN76nCO1NGBgbQIDAQAB
-----END PUBLIC KEY-----`), {
                "e": "AQAB",
                "kty": "RSA",
                "n": "zVxSTuXBTInuKEK2lap54qKUllfYQrrelpbj1Wx25b6sh_dHQqn2aPjOrgAcYsa8clhP1OiiZQAJ6Ek1tKhLrgGJR2TxbJjL_pMOw9WQaDwQ7D77mtHY4olUsjM2mmR1f3drwAXIVKAnafwlT46bEqp4x8XGwoDe-pwjtTRgYG0"
            })
        })
        it("converts EC key", () => {
            Assert.deepStrictEqual(Utils.pemToJwk(pemEC), jwkEC)
        })
        it("converts small RSA key", () => {
            Assert.deepStrictEqual(Utils.pemToJwk(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMiwb6VuAvJwHJyRZq1PJO8PpaaYjOXp
iUpBdB8ZntA5vj9KB/ke4HU3gO/hqLEXZ7JkBW6O+ID0ZWlubkqkD7UCAwEAAQ==
-----END PUBLIC KEY-----`),
            {
                "kty": "RSA",
                "n": "yLBvpW4C8nAcnJFmrU8k7w-lppiM5emJSkF0Hxme0Dm-P0oH-R7gdTeA7-GosRdnsmQFbo74gPRlaW5uSqQPtQ",
                "e": "AQAB"
            })
        })
        it("converts small RSA key, e=3", () => {
            Assert.deepStrictEqual(Utils.pemToJwk(`-----BEGIN PUBLIC KEY-----
MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBAM0cWN/vHXq5p6kIGCQ68JALYAUlUI/2
RcAR4NrO2TIb2+H5XpY6aLi27oedXXLq6EfYGEfSLxQ8jpkLFeG5BIkCAQM=
-----END PUBLIC KEY-----`),
            {
                "kty": "RSA",
                "n": "zRxY3-8dermnqQgYJDrwkAtgBSVQj_ZFwBHg2s7ZMhvb4fleljpouLbuh51dcuroR9gYR9IvFDyOmQsV4bkEiQ",
                "e": "Aw"
            })
        })
        it("throws on invalid PEM", () => {
            Assert.throws(() => Utils.pemToJwk(``), /Unsupported/)
        })
    })

    describe("jwkToPem", () => {
        it("converts RSA key", () => {
            Assert.strictEqual(Utils.jwkToPem(jwkRSA), pemRSA)
        })
        it("converts EC key", () => {
            Assert.strictEqual(Utils.jwkToPem(jwkEC), pemEC)
        })
    })

    describe("mergeQueryParams", _ => {
        it("accepts null arg", () => {
            Assert.strictEqual(Utils.mergeQueryParams("abc", null), "abc")
        })
        it("merges params", () => {
            Assert.strictEqual(Utils.mergeQueryParams("abc", {a:2,b:"b c"}), "abc?a=2&b=b%20c")
        })
    })

    describe("sha256", _ => {
        it("accepts and returns buffer", () => {
            Assert.ok(Utils.sha256(Buffer.from("")) instanceof Buffer)
        })
        it("takes optional encoding", () => {
            Assert.strictEqual(Utils.sha256("", "hex"), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        })
    })

    describe("base64url", _ => {
        it("takes Buffer, returns string", () => {
            Assert.strictEqual(Utils.base64url(Buffer.from("_-w", "base64")), "_-w")
        })
    })

    describe("parseHexString", _ => {
        it("parses hex into string", () => {
            Assert.strictEqual(Utils.parseHexString("00"), "\0")
        })
    })

    describe("parseX509Date", _ => {
        it("parses string into date", () => {
            Assert.ok(Utils.parseX509Date("141213110908Z") instanceof Date)
        })
        it("parses short string into date", () => {
            Assert.strictEqual(Utils.parseX509Date("141213110908Z").toUTCString(), "Sat, 13 Dec 2014 11:09:08 GMT")
        })
        it("parses long string into date", () => {
            Assert.strictEqual(Utils.parseX509Date("19141213110908Z").toUTCString(), "Sun, 13 Dec 1914 11:09:08 GMT")
        })
    })

    describe("dateToString", _ => {
        it("turns current Date into string", () => {
            Assert.strictEqual(typeof Utils.dateToString(new Date), "string")
        })
        it("turns past Date into short string", () => {
            Assert.strictEqual(Utils.dateToString(new Date(Date.UTC(1970,0,1,0,2,3))), "700101000203Z")
        })
        it("turns future Date into long string", () => {
            Assert.strictEqual(Utils.dateToString(new Date(Date.UTC(2080,0,1,0,0,0))), "20800101000000Z")
        })
    })

    describe("http", _ => {
        let app, http, server
        const secret = "secret"
        const appid = "id"

        beforeEach(done => {
            app = Express()
            app.use(require('body-parser').raw({type:"*/*"}))
            app.use((req,res,next) => {
                const fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl
                if (req.headers.authorization) {
                    Assert.strictEqual(req.headers.authorization.split(' ')[0], "Bearer")
                    const claims = Utils.verifyJws(req.headers.authorization.split(' ')[1], secret)
                    Assert.strictEqual(claims.aud, fullUrl)
                    Assert.strictEqual(claims.iss, appid)
                    Assert.ok(claims.iat <= Utils.getUnixTime())
                    Assert.ok(claims.exp > Utils.getUnixTime())
                    if (req.body && req.body.length > 0) {
                        Assert.strictEqual(Utils.sha256(req.body, 'hex'), claims.body)
                    }
                    else {
                        Assert.strictEqual(claims.body, null)
                    }
                    next()
                }
            })
            app.get("/get", (req,res) => res.send("gotten"))
            app.post("/post", (req,res) => res.send("posted"))
            server = app.listen(0, (err,p) => {
                Assert.strictEqual(err, undefined)
                http = new Http(`http://localhost:${server.address().port}`, appid, secret)
                done()
            })
        })
        afterEach(done => {
            server.close(done)
        })
        it("can build URL without params", () => {
            const h = http.buildUrl("/test")
            Assert.strictEqual(h, `http://localhost:${server.address().port}/test`)
        })
        it("can build URL with params", () => {
            const h = http.buildUrl("/test", {a:2})
            Assert.strictEqual(h, `http://localhost:${server.address().port}/test?a=2`)
        })
        it("can create JWT header without body", async () => {
            const h = http.getHeaders("url")
            Assert.strictEqual(h.Authorization.split(' ')[0], "Bearer")
            const claims = Utils.verifyJws(h.Authorization.split(' ')[1], secret)
            const payload = {
                iss: appid,
                aud: "url",
                iat: claims.iat,
                exp: claims.exp,
                body: null,
            }
            Assert.deepStrictEqual(claims, payload)
        })
        it("can create JWT header with body", async () => {
            const h = http.getHeaders("url","body")
            Assert.strictEqual(h.Authorization.split(' ')[0], "Bearer")
            const claims = Utils.verifyJws(h.Authorization.split(' ')[1], secret)
            const payload = {
                iss: appid,
                aud: "url",
                iat: claims.iat,
                exp: claims.exp,
                body: Utils.sha256("body", 'hex'),
            }
            Assert.deepStrictEqual(claims, payload)
        })
        it("can POST without contents", async () => {
            Assert.strictEqual(await http.post("post"), "posted")
        })
        it("can POST with query parameters", async () => {
            Assert.strictEqual(await http.post("post",{a:4}), "posted")
        })
        it("can POST string", async () => {
            Assert.strictEqual(await http.post("post",{},"s"), "posted")
        })
        it("can POST object", async () => {
            Assert.strictEqual(await http.post("post",{},{a:2}), "posted")
        })
        it("can GET", async () => {
            Assert.strictEqual(await http.get("get"), "gotten")
        })
        it("can GET with query parameters", async () => {
            Assert.strictEqual(await http.get("get", {a:3}), "gotten")
        })
        it("can GET with trailing slash", async () => {
            Assert.strictEqual(await http.get("/get", {a:3}), "gotten")
        })
        it("can GET with absolute url", async () => {
            Assert.strictEqual(await http.get("http://localhost:"+server.address().port+"/get"), "gotten")
        })
    })
})
