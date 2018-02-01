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
                http = new Http("http://localhost:"+server.address().port, appid, secret)
                done()
            })
        })
        afterEach(() => {
            server.close()
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
