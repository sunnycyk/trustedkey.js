/* eslint-env mocha */
const Assert = require('assert')
const Express = require('express')
const RP = require('request-promise-native')
const Utils = require('../utils')
const Http = require('../services/http')
const WalletService = require('../services/walletservice')

describe('http server', () => {
  let app, http, server
  const secret = 'secret'
  const appid = 'id'

  before(done => {
    app = Express()
    app.use(require('body-parser').raw({type: '*/*'}))
    server = app.listen(0, (err, p) => {
      Assert.strictEqual(err, undefined)
      http = new Http(`http://localhost:${server.address().port}`, appid, secret)
      done()
    })
  })
  after(done => {
    server.close(done)
  })
  describe('http', () => {
    before(() => {
      function Auth (req, res, next) {
        const fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl
        if (req.headers.authorization) {
          Assert.strictEqual(req.headers.authorization.split(' ')[0], 'Bearer')
          const claims = Utils.verifyJws(req.headers.authorization.split(' ')[1], secret)
          Assert.strictEqual(claims.aud, fullUrl)
          Assert.strictEqual(claims.iss, appid)
          Assert.ok(claims.iat <= Utils.getUnixTime())
          Assert.ok(claims.exp > Utils.getUnixTime())
          if (req.body && req.body.length > 0) {
            Assert.strictEqual(Utils.sha256(req.body, 'hex'), claims.body)
          } else {
            Assert.strictEqual(claims.body, null)
          }
          next()
        } else {
          next(Error('fail'))
        }
      }
      app.get('/get', Auth, (req, res) => res.send('gotten'))
      app.post('/post', Auth, (req, res) => res.send('posted'))
    })
    it('can build URL without params', () => {
      const h = http.buildUrl('/test')
      Assert.strictEqual(h, `http://localhost:${server.address().port}/test`)
    })
    it('can build URL with params', () => {
      const h = http.buildUrl('/test', {a: 2})
      Assert.strictEqual(h, `http://localhost:${server.address().port}/test?a=2`)
    })
    it('can create JWT header without body', async () => {
      const h = http.getHeaders('url')
      Assert.strictEqual(h.Authorization.split(' ')[0], 'Bearer')
      const claims = Utils.verifyJws(h.Authorization.split(' ')[1], secret)
      const payload = {
        iss: appid,
        aud: 'url',
        iat: claims.iat,
        exp: claims.exp,
        body: null
      }
      Assert.deepStrictEqual(claims, payload)
    })
    it('can create JWT header with body', async () => {
      const h = http.getHeaders('url', 'body')
      Assert.strictEqual(h.Authorization.split(' ')[0], 'Bearer')
      const claims = Utils.verifyJws(h.Authorization.split(' ')[1], secret)
      const payload = {
        iss: appid,
        aud: 'url',
        iat: claims.iat,
        exp: claims.exp,
        body: Utils.sha256('body', 'hex')
      }
      Assert.deepStrictEqual(claims, payload)
    })
    it('can POST without contents', async () => {
      Assert.strictEqual(await http.post('post'), 'posted')
    })
    it('can POST with query parameters', async () => {
      Assert.strictEqual(await http.post('post', {a: 4}), 'posted')
    })
    it('can POST string', async () => {
      Assert.strictEqual(await http.post('post', {}, 's'), 'posted')
    })
    it('can POST object', async () => {
      Assert.strictEqual(await http.post('post', {}, {a: 2}), 'posted')
    })
    it('can GET', async () => {
      Assert.strictEqual(await http.get('get'), 'gotten')
    })
    it('can GET with query parameters', async () => {
      Assert.strictEqual(await http.get('get', {a: 3}), 'gotten')
    })
    it('can GET with trailing slash', async () => {
      Assert.strictEqual(await http.get('/get', {a: 3}), 'gotten')
    })
    it('can GET with absolute url', async () => {
      Assert.strictEqual(await http.get(`http://localhost:${server.address().port}/get`), 'gotten')
    })
  })

  context('wallet OAuth', () => {
    const Code = 'codex'
    const State = 'statx'
    const AccessToken = 'access_tokenx'
    const UserInfo = {name: 'John Doe'}
    const RedirectUri = `https://localhost:123/callback`
    let walletservice
    before(() => {
      walletservice = new WalletService(`http://localhost:${server.address().port}`, appid, secret)
      app.get('/oauth/authorize', (req, res) => {
        Assert.deepStrictEqual(req.query, {
          redirect_uri: RedirectUri,
          client_id: appid,
          state: State,
          response_type: 'code',
          scope: 'openid'
        })
        const callback = Utils.mergeQueryParams(req.query.redirect_uri, {
          code: Code
        })
        res.redirect(callback)
      })
      app.post('/oauth/token', (req, res) => {
        const params = req.body.toString().split('&').map(kv => kv.split('=')).reduce((p, [k, v]) => {
          p[k] = decodeURIComponent(v)
          return p
        }, {})
        Assert.deepStrictEqual(params, {
          client_id: appid,
          client_secret: secret,
          grant_type: 'authorization_code',
          code: Code,
          redirect_uri: RedirectUri
        })
        res.json({
          access_token: AccessToken,
          token_type: 'Bearer',
          id_token: 'id_token'
        })
      })
      app.get('/oauth/user', (req, res) => {
        Assert.strictEqual(req.headers.authorization, `Bearer ${AccessToken}`)
        res.json(UserInfo)
      })
    })
    it('can build /authorize URL', () => {
      const url = walletservice.buildAuthorizeUrl(RedirectUri, State)
      Assert.strictEqual(url, `http://localhost:${server.address().port}/oauth/authorize?client_id=id&redirect_uri=${encodeURIComponent(RedirectUri)}&state=${State}&response_type=code&scope=openid`)
    })
    it('can get code from /authorize', async () => {
      const url = walletservice.buildAuthorizeUrl(RedirectUri, State)
      try {
        await RP.get(url, {followRedirect: false})
        Assert(false)
      } catch (err) {
        Assert.strictEqual(err.response.statusCode, 302)
      }
    })
    it('can get access_token from /token', async () => {
      const grant = await walletservice.token(RedirectUri, Code)
      Assert.deepStrictEqual(grant, {
        'access_token': AccessToken,
        'id_token': 'id_token',
        'token_type': 'Bearer'
      })
    })
    it('can get user info from /user', async () => {
      const userInfo = await walletservice.userInfo('access_tokenx')
      Assert.deepStrictEqual(userInfo, UserInfo)
    })
  })
})
