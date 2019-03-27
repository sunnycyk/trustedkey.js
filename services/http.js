const RP = require('request-promise-native')
const Assert = require('assert')
const URL = require('url')

const Utils = require('../utils')

module.exports = httpUtils

// Common JSON sanity check callback
function checkSuccess (jsonData) {
  if (jsonData && jsonData.error) {
    throw Error(jsonData.error.message || jsonData.error)
  }
  return jsonData
}

/**
 * Utility class with wrappers for calling authenticated API endpoints.
 *
 * @constructor
 * @param {String} backendUrl The base backend URL
 * @param {String} [appId] Application ID, without this only unauthorized APIs can be used
 * @param {String} [appSecret] Application shared secret, without this only unauthorized APIs can be used
 */
function httpUtils (backendUrl, appId, appSecret) {
  Assert.strictEqual(typeof backendUrl, 'string', 'backendUrl must be of type `string`')
  this.backendUrl = backendUrl
  this.appId = appId
  this.appSecret = appSecret
}

function getAuthHeader (url, appId, appSecret, body) {
  const iat = Utils.getUnixTime()
  const payload = {
    iss: appId,
    aud: url,
    iat: iat,
    exp: iat + 300,
    body: body ? Utils.sha256(body, 'hex') : null
  }
  const header = { typ: 'JWT', iss: appId }
  return 'Bearer ' + Utils.createHmacJws(payload, appSecret, header)
}

/**
 * Get the headers for the request
 *
 * @param {string} absoluteUrl the absolute URL for the request
 * @param {string} [body] optional HTTP body
 * @returns {object} Object with headers for the request; empty object if no auth is needed
 */
httpUtils.prototype.getHeaders = function (absoluteUrl, body) {
  if (this.appId && this.appSecret) {
    return {Authorization: getAuthHeader(absoluteUrl, this.appId, this.appSecret, body)}
  } else {
    return {}
  }
}

/**
 * Build a URL with optional query string
 *
 * @param {string} path the endpoint to build
 * @param {*} [params] optional parameters to add to the query string
 * @returns {string} the absolute URL
 */
httpUtils.prototype.buildUrl = function (path, params) {
  const url = Utils.mergeQueryParams(path, params || {})
  return URL.resolve(this.backendUrl, url)
}

/**
 * Authenticated GET request
 *
 * @param {string} path the endpoint to build
 * @param {*} [params] optional parameters to add to the query string
 * @returns {Promise.<*>} resolves to the API result
 */
httpUtils.prototype.get = function (path, params) {
  const absoluteUrl = this.buildUrl(path, params)
  return RP.get({
    uri: absoluteUrl,
    json: true,
    forever: true,
    headers: this.getHeaders(absoluteUrl)
  }).then(checkSuccess)
}

/**
 * Authenticated POST request
 *
 * @param {string} path the endpoint to build
 * @param {*} [params] optional parameters to add to the query string
 * @param {*} [jsonBody] optional body
 * @returns {Promise.<*>} resolves to the API result
 */
httpUtils.prototype.post = function (path, params, jsonBody) {
  const absoluteUrl = this.buildUrl(path, params)
  // Assume RP does the exact same serialization of the body
  const body = jsonBody === undefined ? '' : JSON.stringify(jsonBody)
  return RP.post({
    uri: absoluteUrl,
    json: true,
    forever: true,
    headers: this.getHeaders(absoluteUrl, body),
    body: jsonBody
  }).then(checkSuccess)
}

/**
 * Authenticated DELETE request
 *
 * @param {string} path the endpoint to build
 * @param {*} [params] optional parameters to add to the query string
 * @returns {Promise.<*>} resolves to the API result
 */
httpUtils.prototype.delete = function (path, params) {
  const absoluteUrl = this.buildUrl(path, params)
  return RP.delete({
    uri: absoluteUrl,
    json: true,
    forever: true,
    headers: this.getHeaders(absoluteUrl)
  }).then(checkSuccess)
}
