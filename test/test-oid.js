/* eslint-env mocha */
const Assert = require('assert')
const OID = require('../oid')

describe('OID', function () {
  it('all have dotted notation', function () {
    Object.values(OID).forEach(oid => oid.split('.').forEach(i => Assert.ok(i > 0 && i < 100000000)))
  })
  it('are all unique', function () {
    var inv = {}
    Object.values(OID).forEach(oid => {
      Assert.strictEqual(inv[oid], undefined)
      inv[oid] = oid
    })
  })
})
