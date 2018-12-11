/* eslint-env mocha */
const Assert = require('assert')
const OID = require('../oid')
const Claims = require('../claims')

describe('claims', function () {
  it('has all known OIDs', function () {
    const allOidClaims = new Set(Object.values(Claims))
    const missingOids = Object.values(OID).filter(oid => !allOidClaims.has(oid))
    Assert.deepStrictEqual(missingOids, [])
  })
})
