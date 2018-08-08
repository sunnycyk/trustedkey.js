/* eslint-env mocha */
const Assert = require('assert')
const OID = require('../oid')
const Claims = require('../claims')

describe('claims', () => {
  it('has all known OIDs', () => {
    const allOidClaims = new Set(Object.values(Claims))
    const missingOids = Object.values(OID).filter(oid => !allOidClaims.has(oid))
    Assert.deepStrictEqual(missingOids, [])
  })
})
