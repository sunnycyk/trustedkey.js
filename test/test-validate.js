/* eslint-env mocha */
const Assert = require('assert')
const ValidateService = require('../services/validateservice')

describe('ValidateService', () => {
  const ZERO_ADDR = '0x0000000000000000000000000000000000000000'
  let validateService

  it('can contruct with defaults', () => {
    validateService = new ValidateService()
  })

  it('can validate', async () => {
    const valid = await validateService.validateCredential(ZERO_ADDR)
    Assert.strictEqual(valid, false)
  })

  it('can get info', async () => {
    const keyinfo = await validateService.keyInfo(ZERO_ADDR)
    Assert.deepStrictEqual(keyinfo,
      { '0x0000000000000000000000000000000000000000':
        { timestamp: 0,
          revokedBy: ZERO_ADDR,
          replaces: ZERO_ADDR,
          recovery: ZERO_ADDR,
          isRevoked: false,
          rootAddress: ZERO_ADDR
        }
      })
  })

  it('can get info for many', async () => {
    const keyinfo = await validateService.keyInfo([ZERO_ADDR, '0x0000000000000000000000000000000000000001'])
    Assert.deepStrictEqual(keyinfo,
      { '0x0000000000000000000000000000000000000000':
        { timestamp: 0,
          revokedBy: ZERO_ADDR,
          replaces: ZERO_ADDR,
          recovery: ZERO_ADDR,
          isRevoked: false,
          rootAddress: ZERO_ADDR
        },
      '0x0000000000000000000000000000000000000001':
        { timestamp: 0,
          revokedBy: ZERO_ADDR,
          replaces: ZERO_ADDR,
          recovery: ZERO_ADDR,
          isRevoked: false,
          rootAddress: '0x0000000000000000000000000000000000000001'
        }
      })
  })
})
