/* eslint-env mocha */
const Assert = require('assert')
const ValidateService = require('../services/validateservice')

describe('ValidateService', function () {
  const ZERO_ADDR = '0x0000000000000000000000000000000000000000'
  let validateService

  before('can construct with url', function () {
    validateService = new ValidateService(process.env.test_walletURL)
  })

  it('can construct with defaults', function () {
    Assert.doesNotThrow(() => new ValidateService())
  })

  it('can validate', async function () {
    const valid = await validateService.validateCredential(ZERO_ADDR)
    Assert.strictEqual(valid, false)
  })

  it('can get info', async function () {
    const keyinfo = await validateService.keyInfo(ZERO_ADDR)
    Assert.deepStrictEqual(keyinfo,
      { '0x0000000000000000000000000000000000000000':
        { timestamp: 0,
          revokedBy: ZERO_ADDR,
          replaces: ZERO_ADDR,
          recovery: ZERO_ADDR,
          isRevoked: true,
          rootAddress: ZERO_ADDR
        }
      })
  })

  it('pads short addresses', async function () {
    const keyinfo = await validateService.keyInfo('0x01772b7b1c48c3c13fe8c8d05935776eb97987')
    Assert.deepStrictEqual(keyinfo,
      { '0x0001772b7b1c48c3c13fe8c8d05935776eb97987':
        { timestamp: 0,
          revokedBy: ZERO_ADDR,
          replaces: ZERO_ADDR,
          recovery: ZERO_ADDR,
          isRevoked: false,
          rootAddress: '0x0001772b7b1c48c3c13fe8c8d05935776eb97987'
        }
      })
  })

  it('can get info for many', async function () {
    const keyinfo = await validateService.keyInfo([ZERO_ADDR, '0x0000000000000000000000000000000000000001'])
    Assert.deepStrictEqual(keyinfo,
      { '0x0000000000000000000000000000000000000000':
        { timestamp: 0,
          revokedBy: ZERO_ADDR,
          replaces: ZERO_ADDR,
          recovery: ZERO_ADDR,
          isRevoked: true,
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
