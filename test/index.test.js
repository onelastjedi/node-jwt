const assert = require('assert')
const lib = require('../index')
const secret = 'secret'
const data = { foo: 'bar' }
const token = lib.sign(data, secret)
const [head, body] = token.split('.')
const decode = x => JSON.parse(atob(x))

class TokenError extends Error {
  constructor (s)
    {
      super(s)
      this.name = this.constructor.name

          }
    }

describe('Library supports:', () => {
  const hs256 = lib.sign(data, secret, 'HS256')
  const hs384 = lib.sign(data, secret, 'HS384')
  const hs512 = lib.sign(data, secret, 'HS512')

  const head = token => token.split('.')[0]

  it('HS256: HMAC using SHA-256 hash', () =>
    assert.equal(decode(head(hs256)).alg, 'HS256'))

  it('HS384: HMAC using SHA-384 hash', () =>
    assert.equal(decode(head(hs384)).alg, 'HS384'))

  it('HS512: HMAC using SHA-512 hash', () =>
    assert.equal(decode(head(hs512)).alg, 'HS512'))
})

describe('Library is a object which exports:', () => {
  assert.equal(typeof lib, 'object')

  describe(`'sign' method which:`, () => {
    assert.equal(typeof lib.sign, 'function')

    describe(`return token from ${JSON.stringify(data)}:`, () => {
      it(token, () =>
        assert.ok(token, 'iat is `null` or `undefined`'))
    })

    describe(`adds defaults to head (${head}):`, () => {
      const { typ, alg } = decode(head)

      it(`'typ: JWT'`, () =>
        assert.equal(typ, 'JWT'))

      it(`'alg: HS256'`, () =>
        assert.equal(alg, 'HS256'))
    })

    describe(`adds iat prop:`, () => {
      const { iat } = decode(body)

      it(`to body (${body})`, () =>
        assert.ok(iat, 'iat is `null` or `undefined`'))
    })
  })

  describe(`'verify' method which:`, () => {
    assert.equal(typeof lib.verify, 'function')

    describe(`'verify' return data from token:`, () => {
      const { iat } = decode(body)

      it(JSON.stringify({ ...data, iat }), () =>
        assert.deepEqual({ ...data, iat }, lib.verify(token, secret)))
    })

    describe(`'verify' return errors:`, () => {
      const invalid = () => lib.verify(token, 'secre')
      const expired = lib.sign({ exp: -1 }, secret)
      const exp = () => lib.verify(expired, secret)

      it('for invalid signature', () =>
        assert.throws(invalid, new TokenError('Invalid signature')))


      it('for expired token', () =>
        assert.throws(exp, new TokenError('Token expired')))

    })
  })
})
