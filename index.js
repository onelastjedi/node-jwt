/*
 * Copyright (C) 2023 — present J.D <jd@phon.one>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Should satisfy RFC
 * https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-algorithms-40/
 *
 * Depends on native crypto
 */
var crypto = require('node:crypto')

/*
 * Some usefull helpers
 *
 *
 */ // replace :: Regex -> String
var replace = (re, rep) => x => x.replace(re, rep),
    rePad = replace(/=/g, ''),

    // split :: String -> [String]
    splitDot = x => x.split('.'),

    // slice :: Number -> String
    // slicer :: String -> [String]
    slice = (b, e) => str => str.slice(b, e),
    slicer = str => [slice(0, 2)(str), slice(2)(str)],

    // encode :: a -> String
    // decode :: String -> a
    encode = x => rePad(btoa(stringify(x))),
    decode = x => parse(atob(x)),

    // divide :: Number -> Number
    divide1000 = x => x / 1000,

    // now :: Function -> Number
    // after :: Number -> Number
    now = date => Math.floor(divide1000(date.now())),
    after = x => now(Date) + x,

    /* Simple shorthands */
    stringify = JSON.stringify,
    parse = JSON.parse
  ;

/* HMAC sha256 base64 signer */
var hs_b64 = algo => secret => x =>
  crypto
    .createHmac(algo, secret)
    .update(x).digest('base64url')
  ;

/* Signer picker */
var getSigner = alg => {
  var [head, tail] = slicer(alg)

  return {
    'HS': n => hs_b64('sha' + n)
  }[head](tail)
}

/* Head generator */
var getHead = alg => encode({
    alg: alg,
    typ: 'JWT'
  })

/**
 * Sign body with secret using
 * one of supported algorithms
 *
 * @param {Object} body - data to sign
 * @param {String} secret - private secret
 * @param {String} [alg=HS256] alg - desired algorithm
 * @returns {String} JWT token
 *
 * @example
 *
 *    sign({ foo: "bar" }, 'secret') -> eyJhbGc.....
 *    sign({ foo: "bar" }, 'secret', 'HS512') -> eyJhbGc.....
 */
function sign (body, secret, alg = 'HS256') {
  Object.hasOwn(body, 'exp')
    && (body.exp = after(body.exp))
  ;

  var head = getHead(alg),
      body = encode({ ...body, iat: now(Date) }),
      signer = getSigner(alg)(secret)
    ;

  return `${head}.${body}.${signer(head + '.' + body)}`
}

/**
 * Verify token with secret using
 * one of supported algorithms
 *
 * @param {String} token - token to verify
 * @param {String} secret - private secret
 * @returns {Object} body
 *
 * @example
 *
 *    verify(eyJhbGc....., 'secret') -> { foo: "bar", iat: 1697265269 }
 */
function verify (token, secret) {
  var [head, body, tail] = splitDot(token),
      { alg } = decode(head),
      signer = getSigner(alg)(secret)
    ;

  var invalid = tail !== signer(head + '.' + body),
      expired = decode(body).exp <= now(Date)
    ;

  if (invalid) throw new Error('Invalid signature')
  if (expired) throw new Error('Token expired')

  return {
    ...decode(body)
  }
}

/* Public interface */
module.exports = {
  sign,
  verify
}
