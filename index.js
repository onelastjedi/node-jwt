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

/* Define helpers */
var replace = (re, rep) => x => x.replace(re, rep),
    rePad = replace(/=/g, ''),
    reUnd = replace(/_/g, '/'),
    reMin = replace(/-/g, '+'),

    /* Split */
    split = splitter => x => x.split(splitter),
    splitDot = split('.'),

    /* Slice */
    slice = (b, e) => str => str.slice(b, e),
    // [AB123] -> [AB, 123] */
    slicer = str => [slice(0, 2)(str), slice(2)(str)],

    /* JSON */
    stringify = JSON.stringify,
    parse = JSON.parse,

    /* Encoding/decoding */
    encode = x => rePad(btoa(stringify(x))),
    decode = x => parse(atob(x)),

    /* Math */
    divide = div => x => x / div,
    divide1000 = divide(1000),
    floor = Math.floor,

    /* Date */
    now = () => floor(divide1000(Date.now())),
    after = x => now() + x
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

  // REFACTOR
  if (body.exp) {
    body.exp = floor(divide1000(body.exp))
  }

  var head = getHead(alg),
      body = encode({ ...body, iat: now() }),
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
      expired = decode(body).exp < Date.now() / 1000
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