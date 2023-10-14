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
 * Depends on navite crypto
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
    // [AB123] -> [AB, 123]
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
var hs_b64 = algo => secret => x => crypto
    .createHmac(algo, secret)
    .update(x).digest('base64url')
  ;

/* Signer picker */
var getSigner = algo => {
  var [head, tail] = slicer(algo)

  return {
    'HS': n => hs_b64('sha' + n)
  }[head](tail)
}

/* Head generator */
var getHead = alg => encode({
    alg: alg,
    typ: 'JWT'
  })

/* Sign token */
function sign (body, secret, algo = 'HS256') {
  var head = getHead(algo),
      body = encode({ ...body, iat: now() }),
      signer = getSigner(algo)(secret)
    ;

  return `${head}.${body}.${signer(head + '.' + body)}`
}

/* Verify token */
function verify (token, secret) {
  var signer = hs256_b64(secret),
      [head, body, tail] = splitDot(token),
      invalid = tail !== signer(head + '.' + body),
      expired = decode(body).exp < Date.now() / 1000
    ;

  if (invalid) throw new Error('Invalid signature')
  if (expired) throw new Error('Token expired')

  return {
    ...decode(head),
    ...decode(body)
  }
}

/* Public interface */
module.exports = {
  sign,
  verify
}