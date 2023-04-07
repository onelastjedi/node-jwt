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

/* Depends on navite crypto */
var crypto = require('node:crypto')

/* Define helpers */
var replace = (re, rep) => x => x.replace(re, rep),
    rePad = replace(/=/g, ''),
    reUnd = replace(/_/g, '/'),
    reMin = replace(/-/g, '+'),

    /* Split */
    split = splitter => x => x.split(splitter),
    splitDot = split('.'),

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

/* Default head */
var head_d = encode({
    alg: 'HS256',
    typ: 'JWT'
  })

/* HMAC sha256 base64 signer */
var hs256_b64 = secret => x => crypto
    .createHmac('sha256', secret)
    .update(x).digest('base64url')
  ;

/* Sign token */
function sign (body, secret, head = head_d) {
  var body = encode({ ...body, iat: now() }),
      signer = hs256_b64(secret)
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
