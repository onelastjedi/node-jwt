# node-jwt

JavaScript library to sign and verify JSON Web Tokens in it's simplest form.
Has no dependencies.

## Installation

### Use

```js
import jwt from '@onelastjedi/node-jwt'

const secret = process.env.__SECRET__

const data = {
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
    user: { id: 1, name: 'Mary' }
}

jwt.sign(data, secret) // eyJhbGc.....
jwt.verify(token, secret)
/*
    {
      alg: 'HS256',
      typ: 'JWT',
      user: { id: 1, name: 'Mary' },
      iat: ...,
      exp: ...,
    }
*/

```

### Algorithms supported


| alg Parameter Value | Digital Signature or MAC Algorithm                                     |
|---------------------|------------------------------------------------------------------------|
| HS256               | HMAC using SHA-256 hash algorithm                                      |
| HS384               | HMAC using SHA-384 hash algorithm                                      |
| HS512               | HMAC using SHA-512 hash algorithm                                      |

### License

[AGPL](LICENSE)
