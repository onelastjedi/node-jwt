# node-jwt

JavaScript library to sign and verify JSON Web Tokens in it's simplest form. 
Has no dependencies. At the moment works only with HMAC SHA256. 

## Installation

If you use npm, `npm install @onelastjedi/node-jwt`. 
You can also download the [latest release on GitHub](https://github.com/onelastjedi/node-jwt/releases/latest). 

### Use

```js
import jwt from '@onelastjedi/node-jwt'

const secret = process.env.__SECRET__

const data = { 
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
    user: { id: 1, name: 'Mary' }
}

const token = jwt.sign(data, secret) // eyJhbGc.....

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

### License

[AGPL](LICENSE)
