# openpgp-mime

**openpgp-mime** is an email parsing library based upon [postal-mime](https://www.npmjs.com/package/postal-mime) but with added support for PGP encrypted and signed emails as specified in [RFC 3156](https://www.rfc-editor.org/info/rfc3156/) using [OpenPGP.js](https://www.npmjs.com/package/openpgp). The library's semantics are very similar to those of postal-mime with a few additions for PGP functionality.

## Features

- Environment independent - works in Node.js, browser, web workers, serverless environments, etc.
- TypeScript support
- Comprehensive dependencies - only postal-mime and OpenPGP.js
- Handles complex MIME structures combined with encryption and signing, including nested encryption/signatures and partially encrypted/signed messages

## Installation
Available on NPM as `openpgp-mime`

```bash
npm install openpgp-mime
```

## Usage

You should be familiar with the basics of OpenPGP.js so that you can import the appropriate keys

Parse a PGP encrypted email
```js
import OpenPGPMime from "openpgp-mime"; // may vary depending on environment

const eml = `Mime-Version: 1.0
Content-Type: text/plain

-----BEGIN PGP MESSAGE-----
...
-----END PGP MESSAGE-----`;
const email = await OpenPGPMime.parse(eml, {
    decryptOptions: {
        decryptionKeys: ...,
        verificationKeys: ...
    }
});
```

Access content of encrypted email (see [postal-mime documentation](https://www.npmjs.com/package/postal-mime#api) for full email structure)
```js
console.log(email.text) // decrypted text content
console.log(email.html) // decrypted HTML content

email.attachments.forEach(attachment => {
    console.log(attachment.content) // decrypted attachment content
})
```

Parse a PGP signed email
```js
import OpenPGPMime from "openpgp-mime"; // may vary depending on environment

const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
Content-Type: text/plain

hello world
--foo
Content-Type: application/pgp-signature

-----BEGIN PGP SIGNATURE-----
...
-----END PGP SIGNATURE-----`;
const email = await OpenPGPMime.parse(eml, {
    verifyOptions: {
        verificationKeys: ...
    }
});
```

Check signatures for entire email
```js
email.signatures.forEach(signature => {
    console.log(await signature.verified) // whether signature verification succeeded
})
```

Check signatures for individual attachments
```js
email.attachments.forEach(attachment => {
    attachment.signatures.forEach(signature => {
        console.log(await signature.verified) // whether signature verification succeeded
    })
})
```
If you need to check the signature for an individual inline text node, use the `inlineTextAsAttachments` option.

Parse email containing shared public key
```js
import OpenPGPMime from "openpgp-mime"; // may vary depending on environment

const eml = `Mime-Version: 1.0
Content-Type: application/pgp-keys

-----BEGIN PGP PUBLIC KEY BLOCK-----
...
-----END PGP PUBLIC KEY BLOCK-----`;
const email = await OpenPGPMime.parse(eml);

console.log(email.attachment[0].key) // PublicKey object
```

Dynamically select matching key by ID
```js
const email = await OpenPGPMime.parse(eml, {
    // getVerificationKey works the same but for verification keys
    async getDecryptionKey (keyIds) {
        for (const keyId of keyIds) {
            const key = await searchForKey(keyId.toHex()) // case-specific function for accessing keystore
            if (key) {
                return key;
            }
        }
    }
});
```

When parsing arbitrary emails, wrap processing in a `try ... catch` block to catch parsing errors caused by incorrectly formatted emails

## Parser Options
These are in addition to the [postal-mime options](https://www.npmjs.com/package/postal-mime#api). All options default to undefined/false.

- `decryptOptions` - decryption options object to be passed to the call to `decrypt` in OpenPGP.js, mainly useful for setting `decryptionKeys` and `verificationKeys`
- `verifyOptions` - verification options object to be passed to the call to `verify` in OpenPGP.js, mainly useful for setting `verificationKeys`
- `keepPgpAttachments` - whether to preserve attachments containing PGP metadata (`application/pgp-encrypted` and `application/pgp-signature`)
- `preventUnencapsulatedMessages` - whether to disallow PGP encrypted messages that are not wrapped in a `multipart/encrypted` MIME node
- `inlineTextAsAttachments` - whether to return inline text nodes (`text/plain` or `text/html`) as attachments, allowing their individual signatures to be enumerated
- `getDecryptionKey` - function for dynamically selecting a verification key from a given key ID
    - Takes one argument, an array of `KeyID` objects
    - Must return a `PrivateKey` object or `undefined` if no matching key could be found
    - Can be an asynchronous function and return a `Promise` for one of those
- `getVerificationKey` - function for dynamically selecting a decryption key from a given key ID 
    - Works the same as `getDecryptionKey` except that the function should return a `PublicKey` object