import test from "node:test"
import assert from "node:assert"

import OpenPGPMime from "../index.js"
import { senderPrivateKey, senderPublicKey } from "./fixture/keys.js";

test("Sign Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain

hello world`;
    const signedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(signedEml, {
        decryptOptions: {
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Sign Non-String Message", async () => {
    const eml = new TextEncoder().encode(`Mime-Version: 1.0
Content-Type: text/plain

hello world`);
    const signedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(signedEml, {
        decryptOptions: {
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Sign Quoted-Printable Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

=A1hola mundo!`;
    const signedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(signedEml, {
        decryptOptions: {
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "¡hola mundo!\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Sign Base64 Encoded Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: base64

${btoa("hello world")}`;
    const signedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(signedEml, {
        decryptOptions: {
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Sign Multipart Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: multipart/alternative; boundary=foo

--foo
Content-Type: text/plain

hello world`;
    const signedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(signedEml, {
        decryptOptions: {
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});