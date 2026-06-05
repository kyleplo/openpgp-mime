import test from "node:test"
import assert from "node:assert"

import OpenPGPMime from "../index.js"
import { receiver2PrivateKey, receiver2PublicKey, receiverPrivateKey, receiverPublicKey, senderPrivateKey, senderPublicKey } from "./fixture/keys.js";

test("Encrypt Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain

hello world`;
    const encryptedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            encryptionKeys: receiverPublicKey
        }
    });
    const email = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
});

test("Encrypt And Sign Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain

hello world`;
    const encryptedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            encryptionKeys: receiverPublicKey,
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Encrypt Non-String Message", async () => {
    const eml = new TextEncoder().encode(`Mime-Version: 1.0
Content-Type: text/plain

hello world`);
    const encryptedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            encryptionKeys: receiverPublicKey,
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Encrypt Quoted-Printable Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

=A1hola mundo!`;
    const encryptedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            encryptionKeys: receiverPublicKey,
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "¡hola mundo!\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Encrypt Base64 Encoded Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain
Content-Transfer-Encoding: base64

${btoa("hello world")}`;
    const encryptedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            encryptionKeys: receiverPublicKey,
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Encrypt Multipart Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: multipart/alternative; boundary=foo

--foo
Content-Type: text/plain

hello world`;
    const encryptedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            encryptionKeys: receiverPublicKey,
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Encrypt Message For Multiple Recipients", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain

hello world`;
    const encryptedEml = await OpenPGPMime.apply(eml, {
        encryptOptions: {
            encryptionKeys: [receiverPublicKey, receiver2PublicKey],
            signingKeys: senderPrivateKey
        }
    });
    const email = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)

    const email2 = await OpenPGPMime.parse(encryptedEml, {
        decryptOptions: {
            decryptionKeys: receiver2PrivateKey,
            verificationKeys: senderPublicKey
        }
    })
    assert.strictEqual(email2.text, "hello world\n")
    assert.ok(email2?.signatures && await email2.signatures[0].verified)
});