import test from "node:test"
import assert from "node:assert"

import { OpenPGPMime } from "../src/OpenPGPMime.js"
import { createMessage, encrypt, sign } from "openpgp"
import { receiverPrivateKey, receiverPublicKey, senderPrivateKey, senderPublicKey } from "./fixture/keys.js";

test("Verify Signed Message", async () => {
    const message = `Content-Type: text/plain

hello world`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify Signed Multiline Message", async () => {
    const message = `Content-Type: text/plain

hello
world`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello\nworld\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify Signed Message With Bad Signature", async () => {
    const message = `Content-Type: text/plain

hello world`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message.replace("hello", "helo")
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures)
    assert.rejects(email.signatures[0].verified)
});

test("Verify Signed Message With Wrong Verification Key", async () => {
    const message = `Content-Type: text/plain

hello world`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: receiverPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures)
    assert.rejects(email.signatures[0].verified)
});

test("Verify Signed Message With Missing Signature", async () => {
    const message = `Content-Type: text/plain

hello world`

    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && email.signatures.length === 0)
});

test("Verify Signed Multipart Message", async () => {
    const message = `Content-Type: multipart/alternative; boundary=bar

--bar
Content-Type: text/plain

hello world
--bar
Content-Type: text/html

<p>hello world</p>`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.strictEqual(email.html, "<p>hello world</p>\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify Partially Signed Message", async () => {
    const message = `Content-Type: text/plain

hello world`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/alternative; boundary=foo

--foo
Content-Type: multipart/signed; boundary=bar; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--bar
${message}
--bar
Content-Type: application/pgp-signature

${signature}
--foo
Content-Type: text/html

<p>hello world</p>`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.strictEqual(email.html, "<p>hello world</p>\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify Nested Signed Message", async () => {
    const innerMessage = `Content-Type: text/plain

hello world`
    const innerSignature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: innerMessage
        }),
        detached: true
    });
    const outerMessage = `Content-Type: multipart/signed; boundary=bar; micalg=pgp-sha512;
  protocol="application/pgp-signature

--bar
${innerMessage}
--bar
Content-Type: application/pgp-signature

${innerSignature}`
    const outerSignature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: outerMessage
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${outerMessage}
--foo
Content-Type: application/pgp-signature

${outerSignature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify Signed Base64 Encoded Message", async () => {
    const message = `Content-Type: text/plain
Content-Transfer-Encoding: base64

${btoa("hello world")}`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify Signed Quoted-Printable Message", async () => {
    const message = `Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

=A1hola mundo!`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "¡hola mundo!\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify Signed Message With Attachment", async () => {
    const message = `Content-Type: multipart/alternative; boundary=bar

--bar
Content-Type: text/plain

hello world
--bar
Content-Type: image/png

not actually an image but whatever`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}`;

    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        },
        attachmentEncoding: "utf8"
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
    assert.strictEqual(email.attachments[0].content, "not actually an image but whatever\n")
});

test("Verify Signed Message With Multiple Signatures", async () => {
    const message = `Content-Type: text/plain

hello world`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--foo
${message}
--foo
Content-Type: application/pgp-signature

${signature}
--foo
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
    assert.ok(email?.signatures && await email.signatures[1].verified)
});

test("Decrypt And Verify Encrypted And Signed Message", async () => {
    const message = `Content-Type: text/plain

hello world`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        }),
        detached: true
    });
    const signedMessage = `Content-Type: multipart/signed; boundary=bar; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--bar
${message}
--bar
Content-Type: application/pgp-signature

${signature}`;
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        message: await createMessage({
            text: signedMessage
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=foo

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

${armoredMessage}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        },
        decryptOptions: {
            decryptionKeys: receiverPrivateKey
        }
    });

    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Verify And Decrypted Signed And Encrypted Message", async () => {
    const message = `Content-Type: text/plain

hello world`
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        message: await createMessage({
            text: message
        })
    });
    const signingMessage = `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=foo

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

${armoredMessage}`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: signingMessage
        }),
        detached: true
    });
    const eml = `Content-Type: multipart/signed; boundary=bar; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--bar
${signingMessage}
--bar
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        },
        decryptOptions: {
            decryptionKeys: receiverPrivateKey
        }
    });

    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});