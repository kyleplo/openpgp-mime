import test from "node:test"
import assert from "node:assert"

import { OpenPGPMime } from "../src/OpenPGPMime.js"
import { createMessage, sign } from "openpgp"
import { senderPrivateKey, senderPublicKey } from "./fixture/keys.js";

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
Content-Type: multipart/signed; boundary=foo; micalg=pgp-md5;
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

test("Verify Incorrectly Signed Message", async () => {
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
Content-Type: multipart/signed; boundary=foo; micalg=pgp-md5;
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

test("Verify Signed Message With Missing Signature", async () => {
    const message = `Content-Type: text/plain

hello world`

    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=foo; micalg=pgp-md5;
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
Content-Type: multipart/signed; boundary=foo; micalg=pgp-md5;
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
Content-Type: multipart/signed; boundary=bar; micalg=pgp-md5;
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
    const outerMessage = `Content-Type: multipart/signed; boundary=bar; micalg=pgp-md5;
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
Content-Type: multipart/signed; boundary=foo; micalg=pgp-md5;
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