import test from "node:test"
import assert from "node:assert"

import OpenPGPMime, { VerificationResult } from "../index.js"
import { createMessage, encrypt, sign } from "openpgp"
import { receiverPrivateKey, receiverPublicKey, senderPrivateKey, senderPublicKey } from "./fixture/keys.js";

test("Get Signature From Signed Message", async () => {
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
        },
        inlineTextAsAttachments: true,
        attachmentEncoding: "utf8"
    });
    assert.strictEqual(email.attachments.length, 1);
    assert.strictEqual(email.attachments[0].mimeType, "text/plain")
    assert.strictEqual(email.attachments[0].content, "hello world\n")
    assert.strictEqual(email.attachments[0].signatures?.length, 1)
    assert.ok(await (email.attachments[0].signatures as VerificationResult[])[0].verified)
    assert.ok((email.attachments[0].signatures as VerificationResult[])[0].keyID.equals(senderPublicKey.getKeyID()))
});

test("Get Signature From Signed And Encrypted Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: "hello world"
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: text/plain

${armoredMessage}`;
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        },
        inlineTextAsAttachments: true,
        attachmentEncoding: "utf8"
    });
    assert.strictEqual(email.attachments.length, 1);
    assert.strictEqual(email.attachments[0].mimeType, "text/plain")
    assert.strictEqual(email.attachments[0].content, "hello world\n")
    assert.strictEqual(email.attachments[0].signatures?.length, 1)
    assert.ok(await (email.attachments[0].signatures as VerificationResult[])[0].verified)
    assert.ok((email.attachments[0].signatures as VerificationResult[])[0].keyID.equals(senderPublicKey.getKeyID()))
});

test("Get Signature From Signed And Encrypted Multipart Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: text/plain

hello world`
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
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        },
        inlineTextAsAttachments: true,
        attachmentEncoding: "utf8"
    });
    assert.strictEqual(email.attachments.length, 1);
    assert.strictEqual(email.attachments[0].mimeType, "text/plain")
    assert.strictEqual(email.attachments[0].content, "hello world\n")
    assert.strictEqual(email.attachments[0].signatures?.length, 1)
    assert.ok(await (email.attachments[0].signatures as VerificationResult[])[0].verified)
    assert.ok((email.attachments[0].signatures as VerificationResult[])[0].keyID.equals(senderPublicKey.getKeyID()))
});

test("Get Signatures From Nested Signed Message", async () => {
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
        },
        inlineTextAsAttachments: true,
        attachmentEncoding: "utf8"
    });
    assert.strictEqual(email.attachments.length, 1);
    assert.strictEqual(email.attachments[0].mimeType, "text/plain")
    assert.strictEqual(email.attachments[0].content, "hello world\n")
    assert.strictEqual(email.attachments[0].signatures?.length, 2)
    assert.ok(await (email.attachments[0].signatures as VerificationResult[])[0].verified)
    assert.ok((email.attachments[0].signatures as VerificationResult[])[0].keyID.equals(senderPublicKey.getKeyID()))
    assert.ok(await (email.attachments[0].signatures as VerificationResult[])[1].verified)
    assert.ok((email.attachments[0].signatures as VerificationResult[])[1].keyID.equals(senderPublicKey.getKeyID()))
});

test("Get Signatures From Complex Message", async () => {
    const message = `Content-Type: text/plain

hello world`
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: message
        })
    });
    const signingMessage = `Content-Type: multipart/alternate; boundary=foo

--foo
Content-Type: text/plain
Content-Transfer-Encoding: quoted-printable

=C2=A1hola mundo!
--foo
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=bar

--bar
Content-Type: application/pgp-encrypted

Version: 1

--bar
Content-Type: application/octet-stream

${armoredMessage}`
    const signature = await sign({
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: signingMessage
        }),
        detached: true
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/signed; boundary=baz; micalg=pgp-sha512;
  protocol="application/pgp-signature"

--baz
${signingMessage}
--baz
Content-Type: application/pgp-signature

${signature}`;
    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        },
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        },
        inlineTextAsAttachments: true,
        attachmentEncoding: "utf8"
    });

    assert.strictEqual(email.attachments.length, 2);

    assert.strictEqual(email.attachments[0].mimeType, "text/plain")
    assert.strictEqual(email.attachments[0].content, "¡hola mundo!\n")
    assert.strictEqual(email.attachments[0].signatures?.length, 1)
    assert.ok(await (email.attachments[0].signatures as VerificationResult[])[0].verified)
    assert.ok((email.attachments[0].signatures as VerificationResult[])[0].keyID.equals(senderPublicKey.getKeyID()))

    assert.strictEqual(email.attachments[1].mimeType, "text/plain")
    assert.strictEqual(email.attachments[1].content, "hello world\n")
    assert.strictEqual(email.attachments[1].signatures?.length, 2)
    email.attachments[1].signatures.forEach(async signature => {
        assert.ok(await signature.verified)
        assert.ok(signature.keyID.equals(senderPublicKey.getKeyID()))
    });
});