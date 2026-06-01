import test from "node:test"
import assert from "node:assert"
import OpenPGPMime from "../index.js"
import { receiverPrivateKey, receiverPublicKey, senderPrivateKey, senderPublicKey, senderPublicKeyArmored } from "./fixture/keys.js";
import { createMessage, encrypt } from "openpgp";

test("Discover Key", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: application/pgp-keys

${senderPublicKeyArmored}`
    const email = await OpenPGPMime.parse(eml);
    assert.ok(email.attachments[0].key)
    assert.strictEqual(email.attachments[0].key.getFingerprint(), senderPublicKey.getFingerprint())
});

test("Discover Invalid Key", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: application/pgp-keys

${senderPublicKeyArmored.replace("=", "A")}`
    const email = await OpenPGPMime.parse(eml);
    assert.ok(!email.attachments[0].key);
});

test("Discover Key In Multipart Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: multipart/alternative; boundary=foo

--foo
Content-Type: text/plain

hello world
--foo
Content-Type: application/pgp-keys

${senderPublicKeyArmored}`
    const email = await OpenPGPMime.parse(eml);
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email.attachments[0].key)
    assert.strictEqual(email.attachments[0].key.getFingerprint(), senderPublicKey.getFingerprint())
});

test("Discover Key In Encrypted Multipart Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: application/pgp-keys

${senderPublicKeyArmored}`
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=foo

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

${armoredMessage}`
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
}   );
    assert.ok(email.attachments[0].key)
    assert.strictEqual(email.attachments[0].key.getFingerprint(), senderPublicKey.getFingerprint())
    assert.ok(email.attachments[0].signatures && await email.attachments[0].signatures[0].verified)
});