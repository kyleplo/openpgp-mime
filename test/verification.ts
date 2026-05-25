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
            decryptOptions: {
                verificationKeys: senderPublicKey
            }
        });
        console.log(email)
        assert.strictEqual(email.text, "hello world\n")
        assert.ok(email?.signatures && await email.signatures[0].verified)
});