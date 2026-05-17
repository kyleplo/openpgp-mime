import test from "node:test"
import assert from "node:assert"
import { readFile } from "node:fs/promises"
import Path from "node:path"
import { createMessage, decryptKey, readKey, readPrivateKey, readSignature, sign, verify } from "openpgp";
import { OpenPGPMime } from "../src/OpenPGPMime.js"

test("Test", async t => {
    const mail = await readFile(Path.join(process.cwd(), "test", "fixture", "signed.eml"), {
        encoding: "utf8"
    });
    const publicKeyArmored = await readFile(Path.join(process.cwd(), "test", "fixture", "publickey.asc"), {
        encoding: "utf8"
    });
    const privateKeyArmored = await readFile(Path.join(process.cwd(), "test", "fixture", "privatekey.asc"), {
        encoding: "utf8"
    });

    const publicKey = await readKey({
        armoredKey: publicKeyArmored
    });
    const privateKey = await decryptKey({
        privateKey: await readPrivateKey({
            armoredKey: privateKeyArmored
        }),
        passphrase: "super long and hard to guess secret"
    });

    const mime = await OpenPGPMime.parse(mail, {
        testNoDecrypt: false,
        forceRfc822Attachments: true,
        attachmentEncoding: "base64",
        decryptOptions: {
            decryptionKeys: privateKey,
            verificationKeys: publicKey
        },
        verifyOptions: {
            verificationKeys: publicKey
        }
    });
    for (const signature of mime.signatures || []) {
        console.log(await signature.verified)
    }
});