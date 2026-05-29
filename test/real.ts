import test from "node:test"
import assert from "node:assert"
import { readFile, stat } from "node:fs/promises"
import { decryptKey, readKey, readPrivateKey } from "openpgp"
import { OpenPGPMime } from "../src/OpenPGPMime.js";
import { exit } from "node:process";

try {
    await stat("./test/fixture/senderpublickey.asc")
    await stat("./test/fixture/receiverprivatekey.asc")
    await stat("./test/fixture/signed.eml")
    await stat("./test/fixture/encrypted.eml")
} catch {
    console.warn("One or more files for the real-world email test is missing, skipping")
    exit();
}

const senderPublicKey = await readKey({
    armoredKey: (await readFile("./test/fixture/senderpublickey.asc")).toString(),
});

const receiverPrivateKey = await decryptKey({
    privateKey: await readPrivateKey({
        armoredKey: (await readFile("./test/fixture/receiverprivatekey.asc")).toString(),
    }),
    passphrase: "super long and hard to guess secret"
});

test("Verify Signed Real-World Message", async () => {
    const eml = (await readFile("./test/fixture/signed.eml")).toString();

    const email = await OpenPGPMime.parse(eml, {
        verifyOptions: {
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "This message is *signed*\u00a0but _not encrypted_.\n\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
})

test("Decrypt Encrypted Real-World Message", async () => {
    const eml = (await readFile("./test/fixture/encrypted.eml")).toString();

    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            verificationKeys: senderPublicKey,
            decryptionKeys: receiverPrivateKey
        }
    });

    assert.strictEqual(email.text, "Test message with *formatting* and /attachments/. Have a bunger:\n\nBunger\n\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
})