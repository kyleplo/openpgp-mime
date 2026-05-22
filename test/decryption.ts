import test from "node:test"
import assert from "node:assert"

import { OpenPGPMime } from "../src/OpenPGPMime.js"
import { createMessage, encrypt } from "openpgp"
import { receiverPrivateKey, receiverPublicKey, senderPrivateKey, senderPublicKey } from "./fixture/keys.js";
import { splitLines } from "./fixture/splitlines.js";
import { encode, wrap } from "libqp"

test("Decrypt Encrypted Message", async () => {
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
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Decrypt Encrypted Multiline Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `hello
world`
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: text/plain

${armoredMessage}`;
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    });

    assert.strictEqual(email.text, `hello
world\n`)
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Decrypt Encrypted Unsigned Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
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
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && email.signatures.length === 0)
});

test("Decrypt Encrypted Message With Wrong Decryption Key", async () => {
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
    assert.rejects(OpenPGPMime.parse(eml, {
            decryptOptions: {
                decryptionKeys: senderPrivateKey,
                verificationKeys: receiverPublicKey
            }
    }));
});

test("Decrypt Encrypted Message With Wrong Verification Key", async () => {
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
            verificationKeys: receiverPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n");
    if (email.signatures) {
        assert.rejects(email.signatures[0].verified);
    } else {
        assert.fail();
    }
});

test("Decrypt Multipart Message Containing Encrypted Message", async () => {
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
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Decrypt Multipart Message Containing Encrypted Multipart Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: multipart/alternative; boundary=bar

--bar
Content-Type: text/plain

hello world
--bar
Content-Type: text/html

<p>hello world</p>`
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
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.strictEqual(email.html, "<p>hello world</p>\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Decrypt Multipart Message Containing Encrypted Multipart Message Containing Encrypted Multipart Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: multipart/alternative; boundary=baz

--baz
Content-Type: text/plain

hello world
--baz
Content-Type: text/html

<p>hello world</p>`
        })
    });
    const armoredMessage2 = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=bar

--bar
Content-Type: application/pgp-encrypted

Version: 1

--bar
Content-Type: application/octet-stream

${armoredMessage}`
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=foo

--foo
Content-Type: application/pgp-encrypted

Version: 1

--foo
Content-Type: application/octet-stream

${armoredMessage2}`;
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.strictEqual(email.html, "<p>hello world</p>\n")
    assert.ok(email?.signatures && await email.signatures[0].verified && await email.signatures[1].verified)
});

test("Decrypt Multipart Message Containing Multiple Encrypted Messages", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: text/plain

hello world`
        })
    });
    const armoredMessage2 = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: text/html

<p>hello world</p>`
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/alternative; boundary=foo

--foo
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=bar

--bar
Content-Type: application/pgp-encrypted

Version: 1

--bar
Content-Type: application/octet-stream

${armoredMessage}--bar--
--foo
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=baz

--baz
Content-Type: application/pgp-encrypted

Version: 1

--baz
Content-Type: application/octet-stream

${armoredMessage2}--baz--
--foo--`;
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    });
    
    assert.strictEqual(email.text, "hello world\n")
    assert.strictEqual(email.html, "<p>hello world</p>\n")
    assert.ok(email?.signatures && await email.signatures[0].verified && await email.signatures[1].verified)
});

test("Decrypt Multipart Message Containing Encrypted Message And Unencrypted Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: text/plain

hello world`
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/alternative; boundary=foo

--foo
Content-Type: text/html

<p>hello world</p>
--foo
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=bar

--bar
Content-Type: application/pgp-encrypted

Version: 1

--bar
Content-Type: application/octet-stream

${armoredMessage}`;
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.strictEqual(email.html, "<p>hello world</p>\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Decrypt Base64 Encoded Multipart Message Containing Encrypted Message", async () => {
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
Content-Transfer-Encoding: base64

${splitLines(btoa("Version: 1"))}

--foo
Content-Type: application/octet-stream
Content-Transfer-Encoding: base64

${splitLines(btoa(armoredMessage))}`;
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "hello world\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Decrypt Multipart Message Containing Encrypted Base64 Encoded Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: text/plain
Content-Transfer-Encoding: base64

${splitLines(btoa("hello world"))}`
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
        }
    });
    assert.strictEqual(email.text, "hello world")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Read Unencrypted Base64 Encoded Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain
Content-Transfer-Encoding: base64

${splitLines(btoa("hello world"))}`;
    const email = await OpenPGPMime.parse(eml);
    assert.strictEqual(email.text, "hello world")
});

test("Decrypt Quoted-Printable Multipart Message Containing Encrypted Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

=A1hola mundo!`
        })
    });
    const eml = `Mime-Version: 1.0
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=foo

--foo
Content-Type: application/pgp-encrypted; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

V=65rsion: 1

--foo
Content-Type: application/octet-stream; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

${wrap(encode(armoredMessage))}`;
    const email = await OpenPGPMime.parse(eml, {
        decryptOptions: {
            decryptionKeys: receiverPrivateKey,
            verificationKeys: senderPublicKey
        }
    });
    assert.strictEqual(email.text, "¡hola mundo!\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Decrypt Multipart Message Containing Encrypted Quoted-Printable Message", async () => {
    const armoredMessage = await encrypt({
        encryptionKeys: receiverPublicKey,
        signingKeys: senderPrivateKey,
        message: await createMessage({
            text: `Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

=A1hola mundo!`
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
        }
    });
    assert.strictEqual(email.text, "¡hola mundo!\n")
    assert.ok(email?.signatures && await email.signatures[0].verified)
});

test("Read Unencrypted Quoted-Printable Message", async () => {
    const eml = `Mime-Version: 1.0
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: quoted-printable

=A1hola mundo!`;
    const email = await OpenPGPMime.parse(eml);
    assert.strictEqual(email.text, "¡hola mundo!\n")
});