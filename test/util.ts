import test from "node:test"
import assert from "node:assert"
import { isPgpArmoredMessage, isPgpArmoredSignature, isPgpPublicKeyBlock, normalizeRawEmail } from "../src/util.js";

test("isPgpArmoredMessage Basic", () => {
    const message = new TextEncoder().encode(`\
-----BEGIN PGP MESSAGE-----
woergnwerkjgnwkjrg
-----END PGP MESSAGE-----`);    
    assert.ok(isPgpArmoredMessage(message));
});

test("isPgpArmoredMessage Missing End Tag", () => {
    const message = new TextEncoder().encode(`\
-----BEGIN PGP MESSAGE-----
woergnwerkjgnwkjrg`);    
    assert.ok(!isPgpArmoredMessage(message));
});

test("isPgpArmoredMessage Line Break At End", () => {
    const message = new TextEncoder().encode(`\
-----BEGIN PGP MESSAGE-----
woergnwerkjgnwkjrg
-----END PGP MESSAGE-----
`);    
    assert.ok(isPgpArmoredMessage(message));
});

test("isPgpArmoredMessage No Content", () => {
    const message = new TextEncoder().encode(`\
-----BEGIN PGP MESSAGE-----
-----END PGP MESSAGE-----`);    
    assert.ok(!isPgpArmoredMessage(message));
});

test("isPgpArmoredSignature Basic", () => {
    const signature = new TextEncoder().encode(`\
-----BEGIN PGP SIGNATURE-----
woergnwerkjgnwkjrg
-----END PGP SIGNATURE-----`);    
    assert.ok(isPgpArmoredSignature(signature));
});

test("isPgpPublicKeyBlock Basic", () => {
    const signature = new TextEncoder().encode(`\
-----BEGIN PGP PUBLIC KEY BLOCK-----
woergnwerkjgnwkjrg
-----END PGP PUBLIC KEY BLOCK-----`);    
    assert.ok(isPgpPublicKeyBlock(signature));
});

test("normalizeRawEmail String", async () => {
    assert.strictEqual(
        new TextDecoder().decode(
            new Uint8Array(await normalizeRawEmail("hello"))
        ),
        "hello")
});

test("normalizeRawEmail ArrayBuffer", async () => {
    assert.strictEqual(
        new TextDecoder().decode(
            await normalizeRawEmail(new Uint8Array([104, 101, 108, 108, 111]).buffer)
        ),
        "hello")
});

test("normalizeRawEmail Uint8Array", async () => {
    assert.strictEqual(
        new TextDecoder().decode(
            await normalizeRawEmail(new Uint8Array([104, 101, 108, 108, 111]))
        ),
        "hello")
});

test("normalizeRawEmail Blob", async () => {
    assert.strictEqual(
        new TextDecoder().decode(
            await normalizeRawEmail(new Blob(["hello"]))
        ),
        "hello")
});

test("normalizeRawEmail Buffer", async () => {
    assert.strictEqual(
        new TextDecoder().decode(
            await normalizeRawEmail(Buffer.from("hello"))
        ),
        "hello")
});

test("normalizeRawEmail ReadableStream", async () => {
    assert.strictEqual(
        new TextDecoder().decode(
            await normalizeRawEmail(new ReadableStream({
                start: (controller: ReadableStreamDefaultController) => {
                    controller.enqueue(new Uint8Array([104]));
                    controller.enqueue(new Uint8Array([101]));
                    controller.enqueue(new Uint8Array([108]));
                    controller.enqueue(new Uint8Array([108]));
                    controller.enqueue(new Uint8Array([111]));
                    controller.close();
                }
            }))
        ),
        "hello")
});