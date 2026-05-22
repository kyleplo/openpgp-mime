import test from "node:test"
import assert from "node:assert"
import { isPgpArmoredMessage } from "../src/util.js";

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