import PostalMime, { RawEmail } from "postal-mime";
import { MimeNode } from "./mimeNodeMixin.js";
import { OpenPGPEmail } from "./OpenPGPMime.js";

export function printMimeTree (root: MimeNode, sp = "") {
    console.log(sp + root.contentType.parsed?.value + " - \"" + new TextDecoder().decode(root.content?.slice(0, 60)).replaceAll("\n", "").replaceAll("\r", "") + "\"")
    root.childNodes.forEach(c => {
        printMimeTree(c, sp + "  ")
    })
}

const beginPgpMessage = new Uint8Array("-----BEGIN PGP MESSAGE-----".split("").map(c => c.charCodeAt(0)));
const endPgpMessage = new Uint8Array("-----END PGP MESSAGE-----".split("").map(c => c.charCodeAt(0)));
const beginPgpSignature = new Uint8Array("-----BEGIN PGP SIGNATURE-----".split("").map(c => c.charCodeAt(0)));
const endPgpSignature = new Uint8Array("-----END PGP SIGNATURE-----".split("").map(c => c.charCodeAt(0)));
const beginPgpPublicKeyBlock = new Uint8Array("-----BEGIN PGP PUBLIC KEY BLOCK-----".split("").map(c => c.charCodeAt(0)));
const endPgpPublicKeyBlock = new Uint8Array("-----END PGP PUBLIC KEY BLOCK-----".split("").map(c => c.charCodeAt(0)));

export function isPgpArmoredMessage (content: Uint8Array): boolean {
    return isPgpArmored(content, beginPgpMessage, endPgpMessage);
}

export function isPgpArmoredSignature (content: Uint8Array): boolean {
    return isPgpArmored(content, beginPgpSignature, endPgpSignature);
}

export function isPgpPublicKeyBlock (content: Uint8Array): boolean {
    return isPgpArmored(content, beginPgpPublicKeyBlock, endPgpPublicKeyBlock);
}

function isPgpArmored (content: Uint8Array, begin: Uint8Array, end: Uint8Array): boolean {
    if (content.length < begin.length + end.length + 2 || !begin.every((c, i) => c === content[i])) {
        return false;
    }

    for (var i = content.length - 1; i >= 0; i--) {
        if (content[i] === 45) {
            return end.every((c, x) => c === content[i - (end.length - 1) + x]);
        } else if (content[i] !== 9 && content[i] !== 10 && content[i] !== 13 && content[i] !== 32) {
            return false;
        }
    }
    return false;
}

export async function normalizeRawEmail (rawEmail: RawEmail): Promise<Uint8Array> {
    if (typeof rawEmail.getReader === "function") {
        return (new PostalMime()).resolveStream(rawEmail);
    }

    if (typeof rawEmail === "string") {
        return new TextEncoder().encode(rawEmail);
    }

    if (rawEmail instanceof Blob || Object.prototype.toString.call(rawEmail) === '[object Blob]') {
        return rawEmail.arrayBuffer();
    }

    if (rawEmail.buffer instanceof ArrayBuffer) {
        return new Uint8Array(rawEmail).buffer;
    }

    if (rawEmail instanceof ArrayBuffer) {
        return new Uint8Array(rawEmail);
    }

    return new Uint8Array();
}