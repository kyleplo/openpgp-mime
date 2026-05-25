import { parse as parseContentType, ParsedMediaType, RequestLike, ResponseLike } from "content-type"
import { OpenPGPEmail } from "./OpenPGPMime.js";
import { MimeNodeStub } from "./mimeNodeMixin.js";

export function safeParseContentType (input: string | RequestLike | ResponseLike): ParsedMediaType {
    try {
        return parseContentType(input);
    } catch {
        return {
            type: "",
            parameters: {}
        };
    }
}

export function readAttachmentData (attachmentData: string | ArrayBuffer | Uint8Array<ArrayBufferLike>, encoding = "utf8"): string {
    var data: string;
    if (attachmentData instanceof ArrayBuffer || attachmentData instanceof Uint8Array) {
        data = new TextDecoder().decode(attachmentData);
    } else {
        data = attachmentData;
    }

    if (encoding === "base64") {
        data = atob(data);
    }
    return data;
}

export function isNodeSigned (node: MimeNodeStub, depth: number): boolean {
    switch (node?.contentType?.parsed?.value.toLowerCase()) {
        case "multipart/signed":
            return depth > 0 ? true : node.parentNode ? isNodeSigned(node.parentNode, depth + 1) : false;
        case "application/pgp-signature":
            return false;
        default:
            return node.parentNode ? isNodeSigned(node.parentNode, depth + 1) : false;
    }
}

export function printMimeTree (root: MimeNodeStub, sp = "") {
    console.log(sp + root.contentType.parsed?.value + " - \"" + new TextDecoder().decode(root.content?.slice(0, 60)).replaceAll("\n", "").replaceAll("\r", "") + "\"")
    root.childNodes.forEach(c => {
        printMimeTree(c, sp + "  ")
    })
}

const beginPgpMessage = new Uint8Array("-----BEGIN PGP MESSAGE-----".split("").map(c => c.charCodeAt(0)));
const endPgpMessage = new Uint8Array("-----END PGP MESSAGE-----".split("").map(c => c.charCodeAt(0)));
const beginPgpSignature = new Uint8Array("-----BEGIN PGP SIGNATURE-----".split("").map(c => c.charCodeAt(0)));
const endPgpSignature = new Uint8Array("-----END PGP SIGNATURE-----".split("").map(c => c.charCodeAt(0)));

export function isPgpArmoredMessage (content: Uint8Array): boolean {
    return isPgpArmored(content, beginPgpMessage, endPgpMessage);
}

export function isPgpArmoredSignature (content: Uint8Array): boolean {
    return isPgpArmored(content, beginPgpSignature, endPgpSignature);
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