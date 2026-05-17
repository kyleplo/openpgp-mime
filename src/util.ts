import { parse as parseContentType, ParsedMediaType, RequestLike, ResponseLike } from "content-type"
import { MimeNode, OpenPGPEmail } from "./OpenPGPMime.js";

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

export function mergeEmails (a: OpenPGPEmail, b: OpenPGPEmail): OpenPGPEmail {
    a.headers = a.headers.concat(b.headers);
    a.headerLines = a.headerLines.concat(b.headerLines);
    if (!a.from) {
        a.from = b.from;
    }
    if (!a.sender) {
        a.sender = b.sender;
    }
    if (!a.replyTo) {
        a.replyTo = b.replyTo;
    }
    if (!a.deliveredTo) {
        a.deliveredTo = b.deliveredTo;
    }
    if (!a.returnPath) {
        a.returnPath = b.returnPath;
    }
    if (!a.to) {
        a.to = b.to;
    }
    if (!a.cc) {
        a.cc = b.cc;
    }
    if (!a.bcc) {
        a.bcc = b.bcc;
    }
    if (!a.subject) {
        a.subject = b.subject;
    }
    if (!a.messageId) {
        a.messageId = b.messageId;
    }
    if (!a.inReplyTo) {
        a.inReplyTo = b.inReplyTo;
    }
    if (!a.references) {
        a.references = b.references;
    }
    if (!a.date) {
        a.date = b.date;
    }
    if (!a.html) {
        a.html = b.html;
    }
    if (!a.text) {
        a.text = b.text;
    }
    a.attachments = b.attachments;
    a.signatures = (a.signatures || []).concat(b.signatures || [])
    return a;
}

export function isNodeSigned (node: MimeNode, depth: number): boolean {
    switch (node?.contentType?.parsed?.value.toLowerCase()) {
        case "multipart/signed":
            return depth > 0 ? true : node.parentNode ? isNodeSigned(node.parentNode, depth + 1) : false;
        case "application/pgp-signature":
            return false;
        default:
            return node.parentNode ? isNodeSigned(node.parentNode, depth + 1) : false;
    }
}