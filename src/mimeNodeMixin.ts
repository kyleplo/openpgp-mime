import { readMessage, decrypt, verify, createMessage, readSignature, readKey } from "openpgp";
import { OpenPGPMime, VerificationResult } from "./OpenPGPMime.js";
import { isPgpArmoredMessage, isPgpArmoredSignature, isPgpPublicKeyBlock } from "./util.js";

var MimeNodeStub;
try {
    // @ts-expect-error
    MimeNodeStub = (await import("../node_modules/postal-mime/src/mime-node.js")).default;
} catch {
    try {
        // @ts-expect-error
        MimeNodeStub = (await import("../../node_modules/postal-mime/src/mime-node.js")).default;
    } catch {
        try {
            // @ts-expect-error
            MimeNodeStub = (await import("../../../node_modules/postal-mime/src/mime-node.js")).default;
        } catch {
            throw new Error("Failed to apply MimeNode mixin");
        }
    }
}

const mimeNodeFinalize = MimeNodeStub.prototype.finalize;
Object.assign(MimeNodeStub.prototype, {
    finalize: async function () {
        const thisMimeNode: MimeNode = this as unknown as MimeNode;

        if (thisMimeNode.state === "finished") {
            return;
        }

        await mimeNodeFinalize.call(thisMimeNode);

        if (!thisMimeNode.content || !(thisMimeNode.postalMime instanceof OpenPGPMime)) {
            return;
        }
        const content = new Uint8Array(thisMimeNode.content);

        if (isPgpArmoredMessage(content) && (!thisMimeNode.postalMime.options.preventUnencapsulatedMessages || thisMimeNode.contentType.parsed?.value === "application/octet-stream")) {

            const message = await readMessage({ armoredMessage: new TextDecoder().decode(content) });
            const decrypted = await decrypt(Object.assign({
                message: message
            }, thisMimeNode.postalMime.options.decryptOptions));
            thisMimeNode.postalMime.signatures = thisMimeNode.postalMime.signatures.concat(decrypted.signatures);
            thisMimeNode.signatures = (thisMimeNode.signatures || []).concat(decrypted.signatures);

            if (thisMimeNode.options?.parentMultipartType === "encrypted") {
                thisMimeNode.state = "header";
                thisMimeNode.headerLines.length = 0;
                thisMimeNode.headerSize = 0;
                thisMimeNode.headers.length = 0;
                thisMimeNode.rawHeaderLines.length = 0;
                thisMimeNode.contentType = {
                    value: "text/plain",
                    default: true
                }
                thisMimeNode.contentTransferEncoding = {
                    value: "8bit"
                }
            } else {
                thisMimeNode.state = "body";
                thisMimeNode.setupContentDecoder(thisMimeNode.contentTransferEncoding.encoding as string)
            }

            const encodedDecryptedContent = new TextEncoder().encode(decrypted.data);
            var startPos = 0;
            var endPos = 0;
            var readPos = 0;
            while (readPos < encodedDecryptedContent.length) {
                const char = encodedDecryptedContent[readPos++];

                if (char !== 0x0d && char !== 0x0a) {
                    endPos = readPos;
                }

                if (char === 0x0a) {
                    const bytes = encodedDecryptedContent.slice(startPos, endPos);
                    await thisMimeNode.postalMime.processLine(bytes, false, thisMimeNode.depth);

                    startPos = readPos;
                    endPos = readPos;
                }
            }

            const bytes = encodedDecryptedContent.slice(startPos, endPos);
            await thisMimeNode.postalMime.processLine(bytes, false, thisMimeNode.depth);
            if (thisMimeNode.state === "finished") {
                await thisMimeNode.finalizeChildNodes();
            } else {
                await thisMimeNode.finalize();
            }
        } else if (isPgpArmoredSignature(content) && thisMimeNode.parentNode?.signedContent && thisMimeNode.contentType.parsed?.value === "application/pgp-signature") {
            const messageText = thisMimeNode.parentNode.signedContent.map(t => new TextDecoder().decode(t)).join("\r\n");
            const message = await createMessage({
                text: messageText
            });
            
            const armoredSignature = new TextDecoder().decode(content);
            const signature = await readSignature({
                armoredSignature: armoredSignature
            });
            
            const verification = await verify(Object.assign({
                message: message,
                signature: signature
            }, thisMimeNode.postalMime.options.verifyOptions));
            thisMimeNode.postalMime.signatures = thisMimeNode.postalMime.signatures.concat(verification.signatures);
            thisMimeNode.parentNode.signatures = (thisMimeNode.parentNode.signatures || []).concat(verification.signatures);
        } else if (isPgpPublicKeyBlock(content) && thisMimeNode.contentType.parsed?.value === "application/pgp-keys") {
            try {
                const key = await readKey({
                    armoredKey: new TextDecoder().decode(content)
                });

                thisMimeNode.postalMime.keys.push(key);
            } catch {}
        }

        if (!thisMimeNode.contentId) {
            thisMimeNode.contentId = Symbol();
        }
        thisMimeNode.postalMime.nodeMap.set(thisMimeNode.contentId, thisMimeNode);
    }
})

declare class MimeNode extends MimeNodeStub {
    finalizeChildNodes(): Promise<void>
    setupContentDecoder(encoding: string): void
    childNodes: MimeNode[]
    contentType: {
        value: string,
        parsed?: {
            value: string,
            params: {
                [key: string]: string
            }
        },
        multipart?: string,
        default?: boolean
    }
    root: boolean
    parentNode?: MimeNode
    state: string
    headerLines: []
    headerSize: number
    headers: []
    rawHeaderLines: []
    options: {
        parentMultipartType?: string
    }
    contentTransferEncoding: {
        value: string,
        encoding?: string
    }
    content?: ArrayBuffer | null
    postalMime: OpenPGPMime
    contentDecoder: {
        finalize (): Promise<ArrayBuffer>
    }
    depth: number
    finalize (): Promise<void>
    signedContent?: Uint8Array[]
    signatures?: VerificationResult[]
    contentId?: string | Symbol
}

export { MimeNode };
