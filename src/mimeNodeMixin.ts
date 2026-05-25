import { readMessage, decrypt } from "openpgp";
// @ts-expect-error
import MimeNodeStub from "../node_modules/postal-mime/src/mime-node.js"
import { OpenPGPMime } from "./OpenPGPMime.js";
import { isPgpArmoredMessage, isPgpArmoredSignature } from "./util.js";

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

        var parent = thisMimeNode;
        while (parent.parentNode) {
            parent = parent.parentNode;

            if (parent.contentType.parsed?.value === "multipart/signed" && parent.contentType.parsed?.params?.protocol === "application/pgp-signature") {
                console.log("parent is pgp signed " + thisMimeNode.contentType.parsed?.value + " " + thisMimeNode.depth)
            }
        }

        if (isPgpArmoredMessage(content)) {
            const message = await readMessage({ armoredMessage: new TextDecoder().decode(content) });
            const decrypted = await decrypt(Object.assign({
                message: message
            }, thisMimeNode.postalMime.options.decryptOptions));
            thisMimeNode.postalMime.signatures = thisMimeNode.postalMime.signatures.concat(decrypted.signatures);

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
                    await thisMimeNode.postalMime.processLine(bytes, false);

                    startPos = readPos;
                    endPos = readPos;
                }
            }

            const bytes = encodedDecryptedContent.slice(startPos, endPos);

            await thisMimeNode.postalMime.processLine(bytes, false);
            thisMimeNode.content = thisMimeNode.contentDecoder ? await thisMimeNode.contentDecoder.finalize() : null;
            await thisMimeNode.finalizeChildNodes();
        } else if (isPgpArmoredSignature(content)) {
            console.log("found signature")
        }
    }
})

declare class MimeNode extends MimeNodeStub {
    finalizeChildNodes(): Promise<void>
    setupContentDecoder(encoding: string): void
    childNodes: MimeNodeStub[]
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
}

export { MimeNode };
