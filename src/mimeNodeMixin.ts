import { readMessage, decrypt } from "openpgp";
// @ts-expect-error MimeNode has no type definitions
import MimeNode from "../node_modules/postal-mime/src/mime-node.js"
import { OpenPGPMime } from "./OpenPGPMime.js";

const mimeNodeFinalize = MimeNode.prototype.finalize;
Object.assign(MimeNode.prototype, {
    finalize: async function () {
        const thisMimeNode: MimeNodeStub = this as unknown as MimeNodeStub;
        await mimeNodeFinalize.call(thisMimeNode);

        if (!thisMimeNode.content) {
            return;
        }
        const content = new Uint8Array(thisMimeNode.content);

        if ("-----BEGIN PGP MESSAGE-----".split("").every((c, i) => c.charCodeAt(0) === content[i])) {
            const message = await readMessage({ armoredMessage: new TextDecoder().decode(content) });
            const decrypted = await decrypt(Object.assign({
                message: message
            }, thisMimeNode.postalMime.options.decryptOptions));
            thisMimeNode.content = (new TextEncoder().encode(decrypted.data)).buffer;
            thisMimeNode.postalMime.signatures = thisMimeNode.postalMime.signatures.concat(decrypted.signatures);
        }
    }
})

export type MimeNodeStub = {
    childNodes: MimeNode[],
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
    },
    root: boolean,
    parentNode?: MimeNode,
    state: string,
    headerLines: [],
    headerSize: number,
    headers: [],
    rawHeaderLines: [],
    options: {
        parentMultipartType?: string
    },
    contentTransferEncoding: {
        value: string
    },
    content?: ArrayBuffer,
    postalMime: OpenPGPMime
}