import { PostalMime } from "./PostalMime.js"
import { Email, PostalMimeOptions, RawEmail } from "postal-mime";
import { DecryptOptions, KeyID, PublicKey, Signature, VerifyOptions } from "openpgp";
import "./mimeNodeMixin.js"
import { MimeNode } from "./mimeNodeMixin.js";

declare module "./PostalMime.js" {
    interface PostalMime {
        currentNode: MimeNode
        processLine (line: Uint8Array, final: boolean): Promise<void>
    }
}

export class OpenPGPMime extends PostalMime {
    options: OpenPGPMimeOptions;
    signatures: VerificationResult[] = [];
    keys: PublicKey[] = [];

    constructor (options?: OpenPGPMimeOptions) {
        super(options);
        this.options = options || {};
    }

    static async parse (rawEmail: RawEmail, options?: OpenPGPMimeOptions): Promise<OpenPGPEmail> {
        return (new OpenPGPMime(options)).parse(rawEmail);
    }

    async parse (rawEmail: RawEmail): Promise<OpenPGPEmail> {
        const email: OpenPGPEmail = await super.parse(rawEmail);
        email.signatures = this.signatures;
        email.keys = this.keys;

        if (!this.options.keepPgpAttachments) {
            email.attachments = email.attachments.filter(attachment => attachment.mimeType !== "application/pgp-encrypted" && attachment.mimeType !== "application/pgp-signature" && attachment.mimeType !== "application/pgp-keys")
        }

        return email;
    }

    async processLine (line: Uint8Array, final: boolean, decryptedDepth = 0): Promise<void> {
        await super.processLine(line, final);

        var parent = this.currentNode;
        while (parent.parentNode) {
            parent = parent.parentNode;

            if (parent.depth < decryptedDepth) {
                return;
            }

            if (parent.contentType.parsed?.value === "multipart/signed" && parent.contentType.parsed?.params?.protocol === "application/pgp-signature" && parent.childNodes.length === 1) {
                if (parent.signedContent) {
                    parent.signedContent.push(line);
                } else {
                    parent.signedContent = [];
                }
            }
        }
    }
}

export type OpenPGPMimeOptions = PostalMimeOptions & {
    decryptOptions?: Omit<DecryptOptions, "message">
    verifyOptions?: Omit<Omit<VerifyOptions, "signature">, "message">
    keepPgpAttachments?: boolean
    preventUnencapsulatedMessages?: boolean
}

export type OpenPGPEmail = Email & {
    signatures?: VerificationResult[],
    keys?: PublicKey[]
}

// taken from OpenPGP.js type definitions, is not exported from there
export interface VerificationResult {
    keyID: KeyID,
    verified: Promise<true>,
    signature: Promise<Signature>
}