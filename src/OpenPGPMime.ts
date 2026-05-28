import { PostalMime } from "./PostalMime.js"
import { Attachment, Email, PostalMimeOptions, RawEmail } from "postal-mime";
import { DecryptMessageResult, DecryptOptions, PublicKey, VerifyOptions } from "openpgp";
import "./mimeNodeMixin.js"
import { MimeNode } from "./mimeNodeMixin.js";

declare module "./PostalMime.js" {
    interface PostalMime {
        currentNode: MimeNode
        processLine (line: Uint8Array, final: boolean): Promise<void>
        isInlineTextNode (node: MimeNode): boolean
    }
}

export class OpenPGPMime extends PostalMime {
    options: OpenPGPMimeOptions;
    signatures: VerificationResult[] = [];
    nodeMap: Map<(string | Symbol), MimeNode> = new Map();
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

        email.attachments.forEach((attachment: OpenPGPAttachment) => {
            if (attachment.contentId && this.nodeMap.has(attachment.contentId)) {
                attachment.signatures = [];
                var node = this.nodeMap.get(attachment.contentId);
                while (node) {
                    attachment.signatures = attachment.signatures.concat(node.signatures || []);
                    node = node.parentNode;
                }

                if (typeof attachment.contentId === "symbol") {
                    delete attachment.contentId;
                    delete attachment.related;
                }
            }
        })
        this.nodeMap.clear();
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

    isInlineTextNode(node: MimeNode): boolean {
        if (this.options.inlineTextAsAttachments) {
            return false;
        }
        return super.isInlineTextNode(node);
    }
}

export type OpenPGPMimeOptions = PostalMimeOptions & {
    decryptOptions?: Omit<DecryptOptions, "message">
    verifyOptions?: Omit<Omit<VerifyOptions, "signature">, "message">
    keepPgpAttachments?: boolean
    preventUnencapsulatedMessages?: boolean
    inlineTextAsAttachments?: boolean
}

export type OpenPGPAttachment = Attachment & {
    signatures?: VerificationResult[]
};

export type OpenPGPEmail = Email & {
    signatures?: VerificationResult[],
    keys?: PublicKey[],
    attachments: OpenPGPAttachment[]
}

// OpenPGP.js doesn't export VerificationResult directly
export type VerificationResult = DecryptMessageResult["signatures"][0]