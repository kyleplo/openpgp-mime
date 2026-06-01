import { PostalMime } from "./PostalMime.js"
import { Attachment, Email, PostalMimeOptions, RawEmail } from "postal-mime";
import { DecryptMessageResult, DecryptOptions, KeyID, PrivateKey, PublicKey, VerifyOptions } from "openpgp";
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

    constructor (options?: OpenPGPMimeOptions) {
        super(options);
        this.options = options || {};

        if (this.options.verifyOptions && !this.options.decryptOptions) {
            this.options.decryptOptions = {
                verificationKeys: this.options.verifyOptions?.verificationKeys,
                config: this.options.verifyOptions?.config,
                expectSigned: this.options.verifyOptions.expectSigned,
                date: this.options.verifyOptions.date || undefined
            };
        } else if (this.options.decryptOptions && !this.options.verifyOptions) {
            this.options.verifyOptions = {
                verificationKeys: this.options.decryptOptions?.verificationKeys || [],
                config: this.options.decryptOptions?.config,
                expectSigned: this.options.decryptOptions.expectSigned,
                date: this.options.decryptOptions.date
            };
        }
    }

    static async parse (rawEmail: RawEmail, options?: OpenPGPMimeOptions): Promise<OpenPGPEmail> {
        return (new OpenPGPMime(options)).parse(rawEmail);
    }

    async parse (rawEmail: RawEmail): Promise<OpenPGPEmail> {
        const email: OpenPGPEmail = await super.parse(rawEmail);
        email.signatures = this.signatures;

        if (!this.options.keepPgpAttachments) {
            email.attachments = email.attachments.filter(attachment => attachment.mimeType !== "application/pgp-encrypted" && attachment.mimeType !== "application/pgp-signature")
        }

        email.attachments.forEach((attachment: OpenPGPAttachment) => {
            if (attachment.contentId && this.nodeMap.has(attachment.contentId)) {
                attachment.signatures = [];
                var node = this.nodeMap.get(attachment.contentId);
                if (node && node.key && attachment.mimeType === "application/pgp-keys") {
                    attachment.key = node.key;
                }

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

        var parent: MimeNode | undefined = this.currentNode;
        while (parent) {
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

            parent = parent.parentNode;
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
    /** Decrypt options to be passed to OpenPGP.js */
    decryptOptions?: Omit<DecryptOptions, "message">
    /** Verify options to be passed to OpenPGP.js */
    verifyOptions?: Omit<Omit<VerifyOptions, "signature">, "message">
    /** Whether to preserve attachments containing PGP metadata (application/pgp-encrypted and application/pgp-signature) */
    keepPgpAttachments?: boolean
    /** Whether to disallow PGP encrypted messages that are not wrapped in a multipart/encrypted MIME node */
    preventUnencapsulatedMessages?: boolean
    /** Whether to return inline text nodes (text/plain or text/html) as attachments, allowing their individual signatures to be enumerated */
    inlineTextAsAttachments?: boolean
    /** Function for dynamically selecting a verification key from a given key ID */
    getVerificationKey?(keyIds: KeyID[]): Promise<PublicKey | undefined> | PublicKey | undefined
    /** Function for dynamically selecting a decryption key from a given key ID */
    getDecryptionKey?(keyIds: KeyID[]): Promise<PrivateKey | undefined> | PrivateKey | undefined
}

export type OpenPGPAttachment = Attachment & {
    /** Signature verification results for this attachment */
    signatures?: VerificationResult[]
    /** OpenPGP public key from a application/pgp-keys attachment */
    key?: PublicKey
};

export type OpenPGPEmail = Email & {
    /** Signature verification results for the entire email */
    signatures?: VerificationResult[],
    attachments: OpenPGPAttachment[]
}

// OpenPGP.js doesn't export VerificationResult directly
export type VerificationResult = DecryptMessageResult["signatures"][0]