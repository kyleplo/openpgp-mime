import { PostalMime } from "./PostalMime.js"
import { Attachment, Email, PostalMimeOptions, RawEmail } from "postal-mime";
import { config, createMessage, DecryptMessageResult, DecryptOptions, encrypt, EncryptOptions, enums, KeyID, PrivateKey, PublicKey, sign, SignOptions, VerifyOptions } from "openpgp";
import "./mimeNodeMixin.js"
import { MimeNode } from "./mimeNodeMixin.js";
import { normalizeRawEmail } from "./util.js";

declare module "./PostalMime.js" {
    interface PostalMime {
        currentNode: MimeNode
        processLine (line: Uint8Array, final: boolean): Promise<void>
        isInlineTextNode (node: MimeNode): boolean
        resolveStream (stream: ReadableStream): Promise<Uint8Array>
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

        if (this.options.encryptOptions && !this.options.signOptions) {
            this.options.signOptions = {
                signingKeys: this.options.encryptOptions.signingKeys as PrivateKey | PrivateKey[],
                signingKeyIDs: this.options.encryptOptions.signingKeyIDs,
                date: this.options.encryptOptions.date,
                signingUserIDs: this.options.encryptOptions.signingUserIDs,
                signatureNotations: this.options.encryptOptions.signatureNotations,
                config: this.options.encryptOptions.config
            };
        } else if (this.options.signOptions && !this.options.encryptOptions) {
            this.options.encryptOptions = {
                signingKeys: this.options.signOptions.signingKeys,
                date: this.options.signOptions.date,
                signingKeyIDs: this.options.signOptions.signingKeyIDs,
                signingUserIDs: this.options.signOptions.signingUserIDs,
                config: this.options.signOptions.config
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

    static async apply (rawEmail: RawEmail, options?: OpenPGPMimeOptions): Promise<string> {
        return (new OpenPGPMime(options)).apply(rawEmail);
    }

    async apply (rawEmail: RawEmail): Promise<string> {
        const rawEmailBuffer = await normalizeRawEmail(rawEmail);
        const decodedRawEmail = typeof rawEmail === "string" ? rawEmail : new TextDecoder().decode(rawEmailBuffer)
        const email: Email = await this.parse(rawEmailBuffer);
        const mimeBoundary = crypto.randomUUID();
        const headerLines = email.headerLines.filter(line => !line.key.startsWith("content-") && !line.key.startsWith("arc-")).map(line => line.line).join("\n");

        if (this.options.encryptOptions?.encryptionKeys || this.options.encryptOptions?.encryptionKeyIDs || this.options.encryptOptions?.encryptionUserIDs) {
            const encryptedMessage = await encrypt(Object.assign({
                message: await createMessage({
                    text: decodedRawEmail
                })
            }, this.options.encryptOptions))
            return `${headerLines}
Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=${mimeBoundary}

--${mimeBoundary}
Content-Type: application/pgp-encrypted

Version: 1

--${mimeBoundary}
Content-Type: application/octet-stream

${encryptedMessage}`
        } else {
            const signature = await sign(Object.assign({
                message: await createMessage({
                    text: decodedRawEmail
                }),
                detached: true
            }, this.options.signOptions));
            const hashAlg: [string, unknown] = Object.entries(enums.hash).find(entry => entry[1] === config.preferredHashAlgorithm) || ["sha256", 8]

            return `${headerLines}
Content-Type: multipart/signed; micalg=pgp-${hashAlg[0]};
  protocol="application/pgp-signature"; boundary=${mimeBoundary}

--${mimeBoundary}
${decodedRawEmail}
--${mimeBoundary}
Content-Type: application/pgp-signature

${signature}`
        }
    }
}

export type OpenPGPMimeOptions = PostalMimeOptions & {
    /** Decrypt options to be passed to OpenPGP.js */
    decryptOptions?: Omit<DecryptOptions, "message">
    /** Verify options to be passed to OpenPGP.js */
    verifyOptions?: Omit<Omit<VerifyOptions, "signature">, "message">
    /** Encrypt options to be passed to OpenPGP.js */
    encryptOptions?: Omit<Omit<Omit<EncryptOptions, "signature">, "format">, "message">
    /** Sign options to be passed to OpenPGP.js */
    signOptions?: Omit<Omit<Omit<SignOptions, "detached">, "format">, "message">
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