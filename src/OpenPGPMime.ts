import PostalMime, { Email, PostalMimeOptions, RawEmail } from "postal-mime";
import { DecryptOptions, KeyID, Signature, VerifyOptions } from "openpgp";
import "./mimeNodeMixin.js"

export class OpenPGPMime extends PostalMime {
    options: OpenPGPMimeOptions;
    signatures: VerificationResult[] = [];

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
        if (!this.options.keepPgpAttachments) {
            email.attachments = email.attachments.filter(attachment => attachment.mimeType !== "application/pgp-encrypted")
        }
        // // @ts-expect-error
        //printMimeTree(this.root);

        // const contentType = email.headers.find(header => header.key === "content-type")?.value || "";
        // var contentTypeParsed = safeParseContentType(contentType);

        // if (email.attachments.length >= 1 && contentTypeParsed.parameters["protocol"]) {
        //     if (contentTypeParsed.type.toLowerCase() === "multipart/signed" && contentTypeParsed.parameters["protocol"] === "application/pgp-signature") {
        //         const signatureAttachment = email.attachments.find(attachment => safeParseContentType(attachment.mimeType).type === "application/pgp-signature");

        //         if (!signatureAttachment) {
        //             return email;
        //         }

        //         const signature = await readSignature({
        //             armoredSignature: readAttachmentData(signatureAttachment.content, signatureAttachment.encoding)
        //         });

        //         const message = await createMessage({
        //             text: email.html
        //         });
        //         const verification = await verify(Object.assign({
        //             message: message,
        //             signature: signature
        //         }, this.options.verifyOptions));
        //         console.log(verification)
        //         email.signatures = (email.signatures || []).concat(verification.signatures);
        //     }
        // }
        return email;
    }
}

export type OpenPGPMimeOptions = PostalMimeOptions & {
    decryptOptions?: Omit<DecryptOptions, "message">
    verifyOptions?: Omit<Omit<VerifyOptions, "signature">, "message">
    keepPgpAttachments?: boolean
}

export type OpenPGPEmail = Email & {
    signatures?: VerificationResult[]
}

// taken from OpenPGP.js type definitions, is not exported from there
export interface VerificationResult {
    keyID: KeyID,
    verified: Promise<true>,
    signature: Promise<Signature>
}