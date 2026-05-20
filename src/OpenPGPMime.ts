import PostalMime, { Email, PostalMimeOptions, RawEmail } from "postal-mime";
import { decrypt, DecryptOptions, KeyID, readMessage, Signature, VerifyOptions } from "openpgp";
import { isNodeSigned, mergeEmails, readAttachmentData, safeParseContentType } from "./util.js";

export class OpenPGPMime extends PostalMime {
    #options: OpenPGPMimeOptions;
    #armoredMessage: Uint8Array;
    #armoredMessageLength = 0;
    #signatures: VerificationResult[] = [];

    constructor (options?: OpenPGPMimeOptions) {
        super(options);
        this.#options = options || {};
        this.#armoredMessage = new Uint8Array();
    }

    static async parse (rawEmail: RawEmail, options?: OpenPGPMimeOptions): Promise<OpenPGPEmail> {
        return (new OpenPGPMime(options)).parse(rawEmail);
    }

    async parse (rawEmail: RawEmail): Promise<OpenPGPEmail> {
        const email: OpenPGPEmail = await super.parse(rawEmail);
        email.signatures = this.#signatures;

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
        //         }, this.#options.verifyOptions));
        //         console.log(verification)
        //         email.signatures = (email.signatures || []).concat(verification.signatures);
        //     }
        // }
        return email;
    }

    // async processNodeTree (): Promise<void> {
    //     const walk = async (node: MimeNode) => {
    //         if (isNodeSigned(node, 0)) {
    //         console.log(node.depth)
    //         console.log(node.contentType.parsed.value)
    //         console.log(new TextDecoder().decode(node.content))
    //         }
    //         for (const child of node.childNodes) {
    //             walk(child);
    //         }
            
    //     }

    //     // @ts-expect-error root is not in the type definition
    //     walk(this.root);
    //     // @ts-expect-error processNodeTree is not in the type definition
    //     super.processNodeTree();
    // }

    async processLine (line: Uint8Array, isFinal: boolean): Promise<void> {
        // @ts-expect-error currentNode is not in the type definition
        const currentNode: MimeNode = this.currentNode;

        if (line.length >= 25 && line[1] === 0x2d && line[line.length - 1] === 0x2d) {
            const lineText = new TextDecoder().decode((line[0] === 0x0a || line[0] === 0x0d) ? line.slice(1) : line);
            
            if (lineText === "-----BEGIN PGP MESSAGE-----") {
                this.#armoredMessage = line;
                this.#armoredMessageLength = line.length;
                return;
            } else if (lineText === "-----END PGP MESSAGE-----") {
                this.#appendArmoredMessage(line);

                const messageString = new TextDecoder().decode(this.#armoredMessage).slice(0, this.#armoredMessageLength);

                this.#armoredMessage = new Uint8Array();
                this.#armoredMessageLength = 0;
                
                var lines: string[];
                if (this.#options.testNoDecrypt) {
                    lines = messageString.split("\n");
                } else {
                    const message = await readMessage({ armoredMessage: messageString });
                    const decrypted = await decrypt(Object.assign({
                        message: message
                    }, this.#options.decryptOptions));
                    lines = decrypted.data.split("\n");
                    this.#signatures = this.#signatures.concat(decrypted.signatures);
                }

                if (currentNode.options?.parentMultipartType === "encrypted") {
                    currentNode.state = "header";
                    currentNode.headerLines.length = 0;
                    currentNode.headerSize = 0;
                    currentNode.headers.length = 0;
                    currentNode.rawHeaderLines.length = 0;
                    currentNode.contentType = {
                        value: "text/plain",
                        default: true
                    }
                }

                for (var i = 0; i < lines.length; i++) {
                    await this.processLine(new TextEncoder().encode(lines[i]), i === lines.length - 1 && isFinal);
                }
                return;
            }
        }

        if (this.#armoredMessageLength > 0) {
            this.#appendArmoredMessage(line);
        } else {
            // @ts-expect-error processLine is not in the type definition
            return super.processLine(line, isFinal);
        }
    }

    #appendArmoredMessage (line: Uint8Array) {
        while (this.#armoredMessageLength + line.length + 1 > this.#armoredMessage.length) {
            const newArmoredMessage = new Uint8Array(this.#armoredMessage.length * 2);
            newArmoredMessage.set(this.#armoredMessage);
            this.#armoredMessage = newArmoredMessage;
        }

        this.#armoredMessage.set([0x0a], this.#armoredMessageLength);
        this.#armoredMessage.set(line, this.#armoredMessageLength + 1);
        this.#armoredMessageLength += line.length + 1;
    }
}

export type OpenPGPMimeOptions = PostalMimeOptions & {
    decryptOptions?: Omit<DecryptOptions, "message">
    verifyOptions?: Omit<Omit<VerifyOptions, "signature">, "message">
    testNoDecrypt?: boolean
}

export type OpenPGPEmail = Email & {
    signatures?: VerificationResult[]
}

export type MimeNode = {
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
    }
}

// taken from OpenPGP.js type definitions, is not exported from there
export interface VerificationResult {
    keyID: KeyID,
    verified: Promise<true>,
    signature: Promise<Signature>
}