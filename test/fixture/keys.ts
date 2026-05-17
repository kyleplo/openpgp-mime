import { generateKey, readKey, readPrivateKey } from "openpgp";

const { publicKey: senderPublicKeyArmored, privateKey: senderPrivateKeyArmored } = await generateKey({
    userIDs: [
        {
            name: "Sender",
            email: "sender@example.com"
        }
    ],
});
export const senderPublicKey = await readKey({
    armoredKey: senderPublicKeyArmored
});
export const senderPrivateKey = await readPrivateKey({
    armoredKey: senderPrivateKeyArmored
});
const { publicKey: receiverPublicKeyArmored, privateKey: receiverPrivateKeyArmored } = await generateKey({
    userIDs: [
        {
            name: "Receiver",
            email: "receiver@example.com"
        }
    ],
});
export const receiverPublicKey = await readKey({
    armoredKey: receiverPublicKeyArmored
});
export const receiverPrivateKey = await readPrivateKey({
    armoredKey: receiverPrivateKeyArmored
});