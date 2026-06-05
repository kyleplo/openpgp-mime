import { generateKey, Key, PrivateKey, readKey, readPrivateKey, UserID } from "openpgp";

async function generateKeyPair (user: UserID): Promise<[string, Key, PrivateKey]> {
    const { publicKey, privateKey } = await generateKey({
        userIDs: [user],
    });
    return [
        publicKey,
        await readKey({
            armoredKey: publicKey
        }),
        await readPrivateKey({
            armoredKey: privateKey
        })
    ]
}

export const [ senderPublicKeyArmored, senderPublicKey, senderPrivateKey ] = await generateKeyPair({
    name: "Sender",
    email: "sender@example.com"
});

export const [ receiverPublicKeyArmored, receiverPublicKey, receiverPrivateKey ] = await generateKeyPair({
    name: "Receiver",
    email: "receiver@example.com"
});

export const [ receiver2PublicKeyArmored, receiver2PublicKey, receiver2PrivateKey ] = await generateKeyPair({
    name: "Receiver 2",
    email: "receiver2@example.com"
});