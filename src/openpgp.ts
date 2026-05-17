import { createMessage, decrypt, decryptKey, encrypt, generateKey, readKey, readMessage, readPrivateKey } from "openpgp";

// create sender's keys
const { privateKey: senderPrivateKeyArmored, publicKey: senderPublicKeyArmored } = await generateKey({
    type: 'ecc',
    userIDs: [{ name: 'Sender', email: 'sender@example.com' }],
    passphrase: 'super long and hard to guess secret',
    format: 'armored'
});
const senderPublicKey = await readKey({
    armoredKey: senderPublicKeyArmored
});
const senderPrivateKey = await decryptKey({
    privateKey: await readPrivateKey({
        armoredKey: senderPrivateKeyArmored
    }),
    passphrase: 'super long and hard to guess secret'
});

// create receiver's keys
const { privateKey: receiverPrivateKeyArmored, publicKey: receiverPublicKeyArmored } = await generateKey({
    type: 'rsa',
    userIDs: [{ name: 'Receiver', email: 'receiver@example.com' }],
    passphrase: 'super long and hard to guess secret',
    format: 'armored'
});
const receiverPublicKey = await readKey({
    armoredKey: receiverPublicKeyArmored
});
const receiverPrivateKey = await decryptKey({
    privateKey: await readPrivateKey({
        armoredKey: receiverPrivateKeyArmored
    }),
    passphrase: 'super long and hard to guess secret'
});

// sign and encrypt message using sender's private key and receiver's public key
const encrypted = await encrypt({
    message: await createMessage({
        text: "hello world"
    }),
    encryptionKeys: receiverPublicKey,
    signingKeys: senderPrivateKey
});

console.log(encrypted);

// decrypt and verify message using receiver's private key and sender's public key
const decrypted = await decrypt({
    message: await readMessage({
        armoredMessage: encrypted
    }),
    decryptionKeys: receiverPrivateKey,
    verificationKeys: senderPublicKey
});
console.log(receiverPrivateKeyArmored)
console.log(receiverPublicKeyArmored)
console.log(decrypted.data);
console.log(await decrypted.signatures[0].verified);