makeKeys().then(function (keys) {
    exportKey('spki', keys.publicKey).then(function (exportedKey) {
        document.getElementById('public_key').value = spkiToPEM(exportedKey);

        // prepare a structure similiar to PKAC (Public Key and Challenge)

        // we use a challenge here so the user won't be able to send a public key
        // which belongs to somebody else and thus grant access to the account
        var challenge = base64ToBinary(document.getElementById('challenge').value);
        var pkac = new Uint8Array(exportedKey.byteLength + challenge.byteLength);
        pkac.set(new Uint8Array(exportedKey), 0);
        pkac.set(new Uint8Array(challenge), exportedKey.byteLength);

        // we are not going to sign "user name" field here, if somebody is able to
        // change it on the web application level then he would be also able to generate
        // a proper signature

        // sign data (so we have a signed "PKAC")
        return signData(pkac, keys.privateKey);
    }).then(function (signed) {
        document.getElementById('signature').value = arrayToHex(signed);

        // securely store the new key pair in the IndexedDB
        callIndexedDB(function (store) {
            store.put({id: "key_pair", publicKey: keys.publicKey, privateKey: keys.privateKey});
        });
    });
});