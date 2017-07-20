function performRegister(challenge) {
    if (typeof challenge === "string") {
        challenge = base64ToBinary(challenge);
    }

    return makeKeys().then(function (keys) {
        return Promise.all([keys, exportKey('spki', keys.publicKey)]);
    }).then(function (vals) {
        var keys = vals[0];
        var exportedKey = vals[1];

        var publicKeyPEM = spkiToPEM(exportedKey);

        // prepare a structure similiar to PKAC (Public Key and Challenge)

        // we use a challenge here so the user won't be able to send a public key
        // which belongs to somebody else and thus grant access to the account
        var pkac = new Uint8Array(exportedKey.byteLength + challenge.byteLength);
        pkac.set(new Uint8Array(exportedKey), 0);
        pkac.set(new Uint8Array(challenge), exportedKey.byteLength);

        // we are not going to sign "user name" field here, if somebody is able to
        // change it on the web application level then he would be also able to generate
        // a proper signature

        // sign data (so we have a signed "PKAC")
        return Promise.all([keys, publicKeyPEM, signData(pkac, keys.privateKey)]);
    }).then(function (vals) {
        var keys = vals[0];

        // securely store the new key pair in the IndexedDB
        var dbPromise = callIndexedDB(function (store) {
            return new Promise(function (resolve, reject) {
                store.put({id: "key_pair", publicKey: keys.publicKey, privateKey: keys.privateKey});
                resolve();
            });
        });

        vals.push(dbPromise);
        return Promise.all(vals);
    }).then(function (vals) {
        var keys = vals[0];
        var publicKeyPEM = vals[1];
        var signature = arrayToHex(vals[2]);

        return {"publicKey": publicKeyPEM, "signature": signature};
    });
}

var register_form = document.getElementById('register_form');

if (register_form) {
    var challenge = base64ToBinary(document.getElementById('challenge').value);

    performRegister(challenge).then(function (res) {
        document.getElementById('public_key').value = res.publicKey;
        document.getElementById('signature').value = res.signature;
    }, function (err) {
        console.error(err);
    });
}
