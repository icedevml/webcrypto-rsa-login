function getAllKeyPairLabels() {
    return callIndexedDB(function (store) {
        return new Promise(function (resolve, reject) {
            var getData = store.getAll();
            getData.onsuccess = function () {
                var ids = Object.keys(getData.result).map(function (k) {
                    return getData.result[k].id;
                });

                resolve(ids);
            };
            getData.onerror = function (err) {
                reject(err);
            };
        });
    });
}

function performLogin(key_label, challenge) {
    if (typeof challenge === "string") {
        challenge = base64ToBinary(challenge);
    }

    return callIndexedDB(function (store) {
        return new Promise(function (resolve, reject) {
            var getData = store.get(key_label);
            getData.onsuccess = function () {
                // we've fetched our key pair (which was generated during registration) from IndexedDB
                if (!getData.result) {
                    reject(new NoSuchKeyPair(key_label));
                }

                resolve(getData.result);
            };
            getData.onerror = function (err) {
                reject(err);
            };
        });
    }).then(function (dbResult) {
        var exportKeyPromise = exportKey('spki', dbResult.publicKey);
        var signDataPromise = signData(challenge, dbResult.privateKey);

        return Promise.all([exportKeyPromise, signDataPromise]);
    }).then(function (vals) {
        var exportedKey = vals[0];
        var rawSignature = vals[1];

        // here we export public key only in order to display it to the user
        // it's not required in the login process, as the server needs to know public key already
        var publicKey = spkiToPEM(exportedKey);

        // fill the "signature" form field with the signature of the challenge
        // it will be sent over to the server for verification
        var signature = binaryToBase64(rawSignature);

        return {"publicKey": publicKey, "signature": signature};
    });
}

function performRegister(key_label, challenge) {
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
                store.put({id: key_label, publicKey: keys.publicKey, privateKey: keys.privateKey});
                resolve();
            });
        });

        vals.push(dbPromise);
        return Promise.all(vals);
    }).then(function (vals) {
        var keys = vals[0];
        var publicKeyPEM = vals[1];
        var signature = binaryToBase64(vals[2]);

        return {"publicKey": publicKeyPEM, "signature": signature};
    });
}
