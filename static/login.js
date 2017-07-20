function performLogin(challenge) {
    if (typeof challenge === "string") {
        challenge = base64ToBinary(challenge);
    }

    return callIndexedDB(function (store) {
        return new Promise(function (resolve, reject) {
            var getData = store.get("key_pair");
            getData.onsuccess = function () {
                // we've fetched our key pair (which was generated during registration) from IndexedDB
                resolve(getData.result);
            };
            getData.onerror = function (err) {
                reject(err);
            };
        });
    }).then(function (dbResult) {
        if (!dbResult) {
            return Promise.reject('no_key_stored');
        }

        var exportKeyPromise = exportKey('spki', dbResult.publicKey);
        var signDataPromise = signData(challenge, dbResult.privateKey);

        return Promise.all([exportKeyPromise, signDataPromise]);
    }).then(function (vals) {
        var exportedKey = vals[0];
        var rawSignature = vals[1];

        // here we export public key only in order to display it to the user
        var publicKey = spkiToPEM(exportedKey);

        // fill the "signature" form field with the signature of the challenge
        // it will be sent over to the server for verification
        var signature = arrayToHex(rawSignature);

        return {"publicKey": publicKey, "signature": signature};
    });
}

var login_form = document.getElementById('login_form');

if (login_form) {
    var challenge = document.getElementById('challenge').value;

    performLogin(challenge).then(function (res) {
        document.getElementById('public_key').value = res.publicKey;
        document.getElementById('signature').value = res.signature;
    }, function (err) {
        // TODO implement custom error
        if (err == 'no_key_stored') {
            document.getElementById('login_form').innerHTML = 'You don\'t have any key generated yet.';
        }

        console.error(err);
    });
}
