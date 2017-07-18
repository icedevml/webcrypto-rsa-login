var login_form = document.getElementById('login_form');

if (login_form) {
    callIndexedDB(function (store) {
        var getData = store.get("key_pair");
        getData.onsuccess = function () {
            if (!getData.result) {
                document.getElementById('form').innerHTML = 'You don\'t have any key generated yet.';
                return;
            }

            // we've fetched our key pair (which was generated during registration) from IndexedDB
            var publicKey = getData.result.publicKey;
            var privateKey = getData.result.privateKey;
            var challenge = base64ToBinary(document.getElementById('challenge').value);

            exportKey('spki', publicKey).then(function (exportedKey) {
                // here we export public key only in order to display it to the user
                document.getElementById('public_key').value = spkiToPEM(exportedKey);
                return signData(challenge, privateKey);
            }).then(function (signed) {
                // fill the "signature" form field with the signature of the challenge
                // it will be sent over to the server for verification
                document.getElementById('signature').value = arrayToHex(signed);
            });
        };
    });
}
