var register_form = document.getElementById('register_form');

if (register_form) {
    var challenge = base64ToBinary(document.getElementById('challenge').value);

    performRegister('poc_login', challenge).then(function (res) {
        document.getElementById('public_key').value = res.publicKey;
        document.getElementById('signature').value = res.signature;
    }, function (err) {
        console.error('Failed to perform register script.', err);
    });
}
