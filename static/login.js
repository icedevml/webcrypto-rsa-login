var login_form = document.getElementById('login_form');

if (login_form) {
    var challenge = document.getElementById('challenge').value;

    performLogin('poc_login', challenge).then(function (res) {
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
