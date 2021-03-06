function NoSuchKeyPair(message) {
  this.name = 'NoSuchKeyPair';
  this.message = message;
  this.stack = (new Error()).stack;
}

NoSuchKeyPair.prototype = Object.create(Error.prototype);
NoSuchKeyPair.prototype.constructor = NoSuchKeyPair;

function callIndexedDB(op_callback) {
    // original function brought from:
    // https://gist.github.com/BigstickCarpet/a0d6389a5d0e3a24814b

    return new Promise(function (resolve, reject) {
        var indexedDB = window.indexedDB || window.mozIndexedDB
            || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;

        var open = indexedDB.open("SignatureLoginPoC", 1);

        open.onupgradeneeded = function () {
            var db = open.result;
            var store = db.createObjectStore("keystore", {keyPath: "id"});
        };

        open.onsuccess = function () {
            var db = open.result;
            var tx = db.transaction("keystore", "readwrite");
            var store = tx.objectStore("keystore");

            op_callback(store).then(function (data) {
                db.close();
                resolve(data);
            }, function (err) {
                reject(err);
            })
        };
    });
}

function base64ToBinary(base64) {
    // original function brought from:
    // https://stackoverflow.com/a/12094943

    var raw = window.atob(base64);
    var rawLength = raw.length;
    var array = new Uint8Array(new ArrayBuffer(rawLength));

    for (i = 0; i < rawLength; i++) {
        array[i] = raw.charCodeAt(i);
    }

    return array;
}

function binaryToBase64(arrayBuffer) {
    // original function brought from:
    // https://stackoverflow.com/a/11562550

    return btoa([].reduce.call(new Uint8Array(arrayBuffer), function(p, c) {return p+String.fromCharCode(c)}, ''));
}

function arrayToString(buffer) {
    // original function brought from:
    // https://stackoverflow.com/a/40327542

    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return binary;
}

function formatAsPem(str) {
    // original function brought from:
    // https://stackoverflow.com/a/40327542

    var finalString = '-----BEGIN PUBLIC KEY-----\n';

    while (str.length > 0) {
        finalString += str.substring(0, 64) + '\n';
        str = str.substring(64);
    }

    finalString = finalString + "-----END PUBLIC KEY-----";

    return finalString;
}

function spkiToPEM(keydata) {
    // original function brought from:
    // https://stackoverflow.com/a/40327542

    var keydataS = arrayToString(keydata);
    var keydataB64 = window.btoa(keydataS);
    return formatAsPem(keydataB64);
}

function makeKeys() {
    var options = {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"}
    };

    var usages = ["sign", "verify"];

    return window.crypto.subtle.generateKey(options, false, usages);
}

function signData(data, privateKey) {
    var options = {
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"}
    };

    return window.crypto.subtle.sign(options, privateKey, data);
}

function verifySignature(data, keys, signature) {
    var options = {
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"}
    };

    return window.crypto.subtle.verify(options, keys.publicKey, signature, data);
}

function exportKey(format, publicKey) {
    return window.crypto.subtle.exportKey(format, publicKey);
}
