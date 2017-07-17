function callDB(op_callback, after_callback) {
    // This works on all devices/browsers, and uses IndexedDBShim as a final fallback
    var indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;

    // Open (or create) the database
    var open = indexedDB.open("SignatureLoginPoC", 1);

    // Create the schema
    open.onupgradeneeded = function () {
        var db = open.result;
        var store = db.createObjectStore("keystore", {keyPath: "id"});
    };

    open.onsuccess = function () {
        // Start a new transaction
        var db = open.result;
        var tx = db.transaction("keystore", "readwrite");
        var store = tx.objectStore("keystore");

        op_callback(store);

        tx.oncomplete = function () {
            db.close();
            after_callback();
        };
    };
}

function arrayToHex(arr) {
    return new Uint8Array(arr).reduce(function (memo, i) {
        return memo + ('0' + i.toString(16)).slice(-2); //padd with leading 0 if <16
    }, '');
}

function base64ToBinary(base64) {
    var raw = window.atob(base64);
    var rawLength = raw.length;
    var array = new Uint8Array(new ArrayBuffer(rawLength));

    for (i = 0; i < rawLength; i++) {
        array[i] = raw.charCodeAt(i);
    }

    return array;
}

function spkiToPEM(keydata) {
    var keydataS = arrayBufferToString(keydata);
    var keydataB64 = window.btoa(keydataS);
    return formatAsPem(keydataB64);
}

function arrayBufferToString(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return binary;
}


function formatAsPem(str) {
    var finalString = '-----BEGIN PUBLIC KEY-----\n';

    while (str.length > 0) {
        finalString += str.substring(0, 64) + '\n';
        str = str.substring(64);
    }

    finalString = finalString + "-----END PUBLIC KEY-----";

    return finalString;
}

function makeData() {
    //return window.crypto.getRandomValues(new Uint8Array(16));
    return new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]);
}

function makeKeys() {
    var options = {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048, //can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {name: "SHA-256"} //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
    };

    var usages = ["sign", "verify"];

    // this is insane and the standard trick with window.crypto || window.msCrypto won't work in this case
    if (window.crypto && window.crypto.subtle) {
        return window.crypto.subtle.generateKey(options, false, usages);
    } else if (window.crypto && window.crypto.webkitSubtle) {
        return window.crypto.webkitSubtle.generateKey(options, false, usages);
    } else {
        throw new Error('No suitable "generateKey" implementation was found.');
    }
}

function signData(data, privateKey) {
    var options = {
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"}
    };

    if (window.crypto && window.crypto.subtle) {
        return window.crypto.subtle.sign(options, privateKey, data);
    } else if (window.crypto && window.crypto.webkitSubtle) {
        return window.crypto.webkitSubtle.sign(options, privateKey, data);
    } else {
        throw new Error('No suitable "sign" implementation was found.');
    }
}

function verifySignature(data, keys, signature) {
    var options = {
        name: "RSASSA-PKCS1-v1_5",
        hash: {name: "SHA-256"}
    };

    if (window.crypto && window.crypto.subtle) {
        return window.crypto.subtle.verify(options, keys.publicKey, signature, data);
    } else if (window.crypto && window.crypto.webkitSubtle) {
        return window.crypto.webkitSubtle.verify(options, keys.publicKey, signature, data);
    } else {
        throw new Error('No suitable "verify" implementation was found.');
    }
}

function exportKey(format, publicKey) {
    if (window.crypto && window.crypto.subtle) {
        return window.crypto.subtle.exportKey(format, publicKey);
    } else if (window.crypto && window.crypto.webkitSubtle) {
        return window.crypto.webkitSubtle.exportKey(format, publicKey);
    } else {
        throw new Error('No suitable "verify" implementation was found.');
    }
}
