function callDB(op_callback, after_callback) {
    // This works on all devices/browsers, and uses IndexedDBShim as a final fallback
    var indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;

    // Open (or create) the database
    var open = indexedDB.open("MyDatabase", 1);

    // Create the schema
    open.onupgradeneeded = function () {
        var db = open.result;
        var store = db.createObjectStore("MyObjectStore", {keyPath: "id"});
    };

    open.onsuccess = function () {
        // Start a new transaction
        var db = open.result;
        var tx = db.transaction("MyObjectStore", "readwrite");
        var store = tx.objectStore("MyObjectStore");

        op_callback(store);

        tx.oncomplete = function () {
            db.close();
            after_callback();
        };
    };
}

function arrayToHex(arr) {
    return arr.reduce(function (memo, i) {
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
    return window.crypto.subtle.generateKey({
            name: "RSA-PSS",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: {name: "SHA-256"}
        }, false, // exportable
        ["sign", "verify"]);
}

function signData(data, privateKey) {
    return window.crypto.subtle.sign({
        name: "RSA-PSS",
        saltLength: 222, // max salt length
        hash: {name: "SHA-256"}
    }, privateKey, data);
}

function verifySignature(data, keys, signature) {
    return window.crypto.subtle.verify({
        name: "RSA-PSS",
        saltLength: 222, // max salt length
        hash: {name: "SHA-256"}
    }, keys.publicKey, signature, data);
}
