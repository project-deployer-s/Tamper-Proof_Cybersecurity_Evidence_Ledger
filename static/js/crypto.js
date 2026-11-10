async function generateKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign", "verify"]
    );
}

async function testKeyGeneration() {
    const keyPair = await generateKeyPair();

    console.log("Private key:", keyPair.privateKey);
    console.log("Public key:", keyPair.publicKey);

    return keyPair;
}

async function exportPublicKey(publicKey) {
    return await crypto.subtle.exportKey(
        "spki",
        publicKey
    );
}


async function exportPrivateKey(privateKey) {
    return await crypto.subtle.exportKey(
        "pkcs8",
        privateKey
    );
}


function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}


function downloadPrivateKey(privateKeyBase64) {
    const blob = new Blob(
        [privateKeyBase64],
        { type: "text/plain" }
    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = "private-key-backup.txt";

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
}

async function setupKeys() {
    const keyPair = await generateKeyPair();

    const publicKey = await exportPublicKey(
        keyPair.publicKey
    );

    const privateKey = await exportPrivateKey(
        keyPair.privateKey
    );

    const publicKeyBase64 =
        arrayBufferToBase64(publicKey);

    const privateKeyBase64 =
        arrayBufferToBase64(privateKey);

    console.log("Public key:", publicKeyBase64);

    downloadPrivateKey(privateKeyBase64);

    return {
        keyPair,
        publicKeyBase64
    };
}

async function signPayload(privateKey, payload) {
    const encoder = new TextEncoder();
    const data = encoder.encode(payload);

    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256"
        },
        privateKey,
        data
    );

    return new Uint8Array(signature);
}

function bytesToBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

async function testSigning() {
    const keyPair = await generateKeyPair();

    const payload = JSON.stringify({
        sender: "Alice",
        receiver: "Bob",
        timestamp: "2026-10-06T12:00:00Z",
        nonce: "abc123",
        message: "Hello Bob"
    });

    const signature = await signPayload(
        keyPair.privateKey,
        payload
    );

    const signatureBase64 = bytesToBase64(signature);

    console.log("Canonical payload:", payload);
    console.log("Signature length:", signature.length);
    console.log("Signature Base64:", signatureBase64);

    return {
        keyPair,
        payload,
        signature,
        signatureBase64
    };
}

async function getCryptoTestData() {
    const keyPair = await generateKeyPair();

    const payload = JSON.stringify({
        sender: "Alice",
        receiver: "Bob",
        timestamp: "2026-10-06T12:00:00Z",
        nonce: "abc123",
        message: "Hello Bob"
    });

    const publicKey = await exportPublicKey(keyPair.publicKey);

    const signature = await signPayload(
        keyPair.privateKey,
        payload
    );

    return {
        payload: payload,
        publicKeyBase64: arrayBufferToBase64(publicKey),
        signatureBase64: bytesToBase64(signature)
    };
}


function openKeyDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open("EvidenceLedgerKeys", 1);

        request.onupgradeneeded = () => {
            const db = request.result;

            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys", { keyPath: "userId" });
            }
        };

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function savePrivateKey(userId, privateKey) {
    const db = await openKeyDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction("keys", "readwrite");

        transaction.objectStore("keys").put({
            userId: String(userId),
            privateKey: privateKey,
            createdAt: new Date().toISOString()
        });

        transaction.oncomplete = () => {
            db.close();
            resolve(true);
        };

        transaction.onerror = () => {
            db.close();
            reject(transaction.error);
        };
    });
}

async function loadPrivateKey(userId) {
    const db = await openKeyDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction("keys", "readonly");
        const request = transaction.objectStore("keys").get(String(userId));

        request.onsuccess = () => {
            db.close();
            resolve(request.result?.privateKey || null);
        };

        request.onerror = () => {
            db.close();
            reject(request.error);
        };
    });
}

// Make crypto functions available to other scripts.
window.generateKeyPair = generateKeyPair;
window.exportPublicKey = exportPublicKey;
window.exportPrivateKey = exportPrivateKey;
window.arrayBufferToBase64 = arrayBufferToBase64;
window.downloadPrivateKey = downloadPrivateKey;
window.signPayload = signPayload;
window.bytesToBase64 = bytesToBase64;
window.savePrivateKey = savePrivateKey;
window.loadPrivateKey = loadPrivateKey;
window.setupKeys = setupKeys;