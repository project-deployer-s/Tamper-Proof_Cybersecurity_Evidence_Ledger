
async function generateKeyPair() {
    return await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
    );
}

async function exportPublicKey(publicKey) {
    return crypto.subtle.exportKey("spki", publicKey);
}

async function exportPrivateKey(privateKey) {
    return crypto.subtle.exportKey("pkcs8", privateKey);
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64.replace(/\s/g, ""));
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
}

function bytesToBase64(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function downloadPrivateKey(privateKeyBase64) {
    const blob = new Blob([privateKeyBase64], {
        type: "text/plain"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "private-key-backup.txt";

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function signPayload(privateKey, payload) {
    const data = new TextEncoder().encode(payload);

    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        data
    );

    return new Uint8Array(signature);
}

async function setupKeys() {
    const keyPair = await generateKeyPair();

    const publicKey = await exportPublicKey(keyPair.publicKey);
    const privateKey = await exportPrivateKey(keyPair.privateKey);

    const publicKeyBase64 = arrayBufferToBase64(publicKey);
    const privateKeyBase64 = arrayBufferToBase64(privateKey);

    downloadPrivateKey(privateKeyBase64);

    return { keyPair, publicKeyBase64 };
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
            privateKey,
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

        transaction.onabort = () => {
            db.close();
            reject(transaction.error || new Error("Key storage failed."));
        };
    });
}

async function loadPrivateKey(userId) {
    const db = await openKeyDatabase();

    return new Promise((resolve, reject) => {
        const transaction = db.transaction("keys", "readonly");
        const request = transaction.objectStore("keys").get(String(userId));

        request.onsuccess = () => {
            resolve(request.result?.privateKey || null);
        };

        request.onerror = () => reject(request.error);

        transaction.oncomplete = () => db.close();
        transaction.onerror = () => db.close();
    });
}

async function importPrivateKey(base64) {
    return crypto.subtle.importKey(
        "pkcs8",
        base64ToArrayBuffer(base64),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
    );
}

async function matchesPublicKey(privateKey, publicKeyBase64) {
    const publicKey = await crypto.subtle.importKey(
        "spki",
        base64ToArrayBuffer(publicKeyBase64),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
    );

    const challenge = crypto.getRandomValues(new Uint8Array(32));

    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        challenge
    );

    return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        signature,
        challenge
    );
}

window.generateKeyPair = generateKeyPair;
window.exportPublicKey = exportPublicKey;
window.exportPrivateKey = exportPrivateKey;
window.arrayBufferToBase64 = arrayBufferToBase64;
window.bytesToBase64 = bytesToBase64;
window.downloadPrivateKey = downloadPrivateKey;
window.signPayload = signPayload;
window.savePrivateKey = savePrivateKey;
window.loadPrivateKey = loadPrivateKey;
window.setupKeys = setupKeys;
window.importPrivateKey = importPrivateKey;
window.matchesPublicKey = matchesPublicKey;
