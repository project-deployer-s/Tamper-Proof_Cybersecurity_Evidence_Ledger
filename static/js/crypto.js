'use strict';

async function generateKeyPair() {
    return crypto.subtle.generateKey(
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
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const normalized = String(base64).replace(/\s/g, "");
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function downloadPrivateKey(privateKeyBase64) {
    const blob = new Blob([privateKeyBase64], { type: "text/plain" });
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
        { name: "ECDSA", hash: "SHA-256" }, privateKey, data
    );
    return new Uint8Array(signature);
}

async function setupKeys() {
    const keyPair = await generateKeyPair();
    const publicKey = await exportPublicKey(keyPair.publicKey);
    const privateKey = await exportPrivateKey(keyPair.privateKey);
    const publicKeyBase64 = arrayBufferToBase64(publicKey);
    downloadPrivateKey(arrayBufferToBase64(privateKey));
    return { keyPair, publicKeyBase64 };
}

function openKeyDatabase() {
    return new Promise((resolve, reject) => {
        if (!("indexedDB" in window)) {
            reject(new Error("This browser does not support IndexedDB."));
            return;
        }

        const request = indexedDB.open("EvidenceLedgerKeys", 1);

        request.onupgradeneeded = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys", { keyPath: "userId" });
            }
        };

        request.onsuccess = () => {
            const db = request.result;
            db.onversionchange = () => db.close();
            resolve(db);
        };
        request.onerror = () => reject(request.error || new Error("Could not open key storage."));
        request.onblocked = () => reject(new Error("Key storage is blocked by another open tab. Close other project tabs and retry."));
    });
}

function validateSigningKey(key) {
    return !!key &&
        key.type === "private" &&
        key.algorithm?.name === "ECDSA" &&
        key.algorithm?.namedCurve === "P-256" &&
        Array.from(key.usages || []).includes("sign");
}

async function savePrivateKey(userId, privateKey) {
    if (userId === undefined || userId === null || String(userId) === "") {
        throw new Error("Cannot save signing key: account ID is missing.");
    }
    if (!validateSigningKey(privateKey)) {
        throw new Error("Cannot save signing key: the key is not a valid ECDSA P-256 signing key.");
    }

    const db = await openKeyDatabase();
    try {
        return await new Promise((resolve, reject) => {
            let tx;
            try {
                tx = db.transaction("keys", "readwrite");
                const store = tx.objectStore("keys");
                const getRequest = store.get(String(userId));

                getRequest.onsuccess = () => {
                    const previous = getRequest.result;
                    store.put({
                        userId: String(userId),
                        privateKey,
                        createdAt: previous?.createdAt || new Date().toISOString(),
                        updatedAt: new Date().toISOString()
                    });
                };
                getRequest.onerror = () => {
                    try { tx.abort(); } catch (_) {}
                    reject(getRequest.error || new Error("Could not read existing key record."));
                };
                tx.oncomplete = () => resolve(true);
                tx.onerror = () => reject(tx.error || new Error("Key storage transaction failed."));
                tx.onabort = () => reject(tx.error || new Error("Key storage transaction was aborted."));
            } catch (error) {
                reject(error);
            }
        });
    } finally {
        db.close();
    }
}

async function loadPrivateKey(userId) {
    if (userId === undefined || userId === null || String(userId) === "") {
        throw new Error("Cannot load signing key: account ID is missing.");
    }

    const db = await openKeyDatabase();
    try {
        return await new Promise((resolve, reject) => {
            const tx = db.transaction("keys", "readonly");
            const request = tx.objectStore("keys").get(String(userId));
            let record;

            request.onsuccess = () => { record = request.result || null; };
            request.onerror = () => reject(request.error || new Error("Could not read signing key."));

            tx.oncomplete = () => {
                if (!record) {
                    resolve(null);
                } else if (!validateSigningKey(record.privateKey)) {
                    reject(new Error("A signing-key record exists but is not a valid ECDSA P-256 private key."));
                } else {
                    resolve(record.privateKey);
                }
            };
            tx.onerror = () => reject(tx.error || new Error("Key storage read failed."));
            tx.onabort = () => reject(tx.error || new Error("Key storage read was aborted."));
        });
    } finally {
        db.close();
    }
}

async function importPrivateKey(base64) {
    const key = await crypto.subtle.importKey(
        "pkcs8",
        base64ToArrayBuffer(base64),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
    );
    if (!validateSigningKey(key)) {
        throw new Error("The imported file is not a valid ECDSA P-256 private key.");
    }
    return key;
}

async function matchesPublicKey(privateKey, publicKeyBase64) {
    if (!validateSigningKey(privateKey)) {
        throw new Error("The stored private key is not usable for signing.");
    }

    const publicKey = await crypto.subtle.importKey(
        "spki",
        base64ToArrayBuffer(publicKeyBase64),
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
    );

    const challenge = crypto.getRandomValues(new Uint8Array(32));
    const signature = await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" }, privateKey, challenge
    );

    return crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" }, publicKey, signature, challenge
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

// Hybrid backup format: PBKDF2-SHA256 -> AES-256-GCM, entirely in the browser.
const KEY_BACKUP_ITERATIONS = 600000;

async function deriveRecoveryKey(password, salt, iterations = KEY_BACKUP_ITERATIONS) {
    if (typeof password !== 'string' || password.length < 12) {
        throw new Error('Recovery password must contain at least 12 characters.');
    }
    const material = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function createEncryptedKeyBackup(privateKey, password, userId, publicKeyId) {
    if (!validateSigningKey(privateKey)) throw new Error('Cannot back up an invalid signing key.');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = new TextEncoder().encode(`evidence-ledger-key-backup:v1:${userId}:${publicKeyId}`);
    const aesKey = await deriveRecoveryKey(password, salt);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, aesKey, pkcs8
    );
    return {
        public_key_id: Number(publicKeyId),
        ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
        salt: bytesToBase64(salt),
        iv: bytesToBase64(iv),
        kdf: 'PBKDF2-HMAC-SHA256',
        iterations: KEY_BACKUP_ITERATIONS,
        cipher: 'AES-256-GCM',
        format_version: 1
    };
}

async function decryptEncryptedKeyBackup(payload, password, userId) {
    if (!payload || payload.format_version !== 1 || payload.kdf !== 'PBKDF2-HMAC-SHA256' || payload.cipher !== 'AES-256-GCM') {
        throw new Error('Unsupported encrypted backup format.');
    }
    const iterations = Number(payload.iterations);
    if (!Number.isInteger(iterations) || iterations < 600000 || iterations > 2000000) {
        throw new Error('Encrypted backup has invalid security parameters.');
    }
    const salt = new Uint8Array(base64ToArrayBuffer(payload.salt));
    const iv = new Uint8Array(base64ToArrayBuffer(payload.iv));
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);
    if (salt.length !== 16 || iv.length !== 12 || ciphertext.byteLength < 17) {
        throw new Error('Encrypted backup data is malformed.');
    }
    const aad = new TextEncoder().encode(`evidence-ledger-key-backup:v1:${userId}:${payload.public_key_id}`);
    const aesKey = await deriveRecoveryKey(password, salt, iterations);
    let plaintext;
    try {
        plaintext = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, aesKey, ciphertext
        );
    } catch (_) {
        throw new Error('Recovery password is incorrect or the encrypted backup has been modified.');
    }
    const privateKey = await crypto.subtle.importKey(
        'pkcs8', plaintext, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
    );
    if (!validateSigningKey(privateKey)) throw new Error('Recovered data is not a valid signing key.');
    return privateKey;
}

function downloadEncryptedKeyBackup(payload) {
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'evidence-ledger-encrypted-key-backup.json';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

window.createEncryptedKeyBackup = createEncryptedKeyBackup;
window.decryptEncryptedKeyBackup = decryptEncryptedKeyBackup;
window.downloadEncryptedKeyBackup = downloadEncryptedKeyBackup;

async function lockPrivateKeyForLocalStorage(privateKey) {
    if (!validateSigningKey(privateKey)) {
        throw new Error('Invalid signing key.');
    }

    return privateKey;
}
window.lockPrivateKeyForLocalStorage = lockPrivateKeyForLocalStorage;
