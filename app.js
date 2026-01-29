// app.js — Stepper-driven Card Encrypt/Decrypt demo (RSA-OAEP, Web Crypto)
// Enhanced debug output and keypair self-test on generation.

const demoPublicPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwgq0u+/QX2jLq3m5XK3L
DQ3Zl+b1oF5bXKbZ0pLQxg0Nq3G6qWc0rKxqCqQ2R3gFdcx6m3u+3y/8qkqWgjV3
p1g3y3k6XoQNb3Wq7aQ6dTLg5h2gB9pW5vVh13l9o6w0YWx2zq7sP3dF9ZbJjH8D
7xD2v4M3v1Hn8V3x7zF3kV7i1mGH2b6u6J2+Qd2cQ5c3xK0hFq3w7pV5l2e4fY5Z
mQIDAQAB
-----END PUBLIC KEY-----`;

// DOM elements
const stepsList = document.getElementById('stepsList');
const stepPanels = document.querySelectorAll('.step-panel');
const stepItems = document.querySelectorAll('.step');

const publicKeyEl = document.getElementById('publicKey');
const privateKeyEl = document.getElementById('privateKey');
const generateKeysBtn = document.getElementById('generateKeysBtn');
const step1Next = document.getElementById('step1Next');
const step1Status = document.getElementById('step1Status');

const cardInput = document.getElementById('cardInput');
const generateCardBtn = document.getElementById('generateCardBtn');
const step2Next = document.getElementById('step2Next');
const step2Back = document.getElementById('step2Back');
const step2Status = document.getElementById('step2Status');

const encryptBtn = document.getElementById('encryptBtn');
const encryptedOutput = document.getElementById('encryptedOutput');
const step3Next = document.getElementById('step3Next');
const step3Back = document.getElementById('step3Back');
const step3Status = document.getElementById('step3Status');

const decryptBtn = document.getElementById('decryptBtn');
const output = document.getElementById('output');
const step4Back = document.getElementById('step4Back');
const step4Status = document.getElementById('step4Status');

let currentStep = 1;
let lastEncryptedBase64 = '';

// Prefill demo public key for convenience
publicKeyEl.value = demoPublicPEM;

// Utility helpers
function show(panelIndex) {
  stepPanels.forEach(p => {
    p.classList.toggle('hidden', Number(p.dataset.panel) !== panelIndex);
  });
  stepItems.forEach(item => {
    const s = Number(item.dataset.step);
    item.classList.toggle('active', s === panelIndex);
  });
  currentStep = panelIndex;
  updateStepControls();
}

function markCompleted(stepIndex, completed) {
  const el = document.querySelector(`.step[data-step="${stepIndex}"]`);
  el.classList.toggle('completed', completed);
}

function updateStepControls() {
  const pub = publicKeyEl.value.trim();
  const priv = privateKeyEl.value.trim();
  step1Next.disabled = !pub;
  step1Status.textContent = pub ? (priv ? 'Public and private keys present.' : 'Public key present. Private key optional now (required for decrypt step).') : 'Paste or generate a public key to proceed.';

  try {
    validateCardNumber(cardInput.value || '');
    step2Next.disabled = false;
    step2Status.textContent = 'Card is valid.';
  } catch (e) {
    step2Next.disabled = true;
    step2Status.textContent = 'Enter or generate a valid 16-digit card to proceed.';
  }

  step3Next.disabled = !lastEncryptedBase64;
  step3Status.textContent = lastEncryptedBase64 ? 'Ciphertext present.' : 'Encrypt to produce ciphertext before moving on.';

  step4Status.textContent = privateKeyEl.value.trim() ? 'Private key available.' : 'Paste or generate private key to decrypt.';
}

// PEM and Web Crypto helpers
function chunkString(str, size = 64) {
  const chunks = [];
  for (let i = 0; i < str.length; i += size) chunks.push(str.slice(i, i + size));
  return chunks.join('\n');
}
function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}
function base64ToArrayBuffer(base64) {
  const b = base64.replace(/\s+/g, '');
  const binary = atob(b);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function arrayBufferToPem(buffer, label) {
  const b64 = arrayBufferToBase64(buffer);
  return `-----BEGIN ${label}-----\n${chunkString(b64, 64)}\n-----END ${label}-----`;
}
function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----(BEGIN|END)[\w\s\/-]+-----/g, '').replace(/\s+/g, '');
  if (!b64) throw new Error('Invalid PEM content.');
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function generateKeyPairAndFill() {
  step1Status.textContent = 'Generating RSA-2048 key pair...';
  try {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );
    const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const pubPem = arrayBufferToPem(spki, 'PUBLIC KEY');
    const privPem = arrayBufferToPem(pkcs8, 'PRIVATE KEY');

    // Fill fields
    publicKeyEl.value = pubPem;
    privateKeyEl.value = privPem;

    // Self-test: encrypt and decrypt a short test string with generated keys
    step1Status.textContent = 'Running self-test of the generated key pair...';
    try {
      // Import functions expect PEM
      const testPlain = 'webcrypto-self-test';
      const pubImported = await importPublicKey(pubPem);
      const privImported = await importPrivateKey(privPem);
      const enc = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubImported, new TextEncoder().encode(testPlain));
      const decBuf = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privImported, enc);
      const dec = new TextDecoder().decode(decBuf);
      if (dec !== testPlain) throw new Error('Self-test decryption mismatch.');
      step1Status.textContent = 'Generated key pair (self-test OK) and filled PEM fields.';
      markCompleted(1, true);
    } catch (stErr) {
      step1Status.textContent = 'Key pair generated, but self-test failed: ' + (stErr.message || stErr);
    }

    updateStepControls();
  } catch (err) {
    step1Status.textContent = 'Error generating key pair: ' + (err.message || err);
  }
}

function validateCardNumber(value) {
  const digitsOnly = (value || '').replace(/\s+/g, '');
  if (!/^\d{16,19}$/.test(digitsOnly)) throw new Error('Card number must be 16 to 19 digits (digits only).');
  return digitsOnly;
}

function generateRandomCard16() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  let digits = '';
  for (let i = 0; i < 16; i++) digits += String(arr[i] % 10);
  if (digits[0] === '0') digits = '4' + digits.slice(1);
  return digits;
}

async function importPublicKey(pem) {
  try {
    const buf = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey('spki', buf, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  } catch (e) {
    throw new Error('Failed to import public key: ' + (e.message || e));
  }
}
async function importPrivateKey(pem) {
  try {
    const buf = pemToArrayBuffer(pem);
    return await crypto.subtle.importKey('pkcs8', buf, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
  } catch (e) {
    throw new Error('Failed to import private key: ' + (e.message || e));
  }
}

async function encryptWithPublicKey(plainText, publicPem) {
  const pubKey = await importPublicKey(publicPem);
  const encoded = new TextEncoder().encode(plainText);
  const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, encoded);
  return arrayBufferToBase64(encrypted);
}

async function decryptWithPrivateKey(base64Cipher, privatePem) {
  const privKey = await importPrivateKey(privatePem);
  const cipherBuf = base64ToArrayBuffer(base64Cipher);
  const decrypted = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, cipherBuf);
  return new TextDecoder().decode(decrypted);
}

// Event wiring

// Step navigation
document.getElementById('step1Next').addEventListener('click', () => {
  markCompleted(1, true);
  show(2);
});
step2Back.addEventListener('click', () => show(1));
document.getElementById('step3Back').addEventListener('click', () => show(2));
document.getElementById('step4Back').addEventListener('click', () => show(3));
document.getElementById('step2Next').addEventListener('click', () => { markCompleted(2, true); show(3); });
document.getElementById('step3Next').addEventListener('click', () => { markCompleted(3, true); show(4); });

// Step 1 actions
generateKeysBtn.addEventListener('click', async () => {
  await generateKeyPairAndFill();
  updateStepControls();
});

// Update step controls when keys change
publicKeyEl.addEventListener('input', updateStepControls);
privateKeyEl.addEventListener('input', updateStepControls);

// Step 2 actions
generateCardBtn.addEventListener('click', () => {
  const card = generateRandomCard16();
  cardInput.value = card;
  step2Status.textContent = 'Generated 16-digit card.';
  updateStepControls();
});
cardInput.addEventListener('input', () => {
  try {
    validateCardNumber(cardInput.value);
    step2Status.textContent = 'Card looks valid.';
  } catch (e) {
    step2Status.textContent = 'Enter or generate a valid 16-digit card.';
  }
  updateStepControls();
});

// Step 3 actions (encrypt)
encryptBtn.addEventListener('click', async () => {
  step3Status.textContent = '';
  encryptedOutput.textContent = '';
  output.textContent = '';
  try {
    const card = validateCardNumber(cardInput.value);
    const pubPem = publicKeyEl.value.trim();
    if (!pubPem) throw new Error('Public key PEM required to encrypt (generate or paste).');
    step3Status.textContent = 'Encrypting...';
    const cipherB64 = await encryptWithPublicKey(card, pubPem);
    lastEncryptedBase64 = cipherB64;
    encryptedOutput.textContent = cipherB64;
    step3Status.textContent = 'Encryption successful.';
    updateStepControls();
    markCompleted(3, true);
  } catch (err) {
    step3Status.textContent = 'Error: ' + (err.message || err);
    updateStepControls();
  }
});

// Step 4 actions (decrypt) with enhanced error output
decryptBtn.addEventListener('click', async () => {
  step4Status.textContent = '';
  output.textContent = '';
  try {
    let base64 = cardInput.value.trim();
    if (!base64) base64 = lastEncryptedBase64;
    if (!base64) throw new Error('No ciphertext present. Either paste Base64 in the Card field or encrypt first.');
    if (!/^[A-Za-z0-9+/=\s]+$/.test(base64)) throw new Error('Ciphertext appears to be not base64. Paste valid base64.');
    const privPem = privateKeyEl.value.trim();
    if (!privPem) throw new Error('Private key PEM required to decrypt (generate or paste).');

    // Show some debug info before attempting the decrypt
    const rawBuf = base64ToArrayBuffer(base64.replace(/\s+/g, ''));
    step4Status.textContent = `Decrypting... (cipher bytes: ${rawBuf.byteLength})`;

    const plain = await decryptWithPrivateKey(base64.replace(/\s+/g, ''), privPem);
    output.textContent = plain;
    step4Status.textContent = 'Decryption successful.';
    markCompleted(4, true);
  } catch (err) {
    // Display helpful debug output to the UI
    const name = err && err.name ? err.name : '';
    const message = err && err.message ? err.message : String(err);
    let debug = `Error: ${message}\n${name ? 'Error name: ' + name + '\n' : ''}`;
    if (err && err.stack) debug += `Stack: ${err.stack}\n`;
    try {
      // If we have lastEncryptedBase64, show lengths to help debugging
      if (lastEncryptedBase64) {
        const buf = base64ToArrayBuffer(lastEncryptedBase64);
        debug += `Last encrypted (base64) length: ${lastEncryptedBase64.length}\nLast encrypted raw bytes: ${buf.byteLength}\n`;
      }
      // Also if cardInput contains base64 show its length
      if (cardInput.value && /^[A-Za-z0-9+/=\s]+$/.test(cardInput.value)) {
        const buf2 = base64ToArrayBuffer(cardInput.value);
        debug += `Card field (base64) raw bytes: ${buf2.byteLength}\n`;
      }
    } catch (inner) {
      debug += `(Could not compute ciphertext lengths: ${inner.message || inner})\n`;
    }
    step4Status.textContent = 'Decryption failed. See details below.';
    output.textContent = debug;
  }
});

// Initialize UI
show(1);
updateStepControls();