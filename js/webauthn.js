// webauthn.js — passkey + PRF biometric unlock.
//
// The WebAuthn PRF extension turns a passkey (Touch ID / Face ID / Windows Hello)
// into a stable secret we can run through HKDF to wrap the hidden vault key. PRF
// is not everywhere (Chrome 116+, Safari 18+), so callers must feature-detect by
// checking the result of registerPasskey().enabled and fall back to a passcode.

const PRF_EVAL = new TextEncoder().encode('filewall/prf/v1'); // fixed eval input

function b64urlEncode(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function webauthnAvailable() {
  return typeof PublicKeyCredential !== 'undefined' &&
    !!navigator.credentials?.create;
}

// Create a passkey with the PRF extension requested. Returns the credential id
// (to store) and whether PRF is actually supported by this authenticator.
export async function registerPasskey() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: 'FileWall', id: location.hostname },
      user: { id: userId, name: 'filewall-vault', displayName: 'FileWall Vault' },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      timeout: 60000,
      // Ask to EVALUATE the PRF at creation, not just enable it. Some
      // authenticators return a usable secret straight away; others only report
      // it on a later assertion. Evaluating here lets the caller test for a real
      // secret instead of trusting the (often absent) `enabled` flag alone.
      extensions: { prf: { eval: { first: PRF_EVAL } } },
    },
  });
  const ext = cred.getClientExtensionResults();
  const enabled = !!(ext.prf && ext.prf.enabled);
  const first = ext.prf?.results?.first;
  const secret = first ? new Uint8Array(first) : null;
  return { credentialId: b64urlEncode(cred.rawId), enabled, secret };
}

// Get the PRF secret for an existing credential. Returns a Uint8Array (32 bytes)
// or null if PRF results are unavailable.
export async function getPrfSecret(credentialId) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: credentialId
        ? [{ type: 'public-key', id: b64urlDecode(credentialId) }]
        : [],
      userVerification: 'required',
      timeout: 60000,
      extensions: { prf: { eval: { first: PRF_EVAL } } },
    },
  });
  const ext = assertion.getClientExtensionResults();
  const first = ext.prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}
