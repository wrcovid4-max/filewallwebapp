// firebase-config.js — connection values for the SAME Firebase project the
// Android/iOS/watchOS/Wear OS apps use (see ../filewallAS/FIREBASE_BLUEPRINT.md
// principle #1: one project, one uid, across every platform).
//
// While `apiKey` is blank, sync.js never initialises Firebase and the app
// behaves exactly as it always has — no server, no account, fully local.
// This mirrors filewallAS's res/values/firebase.xml on purpose: fill in the
// same project's values here as you put there.
//
// Firebase console -> Project settings -> General -> Your apps -> Web app
// (add one if there isn't one yet; it's free and instant, no server involved):
export const firebaseConfig = {
  apiKey: '',
  authDomain: '',       // e.g. filewall-xxxxx.firebaseapp.com
  projectId: '',        // e.g. filewall-xxxxx — must match the Android app's firebase_project_id
  storageBucket: '',    // e.g. filewall-xxxxx.appspot.com
  appId: '',            // the Web app's App ID (different from the Android App ID — that's expected)
};

// Authentication -> Sign-in method -> Google -> "Web SDK configuration" ->
// Web client ID. This is usually the SAME value as Android's firebase_web_client_id
// (Firebase auto-creates one shared OAuth Web client for a project) — copy
// the same string into both places.
export const googleWebClientId = '';

export function isConfigured() {
  return Boolean(firebaseConfig.apiKey && firebaseConfig.projectId && firebaseConfig.appId);
}
