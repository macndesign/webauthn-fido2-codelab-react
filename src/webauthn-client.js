/*
 * @license
 * Copyright 2019 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
import base64url from "base64url";

export const _fetch = async (path, payload = "") => {
  const headers = {
    "X-Requested-With": "XMLHttpRequest",
  };
  if (payload && !(payload instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(payload);
  }
  const res = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: headers,
    body: payload,
  });
  if (res.status === 200) {
    // Server authentication succeeded
    return res.json();
  } else {
    // Server authentication failed
    const result = await res.json();
    throw result.error;
  }
};

// TODO:
const simpleAuth = async () => {
  await _fetch("/auth/username");
  await _fetch("/auth/password");
  return;
};

// TODO (1): Register a credential using a fingerprint
// 1. Create `registerCredential()` function
// 2. Obtain the challenge and other options from server endpoint: `/auth/registerRequest`
// 3. Create a credential
// 4. Register the credential to the server endpoint: `/auth/registerResponse`
export const registerCredential = async () => {
  // TODO:
  await simpleAuth();

  const opts = {
    attestation: "none",
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
      requireResidentKey: false,
    },
  };

  const options = await _fetch("/auth/registerRequest", opts);

  console.log("[OPTIONS]", options);

  //options.user.id = base64url.decode(options.user.id);
  //options.challenge = base64url.decode(options.challenge);

  options.user.id = Uint8Array.from(options.user.id, (c) => c.charCodeAt(0));
  options.challenge = Uint8Array.from(options.challenge, (c) =>
    c.charCodeAt(0)
  );

  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = base64url.decode(cred.id);
      // cred.id = Uint8Array.from(cred.id, (c) => c.charCodeAt(0));
    }
  }

  const cred = await navigator.credentials.create({
    publicKey: options,
  });

  const credential = {};
  credential.id = cred.id;
  credential.rawId = base64url.encode(cred.rawId);
  credential.type = cred.type;

  if (cred.response) {
    console.log("DIFF cred options", cred, options);
    // cred.response.clientDataJSON.challenge = options.challenge;
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const attestationObject = base64url.encode(cred.response.attestationObject);
    credential.response = {
      clientDataJSON,
      attestationObject,
    };
  }

  console.log("[CRED]", cred);
  console.log("[CREDENTIAL]", credential);

  localStorage.setItem(`credId`, credential.id);

  return await _fetch("/auth/registerResponse", credential);
};

// TODO (2): Build the UI to register, get and remove credentials
// 3. Remove the credential: `removeCredential()`
export const unregisterCredential = async (credId) => {
  localStorage.removeItem("credId");
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};

// TODO (3): Authenticate the user with a fingerprint
// 1. Create `authetnicate()` function
export const authenticate = async () => {
  const opts = {};

  let url = "/auth/signinRequest";
  const credId = localStorage.getItem(`credId`);
  if (credId) {
    url += `?credId=${encodeURIComponent(credId)}`;
  }

  const options = await _fetch(url, opts);

  if (options.allowCredentials.length === 0) {
    console.info("No registered credentials found.");
    return Promise.resolve(null);
  }

  options.challenge = base64url.decode(options.challenge);

  for (let cred of options.allowCredentials) {
    cred.id = base64url.decode(cred.id);
  }

  const cred = await navigator.credentials.get({
    publicKey: options,
  });

  const credential = {};
  credential.id = cred.id;
  credential.type = cred.type;
  credential.rawId = base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const authenticatorData = base64url.encode(cred.response.authenticatorData);
    const signature = base64url.encode(cred.response.signature);
    const userHandle = base64url.encode(cred.response.userHandle);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle,
    };
  }

  return await _fetch(`/auth/signinResponse`, credential);
};

// 2. Obtain the challenge and other options from server
// 3. Locally verify the user and get a credential
// 4. Verify the credential: `/auth/signinResponse`
