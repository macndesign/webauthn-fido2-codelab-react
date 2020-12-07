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
    return res.json();
  } else {
    const result = await res.json();
    throw result.error;
  }
};

const simpleAuth = async () => {
  const username = prompt("Forneça seu email");
  await _fetch("/auth/username", { username });
  await _fetch("/auth/password");
  return;
};

export const registerCredential = async () => {
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

  options.user.id = Uint8Array.from(options.user.id, (c) => c.charCodeAt(0));
  options.challenge = Uint8Array.from(options.challenge, (c) => c.charCodeAt(0));

  if (options.excludeCredentials) {
    for (let cred of options.excludeCredentials) {
      cred.id = Uint8Array.from(cred.id, (c) => c.charCodeAt(0));
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
    const clientDataJSON = base64url.encode(cred.response.clientDataJSON);
    const attestationObject = base64url.encode(cred.response.attestationObject);
    credential.response = {
      clientDataJSON,
      attestationObject,
    };
  }

  localStorage.setItem(`credId`, credential.id);

  return await _fetch("/auth/registerResponse", credential);
};

export const unregisterCredential = async (credId) => {
  localStorage.removeItem("credId");
  return _fetch(`/auth/removeKey?credId=${encodeURIComponent(credId)}`);
};

export const authenticate = async () => {
  const opts = {};

  let url = "/auth/signinRequest";
  const credId = localStorage.getItem(`credId`);
  if (credId) {
    url += `?credId=${encodeURIComponent(credId)}`;
  }

  const options = await _fetch(url, opts);

  if (!options.allowCredentials || options.allowCredentials.length === 0) {
    console.info("No registered credentials found.");
    return Promise.resolve(null);
  }

  options.challenge = Uint8Array.from(options.challenge, (c) => c.charCodeAt(0));

  for (let cred of options.allowCredentials) {
    cred.id = Uint8Array.from(cred.id, (c) => c.charCodeAt(0));
  }

  try {
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
  } catch (e) {
    throw e;
  }
};
