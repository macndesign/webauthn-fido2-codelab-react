import React from "react";
import { registerCredential, authenticate } from "./webauthn-client";

function App() {
  const register = async () => {
    await registerCredential();
  };
  const login = async () => {
    await authenticate();
  };
  return (
    <div>
      <p>Test Register</p>
      <button onClick={register}>Register</button>
      <button onClick={login}>Login</button>
    </div>
  );
}

export default App;
