import React from "react";
import { registerCredential } from "./webauthn-client";

function App() {
  return (
    <div>
      <p>Test Register</p>
      <button onClick={registerCredential}>Register</button>
    </div>
  );
}

export default App;
