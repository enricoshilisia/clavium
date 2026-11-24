import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { loadManagedSettings } from "./managed";

// Managed settings (company server address and so on) must be in place
// before the first request, so they load before the app renders.
loadManagedSettings().finally(() => {
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
});
