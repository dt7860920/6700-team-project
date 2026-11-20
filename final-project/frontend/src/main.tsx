import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { HashRouter } from "react-router-dom";
import App from "./App";
import "./index.css";

// HashRouter: the SPA is served by FastAPI StaticFiles at /ui, which only serves
// files that exist. Hash routes (/ui/#/scan/:id) keep deep links and refreshes
// working without any server-side rewrite.
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </StrictMode>,
);
