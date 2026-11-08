import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import Toasts from "./components/Toasts";
import { applySettings } from "./lib/settings";
import { toast } from "./lib/toast";
import "./index.css";

applySettings();

// last-resort handlers so errors show up and the page never goes blank
window.addEventListener("error", (e) => {
  if (/ResizeObserver loop/.test(e.message || "")) return; // harmless browser warning
  console.error("[AetherEDR] uncaught", e.error || e.message);
  toast({ title: "Something went wrong", body: String(e.message || "Unexpected error. The console keeps running."), tone: "bad", ms: 7000 });
});
window.addEventListener("unhandledrejection", (e) => {
  const r = e.reason;
  if (r?.name === "AbortError") return; // a cancelled request is not a failure
  console.error("[AetherEDR] unhandled rejection", r);
  toast({ title: "A background request failed", body: String(r?.message || r || ""), tone: "bad", ms: 6000 });
});

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <ErrorBoundary label="AetherEDR">
      <App />
    </ErrorBoundary>
    <Toasts />
  </StrictMode>,
);
