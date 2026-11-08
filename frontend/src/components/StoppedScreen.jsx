import { useEffect } from "react";
import { Mark } from "./ui";

/** Shown after Exit. The server is gone, so this page stays static and makes no requests. */
export default function StoppedScreen() {
  useEffect(() => {
    document.title = "AetherEDR stopped";
  }, []);
  return (
    <main className="grid min-h-full place-items-center p-6">
      <div className="w-full max-w-md space-y-4 border border-rule2 bg-plate p-6">
        <div className="flex items-center gap-3">
          <Mark size={34} />
          <h1 className="text-lg font-bold tracking-tight">AetherEDR has stopped</h1>
        </div>
        <p className="text-[0.8125rem] text-pencil">Nothing is being watched now. You can close this tab.</p>
        <p className="border-t border-rule pt-3 text-xs text-graphite">
          To start it again, open <code className="whitespace-nowrap font-mono">AetherEDR.bat</code> on Windows or run <code className="whitespace-nowrap font-mono">python run.py</code>.
        </p>
      </div>
    </main>
  );
}
