import { useState } from "react";
import { api, setKey } from "../lib/api";
import { Button, ErrorNote, Input, Mark } from "./ui";

export default function AuthGate({ onAuthed }) {
  const [value, setValue] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setKey(value);
    try {
      await api("overview/");
      onAuthed();
    } catch (err) {
      setError(err.status === 401 ? "That key was not accepted. Copy it again from the terminal or from data/api_key." : err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="grid min-h-full place-items-center p-6">
      <form onSubmit={submit} className="w-full max-w-md space-y-4 border border-rule2 bg-plate p-6">
        <div className="flex items-center gap-3">
          <Mark size={34} />
          <div>
            <h1 className="text-xl font-bold leading-tight">AetherEDR</h1>
            <p className="text-xs text-graphite">Endpoint detection and response</p>
          </div>
        </div>
        <p className="text-pencil">
          Enter the API key to open the console. It is printed in the window that started AetherEDR and saved in <code className="font-mono text-xs text-ink">data/api_key</code>.
        </p>
        <label className="block">
          <span className="mb-1 block text-[0.8125rem] font-bold">API key</span>
          <Input autoFocus type="password" value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} className="w-full font-mono" />
        </label>
        <ErrorNote error={error} />
        <Button variant="primary" type="submit" disabled={busy || !value.trim()} className="w-full">
          Open console
        </Button>
      </form>
    </main>
  );
}
