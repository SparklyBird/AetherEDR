import { useState } from "react";
import { api, explain } from "../lib/api";
import { Button, Dialog, Spinner } from "./ui";

/** Asks first, then stops the whole program: collector, console and server. */
export default function ExitDialog({ open, onClose, onStopped, remoteAgents }) {
  const [busy, setBusy] = useState(false);

  async function stop() {
    setBusy(true);
    try {
      await api("system/shutdown/", { method: "POST", body: { confirm: true } });
      onStopped();
    } catch (e) {
      explain(e, "Could not stop AetherEDR");
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={busy ? () => {} : onClose} title="Exit AetherEDR">
      <div className="space-y-4 p-4">
        <p className="text-[0.8125rem] text-pencil">
          This stops the collector and the console. Nothing is watched or recorded until you start AetherEDR again.
          {remoteAgents ? " Remote agents cannot send data while it is stopped." : ""} Stored history stays.
        </p>
        <div className="flex flex-wrap justify-end gap-2">
          <Button onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="danger" onClick={stop} disabled={busy}>
            {busy && <Spinner />} Exit
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
