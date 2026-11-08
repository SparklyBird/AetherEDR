import { Kbd } from "./ui";

// Width of the open card plus its margin, so the graph can leave that strip clear when it fits itself.
export const KEYS_CARD_SPACE = 16 + 264 + 12;
export const KEYS_CARD_HEIGHT = 250;

// The card only shows when the graph pane is at least this wide. Beside an open dossier the pane is narrower and the graph needs the room.
export const KEYS_MIN_PANE = 960;

const ROWS = [
  [["Ctrl", "K"], "Search or run commands"],
  [["J", "K"], "Next / previous incident"],
  [["A"], "Acknowledge incident"],
  [["X"], "Mark false positive"],
  [["F"], "Fit graph in view"],
  [["+", "-"], "Zoom in / out"],
  [["/"], "Find a process"],
];

const PLATE = "border border-rule2 bg-[color-mix(in_srgb,var(--plate)_94%,transparent)]";

/** Small floating list of the main keyboard commands, top left of the graph. */
export default function KeysCard({ open, onOpen, onClose, top }) {
  if (!open) {
    return (
      <button
        type="button"
        data-ui
        style={{ top }}
        onClick={onOpen}
        aria-expanded="false"
        className={`absolute left-3 hidden px-2.5 py-1.5 text-xs text-ink hover:bg-plate md:block ${PLATE}`}
      >
        Keys
      </button>
    );
  }
  return (
    <aside data-ui style={{ top }} aria-label="Keyboard commands" className={`absolute left-3 hidden w-[16.5rem] text-xs text-pencil md:block ${PLATE}`}>
      <div className="flex items-center justify-between border-b border-rule px-2.5 py-1">
        <h2 className="text-ink">Keys</h2>
        <button type="button" onClick={onClose} aria-label="Hide keys" className="px-1.5 text-base leading-6 text-graphite hover:text-ink">
          ×
        </button>
      </div>
      <dl className="space-y-1.5 px-2.5 py-2">
        {ROWS.map(([keys, text]) => (
          <div key={text} className="flex items-start gap-2">
            <dt className="flex w-[4.25rem] shrink-0 flex-wrap gap-1">
              {keys.map((k) => (
                <Kbd key={k}>{k}</Kbd>
              ))}
            </dt>
            <dd className="leading-5">{text}</dd>
          </div>
        ))}
      </dl>
    </aside>
  );
}
