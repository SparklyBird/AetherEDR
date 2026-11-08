import { Component } from "react";

/** Keeps one broken panel from taking down the whole page. */
export default class ErrorBoundary extends Component {
  state = { error: null, resetKey: this.props.resetKey };

  static getDerivedStateFromError(error) {
    return { error };
  }

  static getDerivedStateFromProps(props, state) {
    // switching sheet or process resets the panel
    return props.resetKey !== state.resetKey ? { error: null, resetKey: props.resetKey } : null;
  }

  componentDidCatch(error, info) {
    console.error(`[AetherEDR] ${this.props.label || "panel"} crashed`, error, info?.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div role="alert" className="m-4 space-y-2 border-l-[3px] border-redline bg-plate p-4">
        <p className="font-bold text-redline">{this.props.label || "This panel"} hit an error</p>
        <p className="break-words font-mono text-xs text-pencil">{String(this.state.error?.message || this.state.error)}</p>
        <p className="text-[0.8125rem] text-pencil">The rest of the console keeps working. Reloading the panel usually clears it.</p>
        <button
          type="button"
          onClick={() => this.setState({ error: null })}
          className="rounded-sm border border-rule2 px-3 py-1.5 text-[0.8125rem] font-medium hover:bg-plate2"
        >
          Reload panel
        </button>
      </div>
    );
  }
}
