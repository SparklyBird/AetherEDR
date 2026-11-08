"""Launcher: migrates the DB, starts the collector, serves the API and UI.

    python run.py                              # everything, opens the dashboard
    python run.py --no-browser --port 9000
    python run.py --no-agent                   # server only (collect from remote agents)
    python run.py --tls                        # HTTPS with a generated self-signed certificate
    python run.py --host 0.0.0.0 --tls         # reachable from the network, encrypted
    python run.py --agent-only --server https://10.0.0.5:8787 --key <AGENT_KEY> --ca-cert server.crt
"""
from __future__ import annotations

import _thread
import argparse
import ipaddress
import json
import logging
import os
import socket
import ssl
import sys
import webbrowser

LOOPBACK = ("127.0.0.1", "localhost", "::1")


def _port_free(host: str, port: int) -> bool:
    """Can we bind it? A listener blocks the bind everywhere. On Linux old connections in TIME_WAIT (right after
    a restart) would also block it, so SO_REUSEADDR is set there. On Windows that flag lets two servers share a
    port, and TIME_WAIT does not block the bind, so it is left off."""
    import socket

    bind = "127.0.0.1" if host in ("localhost", "") else host
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if os.name != "nt":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind, port))
        except OSError:
            return False
    return True


def _running_scheme(host: str, port: int) -> str | None:
    """"http" or "https" when an AetherEDR answers on that port, None when something else (or nothing) does."""
    import urllib.request

    probe = "127.0.0.1" if host in ("0.0.0.0", "::", "localhost", "") else host
    # health carries no secrets, so the certificate is not checked for this one local probe
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("http", "https"):
        try:
            with urllib.request.urlopen(f"{scheme}://{probe}:{port}/api/health/", timeout=2, context=ctx) as r:  # noqa: S310
                if json.load(r).get("status") == "ok":
                    return scheme
        except Exception:  # noqa: BLE001
            continue
    return None


def _is_aetheredr(host: str, port: int) -> bool:
    return _running_scheme(host, port) is not None


def _server_names(host: str, extra: list[str] | None = None) -> list[str]:
    """Addresses the certificate should cover, and the Host headers Django should accept."""
    names = ["localhost", "127.0.0.1", "::1"]
    if host not in ("0.0.0.0", "::", "", *LOOPBACK):
        names.append(host)
    try:
        names.append(socket.gethostname())
        for info in socket.getaddrinfo(socket.gethostname(), None):
            names.append(info[4][0].split("%")[0])
    except OSError:
        pass
    names.extend(extra or [])
    return list(dict.fromkeys(n for n in names if n))


def _prepare_tls(args, data_dir) -> tuple[str, str, dict]:
    """Certificate and key files to serve with. Your own via --tls-cert/--tls-key, otherwise a generated one
    that is kept in the data folder and made again only when the names change or it is close to expiry."""
    import datetime as dt
    from pathlib import Path

    if args.tls_cert or args.tls_key:
        if not (args.tls_cert and args.tls_key):
            raise SystemExit("--tls-cert and --tls-key go together")
        return args.tls_cert, args.tls_key, {"source": "supplied"}
    from .tlsgen import make_self_signed

    folder = Path(data_dir) / "tls"
    folder.mkdir(exist_ok=True)
    cert, key, meta = folder / "server.crt", folder / "server.key", folder / "server.json"
    names = _server_names(args.host, args.tls_name)
    try:
        info = json.loads(meta.read_text())
        fresh = dt.datetime.fromisoformat(info["not_after"]) - dt.datetime.now(dt.timezone.utc) > dt.timedelta(days=30)
        if cert.exists() and key.exists() and fresh and set(names) <= set(info["names"]):
            return str(cert), str(key), dict(info, source="generated", path=str(cert))
    except (OSError, ValueError, KeyError):
        pass
    print("  Creating a self-signed certificate (a second or two)...")
    cert_pem, key_pem, info = make_self_signed(names)
    cert.write_text(cert_pem)
    key.write_text(key_pem)
    meta.write_text(json.dumps(info))
    try:
        os.chmod(key, 0o600)
    except OSError:
        pass
    return str(cert), str(key), dict(info, source="generated", path=str(cert))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aetheredr", description="AetherEDR - standalone EDR")
    ap.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--interval", type=float, default=None, help="collector poll interval, seconds")
    ap.add_argument("--no-agent", action="store_true", help="do not run the built-in collector")
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--agent-only", action="store_true", help="run only the collector and ship to --server")
    ap.add_argument("--server", help="AetherEDR server URL (agent-only mode)")
    ap.add_argument("--key", help="agent key (agent-only mode). The API key works too, but give agents the agent key")
    ap.add_argument("--ca-cert", help="certificate file to trust when the server uses a self-signed one (agent-only mode)")
    ap.add_argument("--tls", action="store_true", help="serve HTTPS. Makes a self-signed certificate unless --tls-cert is given")
    ap.add_argument("--tls-cert", help="your own certificate (PEM), implies --tls")
    ap.add_argument("--tls-key", help="private key for --tls-cert (PEM)")
    ap.add_argument("--tls-name", action="append", default=[], metavar="NAME",
                    help="extra DNS name or IP for the generated certificate and the allowed Host headers (repeatable)")
    ap.add_argument("--allow-plain-http", action="store_true",
                    help="allow a network address without TLS. The key and all data then cross the network unencrypted")
    args = ap.parse_args(argv)
    args.tls = args.tls or bool(args.tls_cert or args.tls_key)

    if not args.agent_only and args.host not in LOOPBACK and not args.tls and not args.allow_plain_http:
        print(f"\n  Not starting: --host {args.host} makes this reachable from the network without encryption,\n"
              "  so the API key and every alert would travel in clear text.\n\n"
              f"  Add --tls to serve HTTPS:   AetherEDR.bat --host {args.host} --tls\n"
              "  Or keep it on this PC (the default).  --allow-plain-http overrides this check, for a closed lab only.")
        return 1

    if not args.agent_only and not _port_free(args.host, args.port):
        # check before starting anything, a second collector would write to the same database
        if _is_aetheredr(args.host, args.port):
            print(f"\n  AetherEDR is already running on port {args.port}.")
            if not args.no_browser:
                webbrowser.open(f"{_running_scheme(args.host, args.port) or 'http'}://127.0.0.1:{args.port}/")
                print("  Opened it in your browser. The API key is in data/api_key if the page asks for it.")
        else:
            print(f"\n  Port {args.port} is used by another program.\n  Try another one:  AetherEDR.bat --port {args.port + 1}")
            return 1
        return 0

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "aether.settings")
    if args.interval:
        os.environ["AETHER_INTERVAL"] = str(args.interval)
    if args.host not in LOOPBACK or args.tls_name:
        # the console is reached by one of these names, so Django has to accept them as the Host header
        hosts = [n if ":" not in n else f"[{n}]" for n in _server_names(args.host, args.tls_name)]
        os.environ["AETHER_ALLOWED_HOSTS"] = ",".join(filter(None, [os.environ.get("AETHER_ALLOWED_HOSTS", ""), *hosts]))

    from aether import __version__

    log = logging.getLogger("aether")

    if args.agent_only:
        if not args.server or not args.key:
            ap.error("--agent-only needs --server and --key")
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        from edr.collector.agent import AgentThread, HttpSink
        from edr.collector.collector import Collector

        interval = args.interval or 5.0
        if args.server.lower().startswith("http://") and not any(h in args.server for h in ("//127.0.0.1", "//localhost", "//[::1]")):
            print("  Warning: this server address is plain http, so the agent key travels unencrypted. Use https://.")
        agent = AgentThread(HttpSink(args.server, args.key, ca_cert=args.ca_cert),
                            Collector(interval=interval, use_events=os.environ.get("AETHER_EVENTS", "1") != "0"), interval=interval)
        print(f"AetherEDR agent {__version__} -> {args.server} (Ctrl+C to stop)")
        agent.start()
        try:
            while agent.is_alive():
                agent.join(1.0)
        except KeyboardInterrupt:
            agent.stop()
        return 0

    import django

    django.setup()
    from django.conf import settings
    from django.core.management import call_command
    from django.db import connection

    logging.config_done = True  # Django applied LOGGING during setup()
    call_command("migrate", interactive=False, verbosity=0)
    with connection.cursor() as cur:
        cur.execute("PRAGMA journal_mode")
        mode = cur.fetchone()[0]
    log.info("SQLite journal mode: %s (%s)", mode, settings.DATABASES["default"]["NAME"])

    from edr import runtime
    from edr.collector.agent import AgentThread, LocalSink, Supervisor
    from edr.collector.collector import Collector
    from edr.engine.maintenance import MaintenanceThread

    cfg = settings.AETHER
    agent = None
    if not args.no_agent:
        col = Collector(interval=cfg["COLLECT_INTERVAL"], stats_interval=cfg["STATS_INTERVAL"],
                        memscan_per_poll=cfg["MEMSCAN_PER_POLL"], memscan_delays=cfg["MEMSCAN_DELAYS"],
                        memscan_period=cfg["MEMSCAN_PERIOD"], use_events=cfg["EVENTS"])
        agent = AgentThread(LocalSink(), col, interval=cfg["COLLECT_INTERVAL"])
        runtime.state.update(agent=agent, mode="standalone")
        if not col.host["is_admin"]:
            log.warning("Not running elevated: memory introspection will only cover processes you own. "
                        "Run as root / Administrator for full coverage.")
    else:
        runtime.state["mode"] = "server"

    maintenance = MaintenanceThread()
    maintenance.start()
    supervisor = Supervisor(runtime.state)
    if agent:
        agent.start()
        supervisor.start()

    from aether.wsgi import application

    scheme = "https" if args.tls else "http"
    scheme_host = "127.0.0.1" if args.host in ("0.0.0.0", "::", "") else args.host
    url = f"{scheme}://{scheme_host}:{args.port}/#key={settings.API_KEY}"
    tls_info = None
    backend_sock = None
    if args.tls:
        try:
            certfile, keyfile, tls_info = _prepare_tls(args, settings.DATA_DIR)
        except (OSError, ssl.SSLError) as exc:
            print(f"\n  Could not prepare the TLS certificate: {exc}")
            return 1
        # waitress stays on a private loopback port, the TLS front is the only listener on the network
        backend_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_sock.bind(("127.0.0.1", 0))
    elif args.host not in LOOPBACK:
        log.warning("Listening on %s over plain HTTP (--allow-plain-http). The keys and all data cross the network unencrypted.",
                    args.host)
    lines = [f"\n  AetherEDR {__version__}", f"  Dashboard : {url}", f"  API key   : {settings.API_KEY}"]
    if args.no_agent or args.host not in LOOPBACK:
        lines.append(f"  Agent key : {settings.INGEST_KEY}   (for remote agents, send-only)")
    lines.append(f"  Data dir  : {settings.DATA_DIR}")
    if tls_info:
        what = "your certificate" if tls_info["source"] == "supplied" else f"self-signed, {tls_info.get('path', '')}"
        lines.append(f"  HTTPS     : on ({what})")
        if tls_info["source"] == "generated":
            lines.append("              Your browser will warn once because nobody else vouches for this certificate.\n"
                         "              Give agents the same file with --ca-cert so they can check it.")
    print("\n".join(lines) + "\n")
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    from waitress import serve

    # the Exit button in the console ends up here: the same as pressing Ctrl+C in this window
    runtime.state["shutdown"] = _thread.interrupt_main

    code = 0
    front = None
    try:
        if args.tls:
            from .tlsproxy import TlsFront

            front = TlsFront(args.host, args.port, backend_sock.getsockname()[1], certfile, keyfile)
            front.start()
            serve(application, sockets=[backend_sock], threads=24, ident="AetherEDR", _quiet=True,
                  channel_timeout=300, url_scheme="https")
        else:
            serve(application, host=args.host, port=args.port, threads=24, ident="AetherEDR", _quiet=True,
                  channel_timeout=300)
    except KeyboardInterrupt:
        pass
    except OSError as exc:  # lost a race for the port after the check above
        print(f"\n  Could not listen on port {args.port}: {exc}")
        code = 1
    finally:
        if front:
            front.stop()
        supervisor.stop()
        current = runtime.state.get("agent") or agent
        if current:
            current.stop()
        maintenance.stop()
    return code


if __name__ == "__main__":
    sys.exit(main())
