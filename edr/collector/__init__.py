"""Lazy exports so `python -m edr.collector.collector` does not trigger runpy warnings."""


def __getattr__(name):
    if name in ("Collector", "host_info"):
        from . import collector as _c

        return getattr(_c, name)
    raise AttributeError(name)
