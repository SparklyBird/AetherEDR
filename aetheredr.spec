# -*- mode: python ; coding: utf-8 -*-
# Build:  pyinstaller --noconfirm aetheredr.spec     (build the UI first: cd frontend && npm ci && npm run build)
# Result: dist/AetherEDR/AetherEDR[.exe]  - a folder you can copy anywhere. data/ is created next to the binary.
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = [
    ("frontend/dist", "frontend/dist"),
    ("edr/yara_rules", "edr/yara_rules"),
    ("edr/reporting/templates", "edr/reporting/templates"),
]
for pkg in ("rest_framework", "docx", "reportlab"):
    datas += collect_data_files(pkg)

hidden = (
    collect_submodules("edr") + collect_submodules("aether") + collect_submodules("rest_framework")
    + collect_submodules("waitress") + ["whitenoise", "whitenoise.middleware", "django.db.backends.sqlite3",
                                         "sklearn.ensemble", "sklearn.tree", "sklearn.utils._typedefs",
                                         "sklearn.neighbors._partition_nodes"]
)

a = Analysis(["run.py"], pathex=["."], datas=datas, hiddenimports=hidden,
             excludes=["tkinter", "matplotlib", "IPython", "pytest", "scipy.tests", "numpy.tests"], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="AetherEDR", console=True, upx=False)
coll = COLLECT(exe, a.binaries, a.datas, name="AetherEDR", upx=False)
