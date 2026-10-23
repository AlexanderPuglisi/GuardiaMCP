# Changelog

## 0.2.1 — 24 October 2026

- **Fixed**: the Windows executables did not start when the zip was downloaded from the Internet
  (`Failed to resolve Python.Runtime.Loader.Initialize`). Each program now ships a `.exe.config` that
  lets .NET load the libraries in its own folder. See [SECURITY.md](SECURITY.md).
- Step-by-step guide with screenshots: [docs/GUIDA.md](docs/GUIDA.md) (Italiano) and
  [docs/GUIDE.md](docs/GUIDE.md) (English).

## 0.2.0 — 23 October 2026

- First public release: static scanner (v1), real-time Shield (v2), tamper-evident ledger, desktop
  app and command line in Italian and English. See [TESTING.md](TESTING.md).
