# Seljan Security Tool Stack

Version: 1.0.0

Free, browser-based security helpers served at https://seljan.net:

- **IOC pivot:** paste an IP, domain, URL, file hash, or email address and get one-click
  links to lookup tools. Defanged text (`hxxp://`, `[.]`) is cleaned up automatically.
- **Tool directory:** a curated list of reputation, sandbox, email/DNS, and recon tools.
- **Port reference:** what common ports are for and whether they should be exposed.
- **Email checker:** paste a suspicious email and see the warning signs explained.

Everything runs in the browser. The pivot only builds links; nothing is sent anywhere until
you click through to a third-party tool. No cookies, analytics, or tracking.

## Layout

| Path | What it is |
|---|---|
| `site/` | The website (plain HTML, CSS, JavaScript; no build step) |
| `scripts/publish.sh` | Publishes `site/` to the `gh-pages` branch (GitHub Pages) |

## Preview locally

```bash
python -m http.server 8765 --directory site
```

Open http://localhost:8765.
