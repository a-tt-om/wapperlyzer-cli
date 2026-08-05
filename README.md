# wapper — Wapper CLI

Detect web technologies from the command line. Uses a headless browser (Playwright + Chrome/Chromium) to render pages and analyze JavaScript, DOM, cookies, headers, and more — matching the accuracy of the Wappalyzer browser extension.

7500+ technologies · Auto-updating database · Works on Linux & macOS (x64 & arm64)

## Install

```bash
pipx install git+https://github.com/user/wapper-cli.git
```

Or with pip:

```bash
git clone https://github.com/user/wapper-cli.git
cd wapper-cli
pip install .
```

> **Note:** wapper auto-detects Chrome, Chromium, or Edge on your system. If you don't have any of these, install one with `playwright install chromium`.

## Usage

```
wapper -u <url>              # Scan a single URL
wapper -f urls.txt           # Scan a list of URLs
wapper -u <url> -wf out.txt  # Save output to file
wapper --update              # Update technologies database
wapper --no-browser -u <url> # HTTP-only mode (faster, less detection)
```

### Example

```
$ wapper -u https://example.com

[+] TECHNOLOGIES [EXAMPLE.COM] :

CDN : Cloudflare [version: nil]
CMS : WordPress [version: 6.5]
JavaScript libraries : jQuery [version: 3.7.1]
UI frameworks : Bootstrap [version: 5.3.2]
```

## Detection methods

| Method | Browser mode | HTTP-only mode |
|--------|:---:|:---:|
| HTML patterns | ✓ | ✓ |
| HTTP headers | ✓ | ✓ |
| Meta tags | ✓ | ✓ |
| Script URLs | ✓ | ✓ |
| Cookies | ✓ | ✓ |
| DNS records | ✓ | ✓ |
| TLS certificate | ✓ | ✓ |
| JavaScript globals | ✓ | — |
| DOM selectors | ✓ | — |
| CSS selectors | ✓ | — |
| XHR/Fetch URLs | ✓ | — |
| Visible text | ✓ | — |

## Platform support

| OS | Architecture | Status |
|---|---|---|
| Linux | x64 | ✓ |
| Linux | arm64 | ✓ |
| macOS | x64 (Intel) | ✓ |
| macOS | arm64 (Apple Silicon) | ✓ |

## Requirements

- Python 3.9+
- Chrome, Chromium, or Edge (for browser mode)

## License

MIT
