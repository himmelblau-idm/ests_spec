# Unofficial eSTS Protocol Specification

This repository is the home of the unofficial Microsoft Entra ID Security
Token Service (eSTS) interactive multi-factor authentication specification.
It documents the HTTP APIs and flow state used to authenticate users and
obtain OAuth 2.0 authorization codes without rendering the eSTS sign-in pages
in a browser UI.

The Himmelblau project maintains this specification for other implementors.
It covers authentication discovery, passwordless and password-based sign-in,
MFA challenges, post-authentication interrupts, and token exchange, as well
as the OAuth 2.0 device authorization grant.

The source document is [ests-spec.md](ests-spec.md). Generated HTML and
PDF versions are produced from that file for easier reading and distribution.

## Build Instructions

The build requires:

- GNU Make 4.3 or later (the figure sources use grouped targets)
- Python 3, available as `python3`
- Pandoc, available as `pandoc`
- Google Chrome or Chromium, for figure and PDF rendering
- Node.js and npm, with a Node.js version supported by Mermaid CLI
- Mermaid CLI, available as `mmdc`; install it with
  `npm install --global @mermaid-js/mermaid-cli`
- The browser's platform runtime libraries and a readable sans-serif font
  (DejaVu Sans or Arial matches the figure configuration). Installing Chrome
  through your platform's package manager normally supplies its runtime
  dependencies.

Install the other tools with your platform's package manager. No third-party
Python packages are required. The renderer uses the settings in
`figures/mermaid-config.json` and `figures/puppeteer.json`.

The build automatically finds `google-chrome`, `google-chrome-stable`,
`chromium`, or `chromium-browser` on `PATH` and uses that browser for both
figures and PDF. No Puppeteer browser download or environment-variable setup
is needed. An explicit `CHROME` setting takes precedence, followed by an
existing `PUPPETEER_EXECUTABLE_PATH` setting, then automatic detection.

For Fedora 44, install the distribution packages with:

```sh
sudo dnf install make python3 pandoc-cli nodejs npm dejavu-sans-fonts
```

If Chrome or Chromium is not already installed, also run
`sudo dnf install chromium`. Install Mermaid CLI with the npm command above;
then run `make` normally.

Run:

```sh
make
```

The build generates Mermaid sources from `figures/mkfigs.py`, renders the
24 figures into `./images`, creates `ests-spec.html` with Pandoc, and renders
`ests-spec.pdf` using the detected browser in headless mode. Changes to the
figure generator, Mermaid sources, or rendering configuration rebuild affected
images and then the HTML and PDF. Parallel builds (`make -j`) are supported.

Edit figure content in `figures/mkfigs.py`; `figures/src/*.mmd` are generated
files and are overwritten when the generator runs. Figure numbers are
remapped near the end of that script, so check cross-references after edits.
When adding or removing a figure, also update `FIGURE_NAMES` in the Makefile
and the specification's figure index.

To build only the figures, run:

```sh
make figures
```

Tool commands can be overridden, for example:

```sh
make CHROME=chromium MMDC=/path/to/mmdc
```

`PYTHON` and `PANDOC` can also be overridden. `CHROME` selects the browser for
both PDF and Mermaid rendering. Build failures are reported and stop the build.

To remove generated HTML, PDF, and PNG files (keeping the Mermaid sources), run:

```sh
make clean
```
