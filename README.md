# VStackLens

VStackLens 0.2.8 is a local VMware vSphere inspection and reporting framework with a command-line interface and an optional Windows desktop app.

## Features

- Run rule-based vSphere inspections from the CLI or Windows desktop app.
- Analyze VMware support bundles locally.
- Generate offline HTML, Word, and PDF reports.
- Run deeper health, risk, performance, and hardware-compatibility checks when the required evidence and datasets are available.
- Keep inspection databases and reports on the local machine.

Core inspection and report generation run locally. Online HCL data retrieval is an explicit user action.

## Quick start

Requires Python 3.12 or later.

    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -e '.[desktop]'
    .\.venv\Scripts\python.exe -m vstacklens.cli desktop

See available CLI commands with:

    .\.venv\Scripts\python.exe -m vstacklens.cli --help

## HCL and VCG data

This repository intentionally does not include Broadcom VMware HCL/VCG data bundles or fixtures derived from them. Those datasets have their own terms. Obtain data directly under authorization that permits your use, then import it locally. Without an authorized dataset, data-dependent compatibility checks can report unavailable; they must not be interpreted as a compatibility pass.

The bundled VMware PowerCLI and Typst runtimes are also not included. Obtain and provision third-party runtimes under their own terms if you build a desktop package.

## Tests

The included test fixtures are synthetic or sanitized. Tests requiring vendor HCL/VCG bundles are omitted from this source snapshot.

## License

The project code is licensed under GNU GPL-3.0-only. Commercial use is allowed under the GPL terms; if you distribute a modified version, you must provide its corresponding source under GPL-3.0-only. See LICENSE for the full terms.