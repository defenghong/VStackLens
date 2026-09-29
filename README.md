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

VStackLens includes code for downloading and importing HCL/VCG data. We cannot include Broadcom VMware data bundles or test fixtures copied from those datasets because we do not have permission to redistribute them. The download and import code is included below, with links to Broadcom's official data sources.

You can obtain data directly from Broadcom through these official channels:

- **vSAN HCL:** [download the JSON data](https://vvs.broadcom.com/service/vsan/all.json); see Broadcom's [HCL download and upload instructions](https://knowledge.broadcom.com/external/article/373209/downloadupload-hcl-data-for-vcf.html).
- **VCG bundle:** follow Broadcom's [instructions for downloading the VCG database](https://knowledge.broadcom.com/external/article/405839). The VCG download requires Broadcom client credentials for an authorized environment.

Obtain and use the data under your own Broadcom access and applicable terms, then import it locally. Without an authorized local dataset, data-dependent compatibility checks can report unavailable; they must not be interpreted as a compatibility pass.

The bundled VMware PowerCLI and Typst runtimes are also not included. Obtain and provision third-party runtimes under their own terms if you build a desktop package.

## Tests

The included test fixtures use synthetic or sanitized data. We cannot include vendor data bundles or fixtures copied from them because we do not have permission to redistribute those materials.

## License

The project code is licensed under GNU GPL-3.0-only. Commercial use is allowed under the GPL terms; if you distribute a modified version, you must provide its corresponding source under GPL-3.0-only. See LICENSE for the full terms.
