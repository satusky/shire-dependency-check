# shire-dependency-check

A browser-based tool for identifying Python dependency gaps in airgapped Databricks environments.

## What it does

Given:
1. A hosted pip package inventory (Excel `.xlsx`)
2. A Databricks Runtime version (or an offline paste of its library list)
3. A repo's declared dependencies (`requirements.txt`, `pyproject.toml`, `environment.yml`, `setup.cfg`, or `uv.lock`)

It tells you which packages the repo needs that aren't already available inside the airgap — the "shopping list" of things to carry across.

Results are grouped into three buckets:
- **Missing** — not in the hosted pip server or the DBR; must be added
- **Version risk** — present, but the available version doesn't satisfy the repo's exact pin
- **Available** — present and (likely) compatible

## Usage

Requires Python 3.8+. No dependencies beyond the standard library.

```bash
python airgap_deps.py
```

This starts a local web server at `http://127.0.0.1:8765` and opens the UI in your default browser.

```bash
# Custom port
python airgap_deps.py --port=9000

# Don't auto-open the browser
python airgap_deps.py --no-browser
```

### Inputs

**Station 01 — Airgap inventory**

- **Excel file**: Upload an `.xlsx` containing your hosted pip package list. Select the sheet, package-name column, and (optionally) version column.
- **Databricks Runtime version**: Enter a version like `16.4 LTS`, `15.4 LTS ML`, or `18.0`. The tool scrapes the Databricks release-notes page for that runtime's pre-installed libraries. Supports AWS, Azure, and GCP doc channels.
- **Offline mode**: If you're already inside the airgap, paste the release-notes HTML or a `requirements.txt` instead of fetching live docs.

**Station 02 — Repo dependencies**

Upload files, paste text, or provide raw URLs (e.g. `raw.githubusercontent.com` links). Supported formats:
- `requirements.txt`
- `pyproject.toml` (PEP 621, PEP 735, and Poetry)
- `environment.yml` (conda, including `pip:` subsections)
- `setup.cfg`
- `uv.lock`

### Notes

- Package names are compared after [PEP 503](https://peps.python.org/pep-0503/) normalization, so `scikit_learn` and `scikit-learn` match.
- For ML runtimes, the base runtime's library list is automatically fetched and merged in (ML page wins on version conflicts).
- Version-range specifiers (`>=`, `~=`, etc.) are reported but not fully evaluated — only exact pins (`==x.y.z`) are checked for mismatches. Treat output as a starting manifest, not a guarantee.
- The tool does not resolve the full transitive dependency tree.

## License

MIT
