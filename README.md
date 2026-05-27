# Cryptographic Bill of Materials (CBOM) Generator and Blast Radius Analyzer

This is a CBOM generator that also uses [Trailmark](https://github.com/trailofbits/trailmark) (courtesty of Trail of Bits). This tool is a localized security utility designed to scan software codebases (Python and Go) for cryptographic components and map their reachability. 

Rather than just listing the cryptographic algorithms used in your software, this tool identifies which algorithms are actively reachable from public interface entry points (such as web routes, API endpoints, or command-line interfaces) and which are isolated or unreachable. 

This tool was written with the intention to help small to medium-sized businesses and/or under-resourced security teams focus their limited time on creating a CBOM in order to identify cryptography-related weaknesses in their code. This in turn can be used to resolve potential vulnerabilities or be better prepared for a Post Quantum future that is seemingly a matter of "if" not "when."

> [!IMPORTANT]
> **Out-of-the-Box Functionality**: By default, this tool runs **entirely deterministically** on your local machine using static syntax matching (AST analysis) and static call-graph pathfinding. It does not communicate with external APIs or orchestrate AI models. To scale the utility using autonomous workflows, you must define and configure your own AI orchestration layer to hook into the deterministic core modules.

## Key Capabilities

* **Automated Asset Discovery**: Scans Python and Go directories to locate cryptographic primitives (such as AES, RSA, MD5, SHA-256) and generates a standard CycloneDX v1.6 Cryptographic Bill of Materials (CBOM).
* **Call Graph Construction**: Analyzes how functions interact and call each other to build a complete map of the software structure.
* **Deterministic Reachability Mapping**: Automatically determines if a cryptographic asset is actually executable from an external route, mapping the exact step-by-step path an execution request takes.
* **Offline Interactive Reports**: Generates interactive HTML visualization maps that can be opened in any web browser without needing an internet connection.

## System Prerequisites

To run this utility, your local machine needs:
1. **Python 3.12** (newer versions have not yet been tested)
2. **Node.js** (Only required if you want to generate the interactive `visual_map.html` diagram; the JSON-based reports will still generate without Node.js)

## Quick Start Installation

Follow these steps to set up the tool on your system:

### 1. Install Node.js Dependencies (Optional)
If you wish to generate visual diagrams, install the required visual compiler in the project folder:
```bash
npm install
```

### 2. Install Python Dependencies
You can install the required packages using standard Python tools:
```bash
pip install -r pyproject.toml
```
Or, if you are using `uv`:
```bash
uv sync
```

## How to Run a Scan

To analyze a software repository, run the `main.py` script and provide the path to the folder you want to scan:

```bash
python main.py /path/to/your/target/repository
```

Or, using `uv`:
```bash
uv run python main.py /path/to/your/target/repository
```

### Customizing the Output Directory
By default, the analysis results are saved in a folder named `output`. You can specify a different folder using the `--output-dir` or `-o` flag:

```bash
python main.py /path/to/your/target/repository --output-dir /path/to/your/custom_output_folder
```

## Understanding the Deliverables

After the scan completes, the output folder will contain the following files:

| File Name | Intended Audience | Purpose |
| :--- | :--- | :--- |
| **`cbom.json`** | Compliance & Auditing | A complete inventory list of all cryptographic assets discovered in the codebase, formatted as a standard CycloneDX v1.6 document. |
| **`codegraph.json`** | Software Engineers | A full technical mapping of how functions and methods reference each other across the target repository. |
| **`blast_radius.json`** | Security Teams | A structured list grouping every cryptographic asset. Reachable assets show the exact chain of function calls leading to them, while unreachable assets are separated into a designated list. |
| **`visual_map.html`** | Everyone (Non-technical & Technical) | A single, offline-friendly web page containing visual call-chain flowcharts. Reachable paths are highlighted to show exactly how an external request can invoke each cryptographic asset. |
| **`blast_radius.zip`** | IT Administrators | A compressed archive containing the JSON reports and HTML visualization map for easy sharing and backup. |

## Testing with the Included Sample Project

A sample Python KMS API repository is included inside `training data/sampleproject01` to test the capabilities of the scanner. It consists of a legacy v1 API (using weak cryptography like MD5 and SHA-1) and a modern v2 API (using AES-256 and PBKDF2-SHA256). It also contains a legacy compatibility module containing uncalled cryptographic functions.

### Running the Test Scan

To scan the sample project, run the following command in your terminal:

```bash
python main.py "training data/sampleproject01"
```

Or, using `uv`:
```bash
uv run python main.py "training data/sampleproject01"
```

### What to Expect in the Results

When the scan completes, you should expect the following outcome:

1. **Terminal Summary**:
   - **Reachable Vulnerable AST Nodes**: 15
   - **Unreachable/Static Library Cryptographic Assets**: 11

2. **Key Findings in the Reports**:
   - **Reachable Weaknesses**: The tool maps public entry points directly to deprecated algorithms, such as tracing the legacy login route (`api/v1/auth_routes:handle_login_v1`) down to the weak `SHA-1` password verification hashing function (`crypto/hashing.py:sha1_hash`).
   - **Reachable Modern Features**: Secure algorithms like `AES` and `SHA-256` will show clean paths originating from modern v2 routes.
   - **Unreachable Assets**: Cryptographic occurrences inside `utils/legacy_compat.py` and other uncalled methods are successfully isolated and classified under the unreachable section, allowing security teams to deprioritize them.
   - **Visual Flowcharts**: Open `output/visual_map.html` in your browser to see the complete, color-coded call graphs highlighting active and inactive cryptographic blast radiuses.

## How to Prioritize the Results

When reviewing the findings, use the following guidelines:
1. **Reachable and Insecure Algorithms**: If the tool shows that an outdated or weak algorithm (e.g., MD5, SHA-1, DES) is reachable from a public-facing entry point, this should be addressed immediately.
2. **Reachable and Secure Algorithms**: These represent your active cryptographic footprint. Verify that the key sizes and implementation choices align with your security policies.
3. **Unreachable Algorithms**: Cryptographic assets that are not reachable from external entry points are lower priority. They might represent unused/legacy code or internal utility functions that cannot be triggered from the outside.

## Integrating AI Workflows

While this utility is built entirely on local, deterministic code execution to increase reliability and accuracy, it was designed with an AI-agnostic structure that can easily be integrated into modern AI workflows. Depending on your codebase size and resources, you can scale the utility using one of two primary patterns:

### Option 1: Local Deterministic Scan with Downstream LLM Interpretation (Small to Medium Repositories)
For standard codebases, use the built-in deterministic engine as is. Because it is local and rule-based, it runs very quickly, and the code is available for you to pick apart to see any mistakes or discrepancies the tool might produce. Once the scan completes, you can feed the highly structured output files (`blast_radius.json` and `cbom.json`) into the LLM of your choice to:
* Interpret the business and security implications of weak algorithms in your specific architecture.
* Automatically write step-by-step remediation advice and refactoring pull requests to update insecure cryptographic primitives.

### Option 2: AI Sub-Agent Enhancements (Large, Legacy, or Enterprise Codebases)
For large scale or highly dynamic codebases, you can deploy AI-driven sub-agents under careful human supervision to enhance the individual capabilities of Modules A, B, and C as labeled in `main.py`:
* **Enhanced Module A (Cryptographic Extraction)**: Deploy a sub-agent to statically audit files for proprietary, custom, or non-standard cryptographic wrappers, ensuring they are documented in your CBOM alongside standard libraries.
* **Enhanced Module B (CodeGraph Resolution)**: Deploy a sub-agent to analyze complex dependency injection patterns, resolve dynamic metaclasses, or perform sandboxed execution tracing to identify call-graph edges that static analysis misses.
* **Enhanced Module C (Context-Aware Security Triage)**: Deploy a sub-agent to perform automated taint analysis (verifying if user-controlled input actually reaches the weak primitive along the call chain) and automatically write custom-tailored quantum-safe replacement code.
