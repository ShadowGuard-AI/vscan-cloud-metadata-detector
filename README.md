# vscan-cloud-metadata-detector

Detects whether cloud metadata endpoints are accessible (AWS, GCP, Azure) by sending requests to known metadata URLs and checking the responses for sensitive keywords. Part of a lightweight web application vulnerability scanning set focused on common misconfigurations.

## Install

`git clone https://github.com/ShadowGuard-AI/vscan-cloud-metadata-detector.git`

Then install the one dependency:

`pip install -r requirements.txt`

## Usage

`python3 main.py [-u URL] [-v]`

Example: `python3 main.py -u http://127.0.0.1:8000`

## Parameters

- `-h`, `--help`: Show help message and exit.
- `-u`, `--url`: Target URL to check for metadata exposure. If not provided, performs basic checks against the known metadata endpoints themselves.
- `-v`, `--verbose`: Enable verbose output for debugging.

## Notes

With `-u`, each known metadata path (for example `latest/meta-data/`) is built onto the target URL, and the checked address is the target with that path. The AWS and Azure paths are built onto the same target host in turn, each with its own provider headers. When an endpoint answers, the log records the status, the response length, and the names of any matched sensitive keywords. The response body itself is never written to the log.

A response counts as possible sensitive information disclosure only when at least one sensitive keyword matches in the body. A plain 200 response with no matched keyword is logged as content retrieved and is not reported as exposure. Redirects are not followed: a redirect at a metadata path is logged and is not treated as a metadata response. Keyword matching is a case insensitive substring search, so a match says the word was present, nothing more.

Results are reported in the log lines only, and the process exits 0 once the scan completes. Run with no target only on a machine you own: it reaches out to the real link local metadata addresses from the machine it runs on.

## License

MIT License. See LICENSE.
