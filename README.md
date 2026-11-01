# vscan-cloud-metadata-detector
Detects if cloud metadata endpoints are accessible (e.g., AWS, GCP, Azure) by sending requests to known metadata URLs and checking for sensitive information disclosure. - Focused on Lightweight web application vulnerability scanning focused on identifying common misconfigurations and publicly known vulnerabilities

## Install
`git clone https://github.com/ShadowGuardAI/vscan-cloud-metadata-detector`

## Usage
`./vscan-cloud-metadata-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `-u`: Target URL to check for metadata exposure. If not provided, performs basic checks against known endpoints.
- `-v`: Enable verbose output for debugging.

## Notes
With `-u`, each known metadata path (for example `latest/meta-data/`) is built onto the target URL, and the checked address is the target with that path. When an endpoint answers, the log records the status, the response length, and the names of any matched sensitive keywords. The response body itself is never written to the log.

## License
Copyright (c) ShadowGuardAI
