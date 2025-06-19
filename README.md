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

## License
Copyright (c) ShadowGuardAI
