CPanel Credential Checker
========================

Description
-----------
CPanel Credential Checker is a Python script that validates CPanel login credentials by attempting to log in to the CPanel interface. It supports multiple credential formats, checks both HTTPS and HTTP protocols, and verifies domain accessibility and WHM access when available.

Requirements
------------
- Python 3.7 or higher
- Internet connection

Required Python libraries:
- requests
- urllib3

Install dependencies:
pip install requests urllib3

Files
-----
- checker.py        (main script)
- input.txt         (credentials input file)
- output.txt        (valid credentials output file)

Credential Formats Supported
----------------------------
Each credential must be on a single line in the input file.

Supported formats:
- domain.com:username:password
- https://domain.com:username:password
- domain.com:2083:username:password
- https://domain.com:2083/cpsessXXXX/frontend/index.html:username:password
- domain.com|username|password
- https://domain.com|username|password

How to Use
----------
1. Prepare input file

Create a text file (example: input.txt) and search the credentials with 2083 port or 2082 port:

domain.com:cpuser:cppassword
https://example.com|admin|secret123
domain.com:2083:root:mypassword

2. Run the script

Basic usage:
python checker.py --input input.txt --output output.txt

With custom thread count:
python checker.py --input input.txt --output output.txt --threads 50

3. Check results

Valid credentials are written to the output file in real time.

Output Format
-------------
Each valid result appears like:

original_input   [https://domain.com][real-domain.com][DOMAIN WORK][WHM]

Possible status values:
- DOMAIN WORK / DOMAIN NOT WORK
- CPANEL / WHM

If no valid credentials are found:
# No valid credentials found

Behavior Notes
--------------
- Tries HTTPS first, then HTTP
- Uses port 2083 for CPanel and 2087 for WHM
- Avoids duplicate successful checks
- Multi-threaded processing
- Automatically follows redirects
- SSL verification is disabled

Common Issues
-------------
- Ensure correct credential format
- Check internet connectivity
- Verify input file path

Example Command
---------------
python checker.py --input creds.txt --output valid.txt --threads 50
