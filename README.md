# Langsec-Golang-Dependency-Checker

## How to use
- Locally: `python3 main.py [path] [--sarif] [--output]`
    - The path should be the root of the Go project
    - Use the sarif flag if you want it printed in that format
        - If using the sarif flag, the output flag can be specified for exporting to a specified file
    - Without the sarif and output flags, the output will be in the terminal only
- Manual update of local database: `python3 update.py`
- Github enumeration/comparison
    - For repo enumeration: `python3 run_tools.py`
    - For comparison: `python3 compare_reports.py`