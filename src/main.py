# DESCRIPTION
# The entry point for the program. 
# Run it by $ python3 main.py <path>

from dependency_finder import get_dependencies                                      # get_dependencies(path=".")
from package_capability_scan import get_package_capability                          # get_package_capability(package_name: str) -> str
from query_package_cve import query_package_for_cve                                 # query_package_for_cve(package_name: str, package_version: str) -> list
from string_analysis import scan_go_source                                          # scan_go_source(source)
from update import check_for_updates                                                # check_for_updates()
from terminal_print import print_cves, print_capabilities, print_string_analysis    # print_cves(package_cves), print_capabilities(package_capabilities), print_string_analysis(string_analysis)
from export import save_sarif_report, create_sarif_report
from sys import argv
from pathlib import Path

import argparse
import re

VERSION = 'Version'
PACKAGE_NAME = 'Path'
GO_PATTERN = '*.go'

def get_all_golang_files(root_path: str) -> list:
    go_files = filter(lambda path: path.is_file(), Path(root_path).rglob(GO_PATTERN, case_sensitive=False))
    go_filepaths = map(lambda file: file.resolve().as_posix(), go_files)

    return list(go_filepaths)


def get_cves(dependencies: dict) -> list:
    cves = []

    for dependency in dependencies:
        package_name = dependency[PACKAGE_NAME]    
        package_version = dependency[VERSION]

        package_cve = query_package_for_cve(package_name, package_version)
        cves.append((package_name, package_version, package_cve))
    
    return cves

def get_package_capabilities(dependencies: dict) -> dict:
    capabilities = []
    packages = []
    for dependency in dependencies:
        package_name = dependency[PACKAGE_NAME]
        if not package_name in packages: 
            capabilities.append((package_name, get_package_capability(package_name)))
            packages.append(package_name)

    return capabilities

def get_string_analysis(golang_files: list) -> list:
    string_analysis = []

    for golang_file in golang_files:
        with open(golang_file, 'r') as file:
            content = file.read()
        string_analysis.append((golang_file, scan_go_source(content)))
    
    return string_analysis
        
def main(path='.'):
    parser = argparse.ArgumentParser(
        description="Langsec Golang Dependency Checker"
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to scan"
    )
    parser.add_argument(
        "--sarif",
        action="store_true",
        help="Export SARIF report instead of printing"
    )
    parser.add_argument(
        "--output",
        default="report.sarif",
        help="SARIF output file"
    )
    args = parser.parse_args()
    path = args.path

    golang_files = get_all_golang_files(path)

    # Update local database
    check_for_updates()
    # Remove dependencies wihtout versions
    dependencies = list(filter(lambda package: package.get(VERSION, None) is not None, get_dependencies(path)))

    # Returns [(package name, list of CVEs)]
    package_cves = get_cves(dependencies)

    # Returns [(package_name, capability)]
    package_capabilities = get_package_capabilities(dependencies)

    # Returns [(go file path, string analysis)]
    string_analysis = get_string_analysis(golang_files)

    if args.sarif:
        report = create_sarif_report(package_cves, package_capabilities, string_analysis)
        save_sarif_report(report, args.output)
    else:
        print_cves(package_cves)
        print_capabilities(package_capabilities)
        print_string_analysis(string_analysis)

if __name__ == '__main__':
    main()