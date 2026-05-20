# DESCRIPTION
# The entry point for the program. 
# Run it by $ python3 main.py <path>

from dependency_finder import get_dependencies                  # get_dependencies(path=".")
from package_capability_scan import get_package_capability      # get_package_capability(package_name: str) -> str
from query_package_cve import query_package_for_cve             # query_package_for_cve(package_name: str, package_version: str) -> list
from string_analysis import scan_go_source                      # scan_go_source(source)

from sys import argv
from pathlib import Path


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

    for dependency in dependencies:
        package_name = dependency[PACKAGE_NAME]
        capabilities.append((package_name, get_package_capability(package_name)))

    return capabilities


def get_string_analysis(golang_files: list) -> list:
    string_analysis = []

    for golang_file in golang_files:
        with open(golang_file, 'r') as file:
            content = file.read()
        string_analysis.append((golang_file, scan_go_source(content)))
    
    return string_analysis
        

def main(path='.'):
    try: path = argv[1]
    except: pass

    golang_files = get_all_golang_files(path)

    # Remove dependencies wihtout versions
    dependencies = list(filter(lambda package: package.get(VERSION, None) is not None, get_dependencies(path)))

    # Returns [(package name, list of CVEs)]
    package_cves = get_cves(dependencies)

    # Returns [(package_name, capability)]
    package_capabilities = get_package_capabilities(dependencies)

    # Returns [(go file path, string analysis)]
    string_analysis = get_string_analysis(golang_files)

    print(package_cves)
    print(package_capabilities)
    print(string_analysis)



if __name__ == '__main__':
    main()