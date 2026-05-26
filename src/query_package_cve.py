# DESCRIPTION
# This file contains functions surrounding the querying of CVEs of Golang packages.
# The documentation of the database can be found at https://go.dev/doc/security/vuln/database.
# For the structure of the data, check out https://ossf.github.io/osv-schema
#

# EXAMPLE USAGE OF FUNCTIONS:

# query_package_for_cve('golang.org/x/text', '0.3.5')
# version_is_not_patched({ 'id': 'GO-2024-3038', 'modified': '2024-08-06T22:03:16Z', 'fixed': '0.7.1' }, golang.org/x/text, '0.3.5')

from requests import get
from re import search

import semver
import logging
import json
import os

# Keys 
PATH        = 'path'
VULNS       = 'vulns'
FIXED       = 'fixed'
ID          = 'id'
AFFECTED    = 'affected'
PACKAGE     = 'package'
NAME        = 'name'
RANGES      = 'ranges'
EVENTS      = 'events'

# Different types 
INTRODUCED      = 'introduced'
FIXED           = 'fixed'
LAST_AFFECTED   = 'last_affected'
LIMIT           = 'limit'

# Paths to required files
MODULES_PATH = os.path.join(os.path.dirname(__file__), "data", "modules.json")
CVE_PATH = os.path.join(os.path.dirname(__file__), "data", "ID")


def get_dict_by_cve(cve_id: str) -> dict:     
    with open(os.path.join(CVE_PATH, f'{cve_id}.json'), 'r') as file:
        return json.load(file)
    
def get_modules():
    with open(MODULES_PATH, 'r') as file:
        return json.load(file)

PACKAGE_CVE_JSON = get_modules()

# If a version patch number is missing, or is an unrecognized format, default to this
DEFAULT_TO_VULNERABLE = False

PACKAGE_CVE_MISSING_PATCH_VERSION = f'''A vulnerability is missing a patch version or has an unrecognized version format. 
        The vulnerability could still exist, defaulting to {'NOT ' if not DEFAULT_TO_VULNERABLE else ''}VULNERABLE!'''
OPEN_FILE_ERROR = f'Couldn\'t open a CVE file, defaulting to {'NOT ' if not DEFAULT_TO_VULNERABLE else ''} VULNERABLE!' 


# Returns a list of CVEs, if it's empty, then there were no CVEs to be found

# ARGUMENTS: 
# package_name: str     -- Name of the possibly affected package
# package_version: str  -- Version of the possibly affected package
def query_package_for_cve(package_name: str, package_version: str) -> list:
    entry_returned = next(filter(
                        lambda entry: package_name == entry.get(PATH),
                        PACKAGE_CVE_JSON
                    ), None)
    
    # if there was no entry, there was no exploit to bgein with
    if (entry_returned is None): return []

    unpatched_vulns = list(filter(
                        lambda vuln: version_is_not_patched(vuln, package_name, package_version), 
                        entry_returned.get(VULNS)
                    ))

    # Get the actual CVEs and GHSAs linked to the Go vulnerabilities
    go_ids = list(map(lambda vuln: vuln.get(ID), unpatched_vulns))
    result = []
    for go_id in go_ids:
        try:
            vuln_data  = get_dict_by_cve(go_id)
            aliases = vuln_data.get("aliases", [])
        except:
            aliases = []
        
        result.append({
            "go_id": go_id,
            "aliases": aliases
        })
    return result

# Returns true if the package version is below the patched version.
# In the case that the version is missing or is using an unrecognized format,
# we might consider it still vulnerable, it depends on DEFAULT_TO_VULNERABLE. 
# However, we do display a warning either way

# ARGUMENTS: 
# vulnerability: dict   -- The dictionary of the vulnerability
# package_name: str     -- Name of the possibly affected package
# package_version: str  -- Version of the possibly affected package
def version_is_not_patched(vulnerability: dict, package_name: str, package_version: str) -> bool:
    cve_identifier = vulnerability.get(ID)
    package_version = package_version.removeprefix('v')

    try: cve_info = get_dict_by_cve(cve_identifier)
    except: 
        warning_msg = OPEN_FILE_ERROR
        if (cve_identifier is not None): warning_msg += f' ({cve_identifier})'

        logging.warning(warning_msg)
        return DEFAULT_TO_VULNERABLE

    affected = next(filter(
                        lambda package: package.get(PACKAGE).get(NAME) == package_name, 
                        cve_info.get(AFFECTED)
                    ), None)

    package_version = semver.Version.parse(package_version)

    try:
        vulnerable = False
        # I <3 nesting
        for range in affected.get(RANGES):
            for event in range.get(EVENTS):
                if introduced_version := event.get(INTRODUCED):
                    if (introduced_version == '0'): introduced_version = '0.0.0'

                    introduced_version = semver.Version.parse(introduced_version)
                    if package_version >= introduced_version: vulnerable = True

                elif fixed_version := event.get(FIXED):
                    if (fixed_version == '0'): fixed_version_version = '0.0.0'

                    fixed_version = semver.Version.parse(fixed_version)
                    if package_version >= fixed_version: vulnerable = False

                elif (last_affected_version := event.get(LAST_AFFECTED)):
                    if (last_affected_version == '0'): last_affected_version = '0.0.0'

                    last_affected_version = semver.Version.parse(last_affected_version)
                    if package_version > last_affected_version: vulnerable = False

                elif limit_version := event.get(LIMIT):
                    if (limit_version == '0'): limit_version = '0.0.0'

                    limit_version = semver.Version.parse(limit_version)
                    if (package_version >= limit_version): vulnerable = False

                else:
                    pass
            
            if (vulnerable): return True

        return vulnerable
    
    except:
        warning_msg = PACKAGE_CVE_MISSING_PATCH_VERSION
        if (cve_identifier is not None): warning_msg += f' ({cve_identifier})'

        logging.warning(warning_msg)
        return DEFAULT_TO_VULNERABLE