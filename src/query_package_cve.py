# DESCRIPTION
# This file contains functions surrounding the querying of CVEs of Golang packages.
# 
#
#

# EXAMPLE USAGE OF FUNCTIONS:

# query_package_for_cve('golang.org/x/text', '0.3.5')
# version_is_not_patched({ 'id': 'GO-2024-3038', 'modified': '2024-08-06T22:03:16Z', 'fixed': '0.7.1' }, golang.org/x/text, '0.3.5')

from requests import get
from re import search

import semver
import logging

PATH        = 'path'
VULNS       = 'vulns'
FIXED       = 'fixed'
ID          = 'id'
AFFECTED    = 'affected'
PACKAGE     = 'package'
NAME        = 'name'
RANGES      = 'RANGES'
EVENTS      = 'EVENTS'

# Different types 
INTRODUCED      = 'introduced'
FIXED           = 'fixed'
LAST_AFFECTED   = 'last_affected'
LIMIT           = 'limit'

PACKAGE_CVE_JSON = get('https://vuln.go.dev/index/modules.json').json()

# If a version patch number is missing, or is an unrecognized format, default to this
DEFAULT_TO_VULNERABLE = False
PACKAGE_CVE_MISSING_PATCH_VERSION = f'''A vulnerability is missing a patch version or has an unrecognized version format. 
        The vulnerability could still exist, defaulting to {'NOT ' if not DEFAULT_TO_VULNERABLE else ''}VULNERABLE!'''



# Returns a list of CVEs, if it's empty, then there were no CVEs to be found

# ARGUMENTS: 
# package_name: str     -- Name of the possibly affected package
# package_version: str  -- Version of the possibly affected package
def query_package_for_cve(package_name: str, package_version: str) -> list:
    entry_returned = filter(
                        lambda entry: package_name == entry.get(PATH),
                        PACKAGE_CVE_JSON
                    )   
    
    # if there was no entry, the __next__() will throw
    try: entry_returned = entry_returned.__next__()
    except: return []

    unpatched_vulns = filter(
                        lambda vuln: version_is_not_patched(vuln, package_name, package_version), 
                        entry_returned.get(VULNS)
                    )
    
    return list(unpatched_vulns)

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
    cve_info = get(f'https://vuln.go.dev/ID/{cve_identifier}.json').json()

    try:
        affected = filter(
                            lambda package: package.get(NAME) == package_name, 
                            cve_info.get[AFFECTED]
                        ).__next__()

        package_version = semver.Version.parse(package_version)
        vulnerable = False
        # I <3 nesting
        for range in affected.get(RANGES):
            for event in range.get(EVENTS):
                if introduced_version := event.get(INTRODUCED):
                    introduced_version = semver.Version.parse(introduced_version)
                    if package_version >= introduced_version: vulnerable = True

                elif fixed_version := event.get(FIXED):
                    fixed_version = semver.Version.parse(fixed_version)
                    if package_version >= fixed_version: vulnerable = False

                elif (last_affected_version := event.get(LAST_AFFECTED)):
                    last_affected_version = semver.Version.parse(last_affected_version)

                    if package_version > last_affected_version: vulnerable = False

                elif limit_version := event.get(LIMIT):
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

    return package_version < patched_version