# DESCRIPTION
# This file contains functions surrounding the querying of CVEs of Golang packages.
# 
#
#

# EXAMPLE USAGE OF FUNCTIONS:

# query_package_for_cve('golang.org/x/text', '0.3.5')
# version_is_not_patched({ 'id': 'GO-2024-3038', 'modified': '2024-08-06T22:03:16Z', 'fixed': '0.7.1' }, '0.3.5')

from requests import get
from packaging import version
import logging

PACKAGE_CVE_JSON = get('https://vuln.go.dev/index/modules.json').json()
# If a version patch number is missing, or is an unrecognized format, default to this
DEFAULT_TO_VULNERABLE = False
PACKAGE_CVE_MISSING_PATCH_VERSION = f'''A vulnerability is missing a patch version or has an unrecognized version format. 
        The vulnerability could still exist, defaulting to {'NOT ' if DEFAULT_TO_VULNERABLE else ''}VULNERABLE!'''

PATH = 'path'
VULNS = 'vulns'
FIXED = 'fixed'
ID = 'id'


# Returns a list of CVEs, if it's empty, then there were no CVEs to be found
def query_package_for_cve(package_name: str, package_version: str) -> list:
    entry_returned = filter(
                        lambda entry: package_name == entry.get(PATH),
                        PACKAGE_CVE_JSON
                    )   
    
    # if there was no entry, the __next__() will throw
    try: entry_returned = entry_returned.__next__()
    except: return []

    unpatched_vulns = filter(
                        lambda vuln: version_is_not_patched(vuln, package_version), 
                        entry_returned[VULNS]
                    )
    
    return list(unpatched_vulns)

# Returns true if the package version is below the patched version.
# In the case that the version is missing or is using an unrecognized format,
# we might consider it still vulnerable, it depends on DEFAULT_TO_VULNERABLE. 
# However, we do display a warning either way
def version_is_not_patched(vulnerability: dict, package_version: str) -> bool:
    patched_version = vulnerability.get(FIXED)
    cve_identifier = vulnerability.get(ID)

    try: 
        package_version = version.parse(package_version)
        patched_version = version.parse(patched_version)
    except:
        warning_msg = PACKAGE_CVE_MISSING_PATCH_VERSION
        if (cve_identifier is not None): warning_msg += f' ({cve_identifier})'

        logging.warning(warning_msg)
        return DEFAULT_TO_VULNERABLE

    return package_version < patched_version