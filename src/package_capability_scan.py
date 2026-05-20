# DESCRIPTION
# Script which gathers the capabilities of different packages. 
# This includes capabilities such as network or exec capabilities.

PACKAGE_CAPABILITY_PATH = './data/package-capabilities.txt'

def INIT_PACKAGE_CAPABILITIES() -> list:
    with open(PACKAGE_CAPABILITY_PATH, 'r') as file:
        content = file.read()
    
    package_info = content.split('\n')

    # returns [(package_name, package_capability)]
    return list(map(lambda package: (package.split()[1], package.split()[2]), package_info))

CAPABILITY_UNSPECIFIED          = 'CAPABILITY_UNSPECIFIED'
CAPABILITY_SAFE                 = 'CAPABILITY_SAFE'
CAPABILITY_FILES                = 'CAPABILITY_FILES'
CAPABILITY_NETWORK              = 'CAPABILITY_NETWORK'
CAPABILITY_RUNTIME              = 'CAPABILITY_RUNTIME'
CAPABILITY_READ_SYSTEM_STATE    = 'CAPABILITY_READ_SYSTEM_STATE'
CAPABILITY_MODIFY_SYSTEM_STATE  = 'CAPABILITY_MODIFY_SYSTEM_STATE'
CAPABILITY_OPERATING_SYSTEM     = 'CAPABILITY_OPERATING_SYSTEM'
CAPABILITY_SYSTEM_CALLS         = 'CAPABILITY_SYSTEM_CALLS'
CAPABILITY_ARBITRARY_EXECUTION  = 'CAPABILITY_ARBITRARY_EXECUTION'
CAPABILITY_CGO                  = 'CAPABILITY_CGO'
CAPABILITY_UNANALYZED           = 'CAPABILITY_UNANALYZED'
CAPABILITY_UNSAFE_POINTER       = 'CAPABILITY_UNSAFE_POINTER'
CAPABILITY_REFLECT              = 'CAPABILITY_REFLECT'
CAPABILITY_EXEC                 = 'CAPABILITY_EXEC'

PACKAGE_CAPABILITIES = INIT_PACKAGE_CAPABILITIES()

def get_package_capability(package_name: str) -> str:
    capability = next(filter(
        lambda package_info: package_name == package_info[0], PACKAGE_CAPABILITIES
    ), None)

    if (capability is None): return CAPABILITY_UNSPECIFIED

    return capability[1]