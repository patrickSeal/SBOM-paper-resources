
def handle(name):
    print(f"[ERROR]: SBOM has no '{name}' property")

def full_analysis(sbom):
    print("Running full analysis...")
    print(f"Number of Duplicates: {checkforduplicates(sbom)}")
    # NTIA min requirements
    print("---- NTIA minimum requirements:")
    print_metadata(sbom)
    print(f"Number of Components: {get_number_of_components(sbom)}")
    print(f"Number of Components with PURL: {get_number_of_PURL(sbom)}")
    print(f"Number of Components with CPE: {get_number_of_CPE(sbom)}")
    print()

    # BSI guideline
    print("---- BSI guideline requirements:")
    contains_vulninfo(sbom)
    format_check(sbom)
    a = component_authors_check(sbom)
    l = component_has_license(sbom)
    h = component_has_hashes(sbom)
    print(f"Number of components with no author(s): {a}")
    print(f"Number of components with no license(s): {l}")
    print(f"Number of components with no hash(es): {h}")
    print(f"Number of components with a type: {components_with_type(sbom)}")
    print("----")
    list_components(sbom)

def list_components(sbom):
    for c in sbom['components']:
        if "version" not in c:
            print(f"{c['name']} HAS NO VERSION")
        else:
            print(f'{c['name']} {c['version']}')

# metadata minimum requirements NTIA
def print_metadata(sbom):
    if "metadata" not in sbom:
        handle("metadata")
        return
    metadata = sbom['metadata']
    if "timestamp" in metadata:
        print(f"Has timestamp: {metadata['timestamp']}")
    else:
        handle("timestamp")

    if "tools" in metadata:
        print(f"Has Creator of component: {metadata['tools']}")
        if "supplier" in metadata:
            print(f"Supplier: {metadata['supplier']}")
        else:
            handle("supplier")
    else:
        handle("tools")

def get_number_of_components(sbom):
    return len(sbom['components'])

def get_number_of_PURL(sbom):
    n = 0
    for c in sbom['components']:
        if "purl" in c:
            n += 1
            continue  
        print(f"[INFO] {c['name']} has no PURL")
    return n

def get_number_of_CPE(sbom):
    n = 0
    for c in sbom['components']:
        if "cpe" in c:
            if c['cpe'][:3] == "cpe":
                n += 1
                continue
        print(f"[INFO] {c['name']} has no CPE")
    return n

def contains_vulninfo(sbom):
    if "vulnerabilities" in sbom:
        print("[BSI VIOLATION] SBOM contains Vulnerability Information")
    else:
        print("[BSI] SBOM does NOT contain Vulnerability Information +1")

def format_check(sbom):
    if "bomFormat" in sbom and "specVersion" in sbom:
        print(f"[BSI] SBOM format: {sbom['bomFormat']} {sbom['specVersion']}")
    else:
        print(f"[BSI VIOLATION] SBOM has no Format or Spec Identifier.")

def component_authors_check(sbom):
    viols = 0
    for c in sbom['components']:
        if "authors" in c or "author" in c or "publisher" in c or "supplier" in c:
            x = 1
            #print("ADDITIONAL CHECK NEEDED!")
        else:
            print(f"[BSI VIOLATION]: {c['name']} has no author(s)")
            viols += 1
    return viols

def component_has_license(sbom):
    viols = 0
    for c in sbom['components']:
        if "licenses" in c:
            x = 1
            #print(f"[BSI]: {c['name']} has license information")
        else:
            print(f"[BSI VIOLATION]: {c['name']} has no license information")
            viols += 1
    return viols

def component_has_hashes(sbom):
    viols = 0
    for c in sbom['components']:
        if "hashes" in c:
            x = 1
            #print(f"[BSI]: {c['name']} has hashes information")
        else:
            print(f"[BSI VIOLATION]: {c['name']} has no hashes information")
            viols += 1
    return viols

def components_with_type(sbom):
    n = 0
    for c in sbom['components']:
        if "type" in c:
            n += 1

    return n

def checkforduplicates(sbom):
    name = ""
    version = ""
    dups = 0
    for c in sbom['components']:
        name = c['name']
        if "version" in c:
            version = c['version']
        else:
            version = 0
        current = 0
        for c2 in sbom['components']:
            if "version" in c2:
                if c2['name'] == name and c2['version'] == version:
                    current += 1
            else:
                if c2['name'] == name:
                    current += 1
        
        if current > 1:
            dups += 1

    return dups


