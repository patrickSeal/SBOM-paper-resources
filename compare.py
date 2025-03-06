import json

emba01 = "./SBOM/EMBA/EMBA_01_cdx.json"
emba02 = "./SBOM/EMBA/EMBA_02_cdx.json"
emba03 = "./SBOM/EMBA/EMBA_03_cdx.json"

syft01 = "./SBOM/Syft/Syft_01_cdx.json"
syft02 = "./SBOM/Syft/Syft_02_cdx.json"
syft03 = "./SBOM/Syft/Syft_03_cdx.json"

trivy01 = "./SBOM/Trivy/Trivy_01_cdx.json"
trivy02 = "./SBOM/Trivy/Trivy_02_cdx.json"
trivy03 = "./SBOM/Trivy/Trivy_03_cdx.json"

path1 = emba03
path2 = syft03

def compareComps(sbom1, sbom2):
    equal = 0
    for c in sbom1['components']:
        name = c['name']
        version = 0
        if "version" in c:
            version = c['version']
        found = False
        for c2 in sbom2['components']:

            if c2['name'] == name:
                versionc2 = 0
                if "version" in c2:
                    versionc2 = c2['version']

                if version == versionc2:
                    x = 1
                else:
                    print(f"SBOM_2 contains {c['name']} with different version {versionc2} instead of {version}")
                found = True
                break
        if found:
            equal += 1
            continue
        print(f"SBOM_2 does not contain {c['name']}")
    
    print(f"Number of equal components: {equal}")


with open(path1) as json_file:
    sbom1 = json.load(json_file)

with open(path2) as json_file:
    sbom2 = json.load(json_file)

compareComps(sbom1, sbom2)
print("-------------------------------------------------------")
compareComps(sbom2, sbom1)