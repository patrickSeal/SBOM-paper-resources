import json

import cdx_analysis as cdx

path = "./SBOM/EMBA/EMBA_03_cdx.json"

with open(path) as json_file:
    sbom = json.load(json_file)

cdx.full_analysis(sbom)