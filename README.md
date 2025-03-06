# SBOM paper resources

A collection of tools used for analyzing SBOMs in CycloneDX format.

## General Information

This repository presents the resources used by the case study in the paper "Software Bill of Materials from Open Source Tools. Can businesses rely on their results?". It was
written as part of the conference seminar "IT Security" which was organized by the IT Security Infrastructures Lab at the Friedrich-Alexander-University Erlangen-Nürnberg (FAU)
during the winter term 2025. In case the paper gets published, it will be uploaded here.

## Sources

The scripts were used specifically for the paper and are therefore neither optimized nor is their output in an easy to read way.
They can give a good overview of the quality of a CDX SBOM, however they do not check specific values, e.g. "unknown", "null", etc., to determine the accuracy of the information contained in the SBOM,
therefore it would be advisable to add vendor specific <unknown> values for a more accurate analysis, because some SBOM vendors do include properties even though their values are false or unknown.

### compare.py

This python script can be used to see the difference in components between two CycloneDX SBOMs.
To run the script, change the "path1"/"path2" variable to your SBOMs paths.

### main.py and cdx_analysis.py

The "main.py" script just opens an SBOM file. The main analysis is done using the functions in the cdx_analysis.py file.
It provides multiple functions to check the format of the SBOM, as well as the number of components having a specific attribute (e.g.: PURL, CPE, author, version, ...).
To run a full analysis of an SBOM, change the "path" variable in the main.py file and execute it. It will run a full analysis by default (using all the provided functions in the cdx_analysis.py file).
