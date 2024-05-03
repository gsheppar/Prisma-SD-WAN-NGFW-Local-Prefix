# Prisma SD-WAN NGFW Local Prefix (Preview)
The purpose of this script is to help with Local Prefixs for NGFW policies

* Export to a CSV legacy security statck local prefixes from a site
* create NGFW local security prefixes from a CSV

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py

 1. ./GetLocalPrefixes.py -S Home-Office
      - Will export all the local security prefixes for this site

 2. ./DeployNGFWLocalPrefixes.py -F site_local_prefix.csv
      - Will deploy all the NGFW local prefixes from the csv

### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>

