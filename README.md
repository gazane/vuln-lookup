# Vulnerability Lookup
## Video Demo: https://youtu.be/79FaINTEqQE
## Description:
#### 
#### The Vulnerability Lookup tool script takes a CSV inventory file as input, which contains a list of operating systems details (Vendor, Version, Edition, and CPE Name). It then searches for vulnerabilities for each operating system listed in the inventory.
#### 
#### The inventory CSV file must be in the same folder as the script and must have the following header: Asset ID, Vendor, Operating System, Version, Update, Edition, CPE Name.
#### 
#### CPE (Common Platform Enumeration) is a structured naming scheme for information technology systems, software, and packages. For more details on CPEs, please refer to [CPE on NVD](https://nvd.nist.gov/products/cpe).
#### 
#### The script will create an output CSV file in the same folder with the following headers: Asset ID, CPE Name, CVE ID, CVE Score, CVE URL.
#### 
#### CVE (Common Vulnerabilities and Exposures) Program from the National Vulnerability Database uniquely identifies vulnerabilities and associates CPEs with those vulnerabilities. For detailed information regarding CVE, please refer to [CVE](https://cve.org/).
####
### Stpes performed by the script
####
#### 1. CPE Name Validation: Before looking for vulnerabilities, the script first checks if the CPE Name is valid because the CPE is used to look for vulnerabilities. It calls a function check_cpe and provides the CPE Name from the inventory. If the CPE Name is valid, the function returns True; otherwise, it returns False.
#### 2. Finding a Valid CPE Name:
####    - If check_cpe returns False, the script calls the function get_cpe to try to find a valid CPE Name.
####    - The get_cpe function uses the following keys from the inventory: Vendor, Operating System, Version, and Edition.
####    - It merges these parameters into a variable and makes a GET request to the following URL:
####          h<span>ttps://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch= + search variable + "&resultsPerPage=1"
####    - The goal is to provide keywords for the search and obtain one CPE Name. This function can return:
####      -- "CPE not found" – If no matches were found for the given parameters.
####      -- "No response" – If no response was received from the server.
####      -- A valid CPE Name.
####  3. Getting Vulnerabilities:
####     - The script then calls the function get_cve to get the vulnerabilities associated with the CPE Name. It provides the following variables: Asset ID, CPE Name, and output CSV file.
####     - This function tries to find vulnerabilities associated with the CPE Name and appends the results to the output CSV file.
####     - The function returns the total number of identified vulnerabilities. If it returns -1, it means the CPE Name was not found, and it prints a message on the screen for the user to review the CPE Name in the inventory. If it returns False, it means it was not possible to get a response from the server. The script tries twice to get a response; if not successful, it will print the message "Unable to get the CPE Name from the server".
####
#### The script processes all rows of the inventory CSV file and ends after completing the checks for each entry.
