import sys
import csv
import os
import nvdlib
import time
from datetime import date
import re
import requests
import json


def main():
    
    #Get the directory path and add the inventory CSV file to the path
    dir_path = os.path.dirname(os.path.abspath(__file__))
    inventory = dir_path + "\os_inventory.csv"
    
    #Get todays date to include in the output file
    today = date.today()
    outputcsv = dir_path + "\\" + str(today.year) + str(today.month) + str(today.day) + "_CVE_Scan.csv"

    #Create Vulnerabilities CSV File (Output)
    with open(outputcsv, "w", newline="") as cvefile:
            writer = csv.DictWriter(cvefile, fieldnames=["Asset ID", "CPE Name", "CVE ID", "CVE Score", "CVE URL"])
            writer.writeheader()

    #Open the Inventory CSV file (Input)
    try:
        with open(inventory, "r") as invfile:
            reader = csv.DictReader(invfile)
            for row in reader:
                #Get the CPE name
                print("Asset ID:", row["Asset ID"])
                cpe = (row["CPE Name"])
                
                #If CPE is not blank, call the "check_cpe" function to check if the CPE is valid
                if not cpe == "":
                    check = check_cpe(cpe)
                
                #If CPE is blank or the result of check_cpe is False, call the "get_cpe" function to search for the CPE Name using the Vendor, Operating System, Version and Edition data
                if cpe == "" or check == False:
                    print("          - Invalid CPE")
                    cpe = get_cpe(row["Vendor"], row["Operating System"], row["Version"], row["Edition"])
                print("          - CPE Name:", cpe)
                
                #Look for CVEs by calling the "get_cve" function
                total_cve = get_cve(row["Asset ID"], cpe, outputcsv)
                
                #If it was not possible to search for vulnerabilities, wait 7 seconds and try again
                if total_cve == False:
                    print("          - Unable to search for vulnerabilities for this asset")
                    print("          - Trying again ...")
                    time.sleep(7)
                    total_cve = get_cve(row["Asset ID"], cpe, outputcsv)
                
                if total_cve == False:
                    print("          - Unable to search for vulnerabilities for this asset")
                elif total_cve == -1 and cpe == "No response":
                    print("          - Unable to get the CPE Name from the server")
                elif total_cve == -1 and cpe == "CPE not found":
                    print("          - CPE not found, please review the inventory data")
                elif total_cve == 0:
                    print("          - No vulnerabilities found for this asset")
                elif total_cve == 1:
                    print("          - 1 vulnerability found for this asset")
                else:
                    print(f"          - {total_cve} vulnerabilities found for this asset")
                             
    except(FileNotFoundError):
        sys.exit("Could not read inventory")

    print("End of Scan")


def check_cpe(cpe):
    print("          - Checking CPE")

    #Try to find a match with the CPE Name of the Inventory, if CPE Names exists, return True, otherwise it will return False
    try:
        #Due to rate limiting restrictions by NVD, it is required to wait 6 seconds for the next request if you dont have an API key 
        time.sleep(7)
        r = nvdlib.searchCPE(cpeMatchString= cpe, limit=1)
        for eachCPE in r:
            cpe = eachCPE.cpeName
            return True
    
    except:
        return False


def get_cpe(vendor, os, version, edition):
    print("          - Getting CPE")

    #Due to rate limiting restrictions by NVD, it is required to wait 6 seconds for the next request if you dont have an API key
    time.sleep(7)

    #Based on the data from inventory, define the parameters to search for the CPE Name
    if (os != "") and (version != "") and (edition != ""):
        search = vendor + " " + os + " " + version + " " + edition
    elif (os != "") and (version != ""):
        search = vendor + " " + os + " " + version
    else:
        search = vendor + " " + os
    
    #Get the response from the NVD Server
    search = search.replace(" ", "%20")
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=" + search + "&resultsPerPage=1"
    r = requests.get(url)
    try:
        response = r.json()
        
        #Store response in a string and use Regular Expression to find the CPE Name by capturing matches
        cpe_str = json.dumps(response)
        if matches := re.search(r"\"cpeName\":\s\"(cpe:2.3:.+\*)\",\s", cpe_str):
            cpe = matches.group(1)
        else:
            cpe = "CPE not found"

    except requests.exceptions.JSONDecodeError:
        cpe = "No response"

    return cpe


def get_cve(id, cpe, csvfile):
    print("          - Looking for Vulnerabilities")
    counter = 0

    #Due to rate limiting restrictions by NVD, it is required to wait 6 seconds for the next request if you dont have an API key
    time.sleep(7)
    
    #Open the Output file and store the CVEs for the provided CPE Name and returns the number of identified vulnerabilities
    try:
        with open(csvfile, "a", newline="") as cvefile:
            if (cpe != "CPE not found") or (cpe != "No response"):
                r = nvdlib.searchCVE(cpeName = cpe)
                for eachCVE in r:
                    cve_data = id + "," + cpe + "," + eachCVE.id + "," + str(eachCVE.score[2]) + "," + eachCVE.url + "\r\n"
                    cvefile.write(cve_data)
                    counter = counter + 1
            else:
                cve_data = id + "," + cpe + "," + "," + ","
                cvefile.write(cve_data)
                counter = -1

            return counter
    
    except:
        return False

if __name__ == "__main__":
    main()