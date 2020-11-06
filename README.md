# Bulk activation script for OATH tokens within Azure
When you want to active a bulk of OATH tokens in Azure, you have to active each token seperatly by typing in the OTP code of the token. When you want to import a bunch of tokens this cost a lot of time and effort. (Boring, boring boring effort)

This script helps by activating all tokens via the "hidden" API in Azure. Please note, this function is not supported by Microsoft and can stop working any time when Microsoft changes their backend/API

## Howto

### Import the OATH CSV in Azure
To run the script, first import the CSV with OATH tokens in Azure as you would normally do. The CSV does contain the headers --> upn,serial number,secret key,time interval,manufacturer,model The same CSV can be used in the next step

### Run the script
Run the script OATHToken-MultiActivate.ps1 with the following parameters (if you don't fill in the parameters the script will prompt you to do so):
C:\OATHToken-MultiActivate.ps1 -tenantid 'aaa5b397-b4e6-4442-bce9-2663490e8114' -csv 'C:\tokens.csv'

The TenantID can be found in the "properties" tab of the Azure Active Directory GUI

The CSV is the full path to the CSV file which you also used to import OATH tokens in Azure

After you launcht he script, you will be prompted to authorize to Azure via the link https://microsoft.com/devicelogin + a code. Browse to the site with the code and login with you admin account. The script will detect when you logged in succesfully an contintue to activate the token

Let me know if you have any issues.
