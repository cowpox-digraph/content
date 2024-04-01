"""HelloWorld Feed Integration for Cortex XSOAR - Unit Tests file

This file contains the Unit Tests for the HelloWorld Integration based
on pytest. Cortex XSOAR contribution requirements mandate that every
integration, as well as a feed integration, should have a proper set of unit
tests to automatically verify that the integration is behaving as expected
during CI/CD pipeline.

Test Execution
--------------

Unit tests can be checked in 3 ways:
- Using the command `lint` of demisto-sdk. The command will build a dedicated
  docker instance for your feed integration locally and use the docker instance to
  execute your tests in a dedicated docker instance.
- From the command line using `pytest -v` or `pytest -vv`
- From PyCharm

Example with demisto-sdk (from the content root directory):
demisto-sdk lint -i Packs/HelloWorld/Integrations/FeedHelloWorld

Coverage
--------

There should be at least one unit test per command function. In each unit
test, the target command function is executed with specific parameters and the
output of the command function is checked against an expected output.

Unit tests should be self contained and should not interact with external
resources like (API, devices, ...). To isolate the code from external resources
you need to mock the API of the external resource using pytest-mock:
https://github.com/pytest-dev/pytest-mock/

In the following code we configure requests-mock (a mock of Python requests)
before each test to simulate the API calls to the FeedHelloWorld API (which is
OpenPhish). This way we can have full control of the API behavior and focus only
on testing the logic inside the integration code.

We recommend to use outputs from the API calls and use them to compare the
results when possible. See the ``test_data`` directory that contains the data
we use for comparison, in order to reduce the complexity of the unit tests and
avoding to manually mock all the fields.

NOTE: we do not have to import or build a requests-mock instance explicitly.
requests-mock library uses a pytest specific mechanism to provide a
requests_mock instance to any function with an argument named requests_mock.

More Details
------------

More information about Unit Tests in Cortex XSOAR:
https://xsoar.pan.dev/docs/integrations/unit-testing

"""

from CommonServerPython import string_to_table_header, tableToMarkdown
# from demisto_sdk.commands.common.handlers import JSON_Handler


import json

from Packs.FeedGithub.Integrations.FeedGithub.FeedGitHub import get_yara_indicator, parse_and_map_yara_content, extract_indicators


URL = "https://openphish.com/feed.txt"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# def doibnttest_build_iterator(requests_mock):
#     """

#     Given:
#         - Output of the feed API
#     When:
#         - When calling fetch_indicators or get_indicators
#     Then:
#         - Returns a list of the indicators parsed from the API's response

#     """
#     with open("test_data/FeedHelloWorld_mock.txt") as file:
#         response = file.read()
#     requests_mock.get(URL, text=response)
#     expected_url = "https://url1.com"
#     client = Client(
#         base_url=URL,
#         verify=False,
#         proxy=False,
#     )
#     indicators = client.build_iterator()
#     url_indicators = {
#         indicator["value"] for indicator in indicators if indicator["type"] == "URL"
#     }
#     assert expected_url in url_indicators


# def test_fetch_indicators(mocker):
#     """

#     Given:
#         - Output of the feed API as list
#     When:
#         - Fetching indicators from the API
#     Then:
#         - Create indicator objects list

#     """
#     client = Client(base_url=URL)
#     mocker.patch.object(
#         Client,
#         "build_iterator",
#         return_value=util_load_json("./test_data/build_iterator_results.json"),
#     )
#     results = fetch_indicators_command(client, params={"tlp_color": "RED"})
#     assert results == util_load_json("./test_data/get_indicators_command_results.json")


# def test_get_indicators_command(mocker):
#     """

#     Given:
#         - Output of the feed API as list
#     When:
#         - Getting a limited number of indicators from the API
#     Then:
#         - Return results as war-room entry

#     """
#     client = Client(base_url=URL)
#     indicators_list = util_load_json("./test_data/build_iterator_results.json")[:10]
#     mocker.patch.object(Client, "build_iterator", return_value=indicators_list)
#     results = get_indicators_command(
#         client, params={"tlp_color": "RED"}, args={"limit": "10"}
#     )
#     human_readable = tableToMarkdown(
#         "Indicators from HelloWorld Feed:",
#         indicators_list,
#         headers=["value", "type"],
#         headerTransform=string_to_table_header,
#         removeNull=True,
#     )
#     assert results.readable_output == human_readable
    
    
def test_extractindicators():
    text_content = """
    2023-07-12 (WEDNESDAY): GOZI/ISFB INFECTION WITH COBALT STRIKE

REFERENCE:

- https://twitter.com/Unit42_Intel/status/1679500766858432512

ASSOCIATED MALWARE:

- SHA256 hash: 620bc1e016887d7761907a85d49870a832b70e0340f599b472bec0a11b7b663a
- File size: 613,888 bytes
- File type: PE32 executable (DLL) (GUI) Intel 80386 (stripped to external PDB), for MS Windows
- File description: 32-bit Windows DLL for Gozi/ISFB, Botnet 2100, build 250259
- Run method: regsvr32.exe [filename]

- SHA256 hash: 540dfbef1bc65462cac88ad24a6d5cea867d9b392e9f8ae66c20ee49f4002793
- File size: 1,578,496 bytes
- File type: PE32+ executable (DLL) (GUI) x86-64 (stripped to external PDB), for MS Windows
- File location: hxxps://softwaredw[.]com/64HTTPS.dll
- Saved location: C:\Windows\Tasks\x11ogwin.dll
- File description: 64-bit Windows DLL for Cobalt Strike stager
- Run method: start-process rundll32.exe -ArgumentList '/s c:\windows\tasks\x11ogwin.dll,recurring'

TRAFFIC FROM AN INFECTED WINDOWS HOST:

GOZI/ISFB C2 TRAFFIC:

- 151.248.117[.]244 port 80 - diwdjndsfnj[.]ru - GET /uploaded/[long base64 string with backslashes and underscores].pct
- 151.248.117[.]244 port 80 - diwdjndsfnj[.]ru - POST /uploaded/[long base64 string with backslashes and underscores].dib
- 151.248.117[.]244 port 80 - diwdjndsfnj[.]ru - GET /uploaded/[long base64 string with backslashes and underscores].pmg
- 151.248.117[.]244 port 80 - iwqdndomdn[.]su - GET /uploaded/[long base64 string with backslashes and underscores].pmg
- 151.248.117[.]244 port 80 - iwqdndomdn[.]su - POST /uploaded/[long base64 string with backslashes and underscores].dib

GOZI/ISFB MODULES (ENCRYPTED DATA BINARIES):

- 91.199.147[.]95 port 80 - 91.199.147[.]95 - GET /vnc32.rar
- 91.199.147[.]95 port 80 - 91.199.147[.]95 - GET /vnc64.rar
- 91.199.147[.]95 port 80 - 91.199.147[.]95 - GET /stilak32.rar
- 91.199.147[.]95 port 80 - 91.199.147[.]95 - GET /stilak64.rar
- 91.199.147[.]95 port 80 - 91.199.147[.]95 - GET /cook32.rar
- 91.199.147[.]95 port 80 - 91.199.147[.]95 - GET /cook64.rar

TRAFFIC CAUSED BY VNC MODULE:

- 188.127.224[.]25 port 9955 - TCP traffic

ENCRYPTED DATA BINARY FOR COBALT STRIKE STAGER:

- 194.58.102[.]187 port 80 - 194.58.102[.]187 - GET /01/64HTTPS.zip

DLL FOR COBALT STRIKE STAGER:

- 193.149.176[.]60 port 443 - softwaredw[.]com - GET /softwaredw.com/64HTTPS.dll

COBALT STRIKE C2:

- 170.130.55[.]162 port 443 - iamupdate[.]com - HTTPS traffic, TLSv1.2, Let's Encrypt certificate, not valid before 2023-07-03

2020-09-21 - INFECTION FROM DRIDEX MALSPAM

REFERENCE:

- https://twitter.com/Unit42_Intel/status/1308153302513745920

EMAIL HEADER DATA:

- Received: from [91.81.229.185] (unknown [91.81.229.185]) by [removed]; Mon, 21 Sep 2020 14:25:24 +0200 (CEST)
- Received: from [1.124.14.21] (helo=FAWADUM.esa4.dhl-out.iphmx.com) by [removed] (envelope-from
watercourse71@gateway2d.dhl.com) [removed]; Mon, 21 Sep 2020 13:25:24 +0100
- Date: Mon, 21 Sep 2020 13:25:24 +0100
- From: BillingOnline <donotreply@fedex.com>
- Subject: FedEx Billing Online - Invoice Ready for Payment

ONE OF AT LEAST 10 URLS GENERATED BY EXCEL MACRO:

- hxxps://cdn.applimmo[.]com/wxmn5b.pdf
- hxxps://mazimimarlik[.]com/ow1oorywn.pdf
- hxxps://lamesuspendue.swayb[.]com/pxxnmie14.zip
- hxxps://laptopsservicecenter[.]in/s3k9ebe2.pdf
- hxxps://mail.168vitheyrealestate[.]com/k5hkyj0.zip
- hxxps://retrodays[.]pt/lhtzu8p.zip
- hxxps://skybeetravels.cheapflightso[.]co[.]uk/py198k.pdf
- hxxps://starsignsdates[.]com/hurxlu8.pdf
- hxxps://stepco[.]ro/wij87mvg.txt
- hxxps://update.cabinetulieru[.]ro/thhqpn.txt

DRIDEX POST-INFECTION HTTPS TRAFFIC

- 51.75.24[.]85 port 443
- 109.169.24[.]37 port 453

ASSOCIATED MALWARE:

- SHA256 hash: 3259221b5378b9c9a983ae265527662c0c7856f6664a9a734754f549ee4d7a33
- File size: 28,618 bytes
- File name: 5-107-26477.xlsm
- File description: Excel spreadsheet with macro for Dridex

- SHA256 hash: 5b4337f9ae1d91113c91abd0da39794d8aa216b149562440de541ca99618840d
- File size: 331,776 bytes
- File location: xxps://cdn.applimmo[.]com/wxmn5b.pdf
- File location: C:\XMjrcrYY\WZzAVF\XkZVNh
- Run method: regsvr32.exe /s [file name]
- File description: DLL installer retrieved by Excel macro for Dridex
- Note: Random characters for directory path and file name each infection

- SHA256 hash: 55067d633bef8350b5de24e3e9f153fc4a6765af0af168fb444a6329c701b10a
- File size: 1,017,344 bytes
- File location: C:\Users\[username]\AppData\Roaming\Microsoft\Templates\LiveContent\bGGj9sX\MFC42u.DLL
- File description: Dridex malware DLL
- Note: Run by copy of legitimate system file DevicePairingWizard.exe in the same directory

- SHA256 hash: 8a7cc23e3b7af9ebd2d1dd3791bb62bd1da1efd3d2c480fa51483552520abd0a
- File size: 1,012,224 bytes
- File location: C:\Users\[username]\AppData\Roaming\Sun\0umgO\WTSAPI32.dll
- File description: Dridex malware DLL
- Note: Run by copy of legitimate system file rdpclip.exe in the same directory

- SHA256 hash: eb3c152be59903d29cf02100ed2f9edea183a37882a68ae5655bcbc9004775d8
- File size: 1,009,664 bytes
- File location: C:\Users\[username]\AppData\Roaming\Thunderbird\Profiles\1ovarfyl.default-release\ImapMail\.outlook.com\yFYLx\XmlLite.dll
- File description: Dridex malware DLL
- Note: Run by copy of legitimate system file sppsvc.exe in the same directory




2020-11-16 (MONDAY) - XLSX SPREADSHEET PUSHES COBALT STRIKE

REFERENCE:

- https://twitter.com/Unit42_Intel/status/1328425382140387328

NOTES:

- We've seen this spreadsheet template normally push Qakbot until mid-November 2020, when it started pushing other families of malware instead of Qakbot.
- Since mid-November 2020, we've occasionally seen this spreadsheet template push SmokeLoader or Cobalt Strike malware.

ASSOCIATED MALWARE:

- SHA256 hash: 4af251feed5a80976f897a0749147b74ec92ad90695eea87eeb21f83a41cff7f
- File size: 366,296 bytes
- File name: Document11355.xlsb
- File description: XLSX file with macros for Cobalt Strike

- SHA256 hash: c81cbf497e7427936c0f15290fe4a1648c8fc10c249d3b97e67897bd1e2808b6
- File size: 237,568 bytes
- File location: hxxp://99promo[.]com/ds/161120.gif
- File location: C:\1b3SX\iD93\tor.exe
- File description: Windows executable file (EXE) for Cobalt Strike

INFECTION TRAFFIC:

- 35.209.123[.]121 port 80 - 99promo[.]com - GET /ds/161120.gif
- 185.99.133[.]180 port 80 - 185.99.133[.]180 - GET /IE9CompatViewList.xml
- 185.99.133[.]180 port 80 - 185.99.133[.]180 - POST /submit.php?id=12345678
- NOTE: 1245678 in the above line replaces an 8-digit identification number for the infected Windows host


2021-03-15 (MONDAY) ICEDID (BOKBOT) FROM EXCEL SPREADSHEET MACROS

REFERENCE:

- https://twitter.com/Unit42_Intel/status/1371592816510578689

INFECTION CHAIN:

- malicious spam --> ZIP attachment --> extract Excel file --> enable macros --> Installer DLL --> gziploader process --> IcedID

REFERENCE:

- https://www.binarydefense.com/icedid-gziploader-analysis/

ASSOCIATED MALWARE:

- SHA256 hash: 0b31911de524410fef3725f6fe5b565c6cb3e3b2ea5b7267bebc097f9fb57eb3
- File size: 156,675 bytes
- File name: CompensationClaim_605614143_03152021.zip
- File description: ZIP archive attached to malicious spam pushing IcedID

- SHA256 hash: 1852801558498c3bbc67b028b592ba9444a4e687a7f67737a393ce3f756d8c87
- File size: 239,104 bytes
- File name: CompensationClaim_605614143_03152021.xls
- File description: Extracted from the above ZIP archive, an Excel file with macro for IcedID

- SHA256 hash: f175d5883a0958f8ce10c387fef6c6750d26089e7413bf7b9a3767b655e61417
- File size: 44,544 bytes
- File location: hxxp://188.127.254[.]114/44270.7145450231.dat
- File location: hxxp://185.82.219[.]160/44270.7145450231.dat
- File location: hxxp://45.140.146[.]34/44270.7145450231.dat
- File location: C:\Users\[username]\SOT.GOT
- File location: C:\Users\[username]\SOT.GOT1
- File location: C:\Users\[username]\SOT.GOT2
- File description: Installer DLL for IcedID
- Run method: rundll32.exe [filename],DllRegisterServer

- SHA256 hash: 54d7277a2637bd8b410419f06a189b902243e91eb683435b931ae013d5a576f0
- File size: 36,352 bytes
- File location: C:\Users\[username]\AppData\Local\Temp\raise_x64.tmp
- File description: Initial IcedID DLL
- Run method: rundll32.exe [filename],update /i:[filepath]\license.dat

- SHA256 hash: 7b329e340343bcdf1a70d1b487093bb3a4579f603a97214ecdcf78b339a6a1fc
- File size: 36,352 bytes
- File location: C:\Users\[username]\AppData\Roaming\{00F0279B-1BB6-6935-485C-566FF0BA28FC}\[username]\ruoyan.dll
- File description: Persistent IcedID DLL
- Run method: rundll32.exe [filename],update /i:[filepath]\license.dat

- SHA256 hash: 45b6349ee9d53278f350b59d4a2a28890bbe9f9de6565453db4c085bb5875865
- File size: 341,002 bytes
- File location: C:\Users\[username]\AppData\Roaming\SpringGoat\license.dat
- File description: Data file used by the above two IcedID DLL files

TRAFFIC TO RETRIEVE INSTALLER DLL FOR ICEDID:

- 188.127.254[.]114 port 80 - 188.127.254[.]114 - GET /44270.7145450231.dat
- 185.82.219[.]160 port 80 - 185.82.219[.]160 - GET /44270.7145450231.dat
- 45.140.146[.]34 port 80 - 45.140.146[.]34 - GET /44270.7145450231.dat

TRAFFIC GENERATED BY INSTALLER DLL:

- port 443 - aws.amazon.com - HTTPS traffic
- 178.128.243[.]14 port 80 - apoxiolazio55[.]space GET /

ICEDID C2 TRAFFIC:

- 165.227.28[.]47 port 443 - twotoiletsr[.]space - HTTPS traffic
- 165.227.28[.]47 port 443 - iporumuski[.]fun - HTTPS traffic
    """
    indicator_type = extract_indicators(text_content)

 
def test_get_yara_indicators():
    my_text_content = """
    rule WindowsShell_s3 {
	meta:
		description = "Detects simple Windows shell - file s3.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		id = "064754a7-8639-5dbd-93f3-906662b8e9bc"
	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "\\\\.\\pipe\\%08X" fullword ascii
		$s3 = "get <remote> <local> - download file" fullword ascii
		$s4 = "[ simple remote shell for windows v3" fullword ascii
		$s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s6 = "put <local> <remote> - upload file" fullword ascii
		$s7 = "term                 - terminate remote client" fullword ascii
		$s8 = "[ downloading \"%s\" to \"%s\"" fullword ascii
		$s9 = "-l           Listen for incoming connections" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindosShell_s1 {
	meta:
		description = "Detects simple Windows shell - file s1.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		id = "b4e783a2-4a93-5c72-9b09-4692b383ac00"
	strings:
		$s1 = "[ executing cmd.exe" fullword ascii
		$s2 = "[ simple remote shell for windows v1" fullword ascii
		$s3 = "-p <number>  Port number to use (default is 443)" fullword ascii
		$s4 = "usage: s1 <address> [options]" fullword ascii
		$s5 = "[ waiting for connections on %s" fullword ascii
		$s6 = "-l           Listen for incoming connections" fullword ascii
		$s7 = "[ connection from %s" fullword ascii
		$s8 = "[ %c%c requires parameter" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 150KB and 2 of them ) or ( 5 of them )
}

rule WindowsShell_s4 {
	meta:
		description = "Detects simple Windows shell - file s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		hash = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "838771dc-f885-5332-9813-2bc01af8e5fe"
	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "\\\\.\\pipe\\%08X" fullword ascii
		$s3 = "get <remote> <local> - download file" fullword ascii
		$s4 = "[ simple remote shell for windows v4" fullword ascii
		$s5 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s6 = "[ downloading \"%s\" to \"%s\"" fullword ascii
		$s7 = "[ uploading \"%s\" to \"%s\"" fullword ascii
		$s8 = "-l           Listen for incoming connections" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}

/* Super Rules ------------------------------------------------------------- */

rule WindowsShell_Gen {
	meta:
		description = "Detects simple Windows shell - from files keygen.exe, s1.exe, s2.exe, s3.exe, s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		super_rule = 1
		hash1 = "a7c3d85eabac01e7a7ec914477ea9f17e3020b3b2f8584a46a98eb6a2a7611c5"
		hash2 = "4a397497cfaf91e05a9b9d6fa6e335243cca3f175d5d81296b96c13c624818bd"
		hash3 = "df0693caae2e5914e63e9ee1a14c1e9506f13060faed67db5797c9e61f3907f0"
		hash4 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash5 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "6b871e8a-8fe3-5cc6-9f2c-ba2359861ea1"
	strings:
		$s0 = "[ %c%c requires parameter" fullword ascii
		$s1 = "[ %s : %i" fullword ascii
		$s2 = "[ %s : %s" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( all of them )
}

rule WindowsShell_Gen2 {
	meta:
		description = "Detects simple Windows shell - from files s3.exe, s4.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/odzhan/shells/"
		date = "2016-03-26"
		super_rule = 1
		hash1 = "344575a58db288c9b5dacc654abc36d38db2e645acff05e894ff51183c61357d"
		hash2 = "f00a1af494067b275407c449b11dfcf5cb9b59a6fac685ebd3f0eb193337e1d6"
		id = "8ed8443d-491b-5cb0-b12b-0d25267ba462"
	strings:
		$s1 = "cmd                  - execute cmd.exe" fullword ascii
		$s2 = "get <remote> <local> - download file" fullword ascii
		$s3 = "REMOTE: CreateFile(\"%s\")" fullword ascii
		$s4 = "put <local> <remote> - upload file" fullword ascii
		$s5 = "term                 - terminate remote client" fullword ascii
		$s6 = "[ uploading \"%s\" to \"%s\"" fullword ascii
		$s7 = "[ error : received %i bytes" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 175KB and 2 of them ) or ( 5 of them )
}
"""
    indicators = parse_and_map_yara_content(my_text_content)
