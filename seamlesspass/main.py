import argparse
import logging
import sys
import traceback

import colorama


from .utils import log
from .utils.exceptions import UsageError
from .utils.helper import Helper
from .utils.help_formatter import ColoredHelpFormatter

from . import banner
from . import seamlesspass


def __format_example(args, show_colors=True):
    return f'  seamlesspass {Helper.colorize_args(args, show_colors)}\n'


def main() -> None:

    show_colors = '-no-color' not in sys.argv
    
    try:
        colorama.just_fix_windows_console()
    except:
        colorama.init()
    log.init(color=show_colors, ts=False)

    if show_colors:
        print(banner.COLORED_BANNER, file=sys.stderr)
    else:
        print(banner.BANNER, file=sys.stderr)

    #Compiling examples
    examples = Helper.maybe_add_color('Examples:', colorama.Fore.YELLOW, show_colors) + '\n'
    examples +=  __format_example({'-tenant':'corp.com','-domain':'corp.local','-dc':'dc.corp.local','-tgt':'<base64_encoded_TGT>'}, show_colors)
    examples +=  __format_example({'-tenant':'corp.com','-tgs':'user_tgs.ccache'}, show_colors)
    examples +=  __format_example({'-tenant':'corp.com','-domain':'corp.local','-dc':'dc.corp.local','-username':'user','-ntlm':'DEADBEEFDEADBEEFDEADBEEFDEADBEEF'}, show_colors)
    examples +=  __format_example({'-tenant':'corp.com','-domain':'corp.local','-dc':'10.0.1.2','-username':'user','-password':'password'}, show_colors)
    examples +=  __format_example({'-tenant':'corp.com','-adssoacc-ntlm':'DEADBEEFDEADBEEFDEADBEEFDEADBEEF','-user-sid':'S-1-5-21-1234567890-1234567890-1234567890-1234'}, show_colors)
    examples +=  __format_example({'-tenant':'corp.com','-adssoacc-aes':'DEADBEEFDEADBEEFDEADBEEFDEADBEEF','-domain-sid':'S-1-5-21-1234567890-1234567890-1234567890','-user-rid':'1234'}, show_colors)

    formatter_class = ColoredHelpFormatter if show_colors else argparse.RawTextHelpFormatter 
    parser = argparse.ArgumentParser(epilog=examples, formatter_class=formatter_class, add_help=False)
    
    #------------- Microsoft 365 options ------------
    group = parser.add_argument_group('Microsoft 365 options')

    group.add_argument(
        "-t",
        "-tenant",
        action="store",
        metavar="tenant domain",
        dest = 'tenant',
        help="Domain of the tenant (e.g. example.com, corp.onmicrosoft.com)"
    )

    group.add_argument(
        "-r",
        "-resource",
        action="store",
        metavar="resource URI",
        dest = 'resource',
        help="Target cloud service to be accessed (Default: https://graph.windows.net)",
    )

    group.add_argument(
        "-c",
        "-client-id",
        action="store",
        metavar="client_id",
        dest = 'client_id',
        help="Microsoft 365 client ID (Default: 1b730954-1685-4b74-9bfd-dac224a7b894)",
    )
    group.add_argument("-ignore-sso-check", action="store_true", help="Try to login using Seamless SSO even if it is not enabled")

    #------------- Authentication Options ------------
    group = parser.add_argument_group("Authentication Options")  
    group.add_argument(
        "-d",
        "-domain",
        metavar="domain",
        dest="domain",
        help = "Local domain (e.g., corp.local)",
        action="store",
    )
    group.add_argument(
        "-dc",
        "-dc-ip",
        action="store",
        metavar="DC host/IP",
        dest='dc_host',
        help="Hostname or IP Address of the domain controller used for authentication (example: dc.corp.local, 10.0.1.2)",
    )
    group.add_argument(
        "-u",
        "-username",
        metavar="username",
        dest="username",
        action="store",
    )
    group.add_argument(
        "-p",
        "-password",
        metavar="password",
        dest="password",
        action="store",
        
    )
    group.add_argument(
        "-n",
        "-ntlm",
        action="store",
        metavar="[LMHASH:]NTHASH",
        dest="ntlm",
        help="User's NTLM hashed password, format is [LMHASH:]NTHASH",
    )
    group.add_argument(
        "-aes",
        action="store",
        metavar="AESKey",
        dest="aes_key",
        help="User's AES 128/256 key",
    )
    group.add_argument(
        "-tgt", 
        action="store", 
        metavar="base64 TGT / TGT file", 
        dest="tgt",
        help="base64-encoded Ticket-Granting Ticket (TGT) or path to TGT file (kirbi/ccache)"
    )
    group.add_argument(
        "-tgs", 
        action="store", 
        metavar="base64 TGS / TGS file", 
        dest="tgs",
        help="base64-encoded Service Ticket (TGS) or path to TGS file (kirbi/ccache)"
    )
    group.add_argument("-spn", 
        action="store", 
        metavar="SPN", 
        help="Target service principal name. (Default: HTTP/autologon.microsoftazuread-sso.com)"
    )
    #------------- Ticket Forgery Options ------------
    group = parser.add_argument_group("Ticket Forgery Options")  
    group.add_argument(
        "-domain-sid",
        metavar="SID",
        help = "Domain Security Identifier ",
        action="store",
    )
    group.add_argument(
        "-user-rid",
        metavar="number",
        help = "User Relative ID (Last part of user SID)",
        action="store",
    )
    group.add_argument(
        "-user-sid",
        metavar="SID",
        help = "User Security Identifier ",
        action="store",
    )
    group.add_argument(
        "-adssoacc-ntlm",
        action="store",
        metavar="[LMHASH:]NTHASH",
        help="NTLM hash of AZUREADSSOACC account (Used to forge TGS)",
    )
    group.add_argument(
        "-adssoacc-aes",
        action="store",
        metavar="AESKey",
        help="AES 128/256 Key of AZUREADSSOACC account (Used to forge TGS)",
    )

    #------------- Connection Options ------------
    group = parser.add_argument_group("Connection Options")
    group.add_argument(
        "-proxy",
        action="store",
        dest="proxies",
        metavar="[scheme]://[user:password]@[host]:[port]",
        help="NOTE: This is used only for HTTP requests not DC communication. (example: http://burp:8080)",
    )
    group.add_argument(
        "-ua",
        "-user-agent",
        action="store",
        dest="user_agent",
        metavar="USERAGENT",
        help="HTTP User agent used in interaction with Microsoft 365 APIs",
    )


    group = parser.add_argument_group('Misc options')
    group.add_argument("-debug", action="store_true", help="Turn debug output on")
    group.add_argument("-no-color", action="store_true", help="Turn off console colors")
    group.add_argument('-h', '--help', action='help', help='Show this help message and exit.')
    

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit()


    if options.debug is True:
        log.logger.setLevel(logging.DEBUG)
    else:
        log.logger.setLevel(logging.INFO)

    try:
        seamlesspass.run(options)

    except UsageError as e:
        log.logger.error(str(e))
        print('------------')
        parser.print_help()
        print('------------')
        log.logger.error(str(e))
        

    except Exception as e:
        log.logger.error("Got error: %s" % e)
        if options.debug:
            traceback.print_exc()
        else:
            log.logger.error("Use -debug to print a stacktrace")

    finally:
        colorama.deinit()


if __name__ == "__main__":
    main()