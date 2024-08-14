import pkg_resources

from colorama import Fore,Style

try:
    version = pkg_resources.get_distribution("seamlesspass").version
except pkg_resources.DistributionNotFound:
    version = '?'

copyright = 'By Abood Nour (@0xSyndr0me) - Malcrove (https://malcrove.com/)'
description = 'Leveraging Kerberos tickets to get cloud access tokens using Seamless SSO'

ASCII_ART = fr"""
   _____                      _               _____              
  / ____|                    | |             |  __ \     v({version})         
 | (___   ___  __ _ _ __ ___ | | ___  ___ ___| |__) |_ _ ___ ___ 
  \___ \ / _ \/ _` | '_ ` _ \| |/ _ \/ __/ __|  ___/ _` / __/ __|
  ____) |  __/ (_| | | | | | | |  __/\__ \__ \ |  | (_| \__ \__ \
 |_____/ \___|\__,_|_| |_| |_|_|\___||___/___/_|   \__,_|___/___/
                                                                 """

BANNER = f'{ASCII_ART} \n {copyright} \n\n{description}\n'
COLORED_BANNER = f'{Fore.CYAN}{ASCII_ART}{Style.RESET_ALL} \n {Fore.LIGHTBLACK_EX}{copyright}{Style.RESET_ALL} \n\n{description}\n'