#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed
import yaml
import cloudgenix_settings
import sys
import logging
import ipcalc
import os
import datetime
from csv import DictReader
import ipcalc
import csv


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: local prefixes'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


def getLocalPrefix(cgx, site_name):
    # find site ID
    site_id = None
    site_list = []
    site_id2n = {}
    for site in cgx.get.sites().cgx_content["items"]:
        if site_name == "ALL_SITES":
            site_list.append(site['id'])
            site_id2n[site['id']] = site['name']
        elif site_name == site['name']:
            site_list.append(site['id'])
            site_id2n[site['id']] = site['name']
        
    global_prefix = cgx.get.localprefixfilters().cgx_content['items']
    csv_name = site_name + "-localprefix.csv"

    # find existing prefix filter
    prefix_site_list = []
    if site_list:
        for site in site_list:
            print("Checking for local prefixes on site " + site_id2n[site])
            try:
                for prefix_filter in cgx.get.prefixfilters(site).cgx_content['items']:
                    parent = prefix_filter['prefix_filter_id']
                    for prefix_filter_global in global_prefix:
                        site_prefix_data = {}
                        site_prefix_data["Site_Name"] = site_id2n[site]
                        site_prefix_data["Prefix_Name"] = prefix_filter_global['name']
                        if parent == prefix_filter_global['id']:
                            prefix_ip = prefix_filter['filters'][0]['ip_prefixes']
                            site_prefix_data["IP"] = ", ".join(prefix_ip)
                            prefix_site_list.append(site_prefix_data)
            except:
                print("Failed to grab prefixes for site " + site_id2n[site])

    csv_columns = []
    if prefix_site_list:
        for key in prefix_site_list[0].keys():
            csv_columns.append(key)
    csv_file = "site_local_prefix.csv"
    try:
        with open(csv_file, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
            writer.writeheader()
            for data in prefix_site_list:
                writer.writerow(data)
            print("Saved site_local_prefix.csv file")
    except IOError:
        print("CSV Write Failed")

    return True, "200"
                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
                             
    # Allow Controller modification and debug level sets.
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
    config_group.add_argument('--sites', '-S',
                              help='Site name or id. More than one can be specified '
                                   'separated by comma, or special string "ALL_SITES".',
                              required=True)
    args = vars(parser.parse_args())
    
    site_name = args['sites']


    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    
    getLocalPrefix(cgx, site_name)
    
    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()