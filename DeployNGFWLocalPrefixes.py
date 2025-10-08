#!/usr/bin/env python3

# 20201020 - Add a function to add a single prefix to a local prefixlist - Dan
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import ipcalc
import os
import datetime
from csv import DictReader
import ipcalc


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: Local Prefix'
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


def addLocalPrefix(sdk, site_name, prefix_name, prefix):
    # check if prefix is None, then there is nothing to do
    if not prefix:
        return ("Not adding None to " + prefix_name)

    # find site ID
    site_id = None
    for site in sdk.get.sites().cgx_content["items"]:
        if site_name == site['name']:
            site_id = site['id']
            break
    if not site_id:
        return ("Site " + site_name + " couldn't be found")

    # Security 
    print("Checking Security Prefix")
    local_filter_id = None
    for prefix_filter in sdk.get.ngfwsecuritypolicylocalprefixes().cgx_content['items']:
        if prefix_name.upper() == prefix_filter['name'].upper():
            local_filter_id = prefix_filter['id']
            break
    if not local_filter_id:
        lpf_data = {
            "description": None,
            "name": prefix_name
        }
        resp = sdk.post.ngfwsecuritypolicylocalprefixes(lpf_data)
        if not resp:
            print(str(jdout(resp)))
            return ("Cloudn't create local prefix filter")

        for prefix_filter in sdk.get.ngfwsecuritypolicylocalprefixes().cgx_content['items']:
            if prefix_name.upper() == prefix_filter['name'].upper():
                local_filter_id = prefix_filter['id']
                break

    filter_id = None
    for prefix_filter in sdk.get.site_ngfwsecuritypolicylocalprefixes(site_id).cgx_content['items']:
        if prefix_filter['prefix_id'] == local_filter_id:
            filter_id = prefix_filter['id']
            filter_json = prefix_filter
            break
    
    if filter_id:
        if prefix in filter_json['ipv4_prefixes']:
            print ("Prefix " + prefix + " already exists on " + prefix_name + " at " + site_name)
        else:
            filter_json['ipv4_prefixes'].append(prefix)
            resp = sdk.put.site_ngfwsecuritypolicylocalprefixes(site_id, filter_id, filter_json)
            if not resp:
                print ("Error adding prefix " + prefix + " to " + prefix_name)
            else:
                print ("Adding prefix " + prefix + " to " + prefix_name)
    else:
        new_prefix = {"prefix_id": local_filter_id, "ipv4_prefixes": [prefix],"ipv6_prefixes":[],"tags":[]}
        resp = sdk.post.site_ngfwsecuritypolicylocalprefixes(site_id, new_prefix)
        if not resp:
            print(str(jdout(resp)))
            print ("Error adding local prefix " + prefix + " from " + prefix_name)
        else:
            print ("Creating local prefix " + prefix_name + " for site " + site_name + " and adding prefix " + prefix)
    
    
    # Path 
    print("Checking Path Prefix")
    local_filter_id = None
    for prefix_filter in sdk.get.tenant_networkpolicylocalprefixes().cgx_content['items']:
        if prefix_name.upper() == prefix_filter['name'].upper():
            local_filter_id = prefix_filter['id']
            break
    if not local_filter_id:
        lpf_data = {
            "description": None,
            "name": prefix_name
        }
        resp = sdk.post.tenant_networkpolicylocalprefixes(lpf_data)
        if not resp:
            print(str(jdout(resp)))
            return ("Cloudn't create local prefix filter")

        for prefix_filter in sdk.get.tenant_networkpolicylocalprefixes().cgx_content['items']:
            if prefix_name.upper() == prefix_filter['name'].upper():
                local_filter_id = prefix_filter['id']
                break

    filter_id = None
    for prefix_filter in sdk.get.site_networkpolicylocalprefixes(site_id).cgx_content['items']:
        if prefix_filter['prefix_id'] == local_filter_id:
            filter_id = prefix_filter['id']
            filter_json = prefix_filter
            break
    
    if filter_id:
        if prefix in filter_json['ipv4_prefixes']:
            print ("Prefix " + prefix + " already exists on " + prefix_name + " at " + site_name)
        else:
            filter_json['ipv4_prefixes'].append(prefix)
            resp = sdk.put.site_networkpolicylocalprefixes(site_id, filter_id, filter_json)
            if not resp:
                print ("Error adding prefix " + prefix + " to " + prefix_name)
            else:
                print ("Adding prefix " + prefix + " to " + prefix_name)
    else:
        new_prefix = {"prefix_id": local_filter_id, "ipv4_prefixes": [prefix],"ipv6_prefixes":[],"tags":[]}
        resp = sdk.post.site_networkpolicylocalprefixes(site_id, new_prefix)
        if not resp:
            print(str(jdout(resp)))
            print ("Error adding local prefix " + prefix + " from " + prefix_name)
        else:
            print ("Creating local prefix " + prefix_name + " for site " + site_name + " and adding prefix " + prefix)
    
    
    # QoS 
    print("Checking QoS Prefix")
    local_filter_id = None
    for prefix_filter in sdk.get.tenant_prioritypolicylocalprefixes().cgx_content['items']:
        if prefix_name.upper() == prefix_filter['name'].upper():
            local_filter_id = prefix_filter['id']
            break
    if not local_filter_id:
        lpf_data = {
            "description": None,
            "name": prefix_name
        }
        resp = sdk.post.tenant_prioritypolicylocalprefixes(lpf_data)
        if not resp:
            print(str(jdout(resp)))
            return ("Cloudn't create local prefix filter")

        for prefix_filter in sdk.get.tenant_prioritypolicylocalprefixes().cgx_content['items']:
            if prefix_name.upper() == prefix_filter['name'].upper():
                local_filter_id = prefix_filter['id']
                break

    filter_id = None
    for prefix_filter in sdk.get.site_prioritypolicylocalprefixes(site_id).cgx_content['items']:
        if prefix_filter['prefix_id'] == local_filter_id:
            filter_id = prefix_filter['id']
            filter_json = prefix_filter
            break
    
    if filter_id:
        if prefix in filter_json['ipv4_prefixes']:
            print ("Prefix " + prefix + " already exists on " + prefix_name + " at " + site_name)
        else:
            filter_json['ipv4_prefixes'].append(prefix)
            resp = sdk.put.site_prioritypolicylocalprefixes(site_id, filter_id, filter_json)
            if not resp:
                print ("Error adding prefix " + prefix + " to " + prefix_name)
            else:
                print ("Adding prefix " + prefix + " to " + prefix_name)
    else:
        new_prefix = {"prefix_id": local_filter_id, "ipv4_prefixes": [prefix],"ipv6_prefixes":[],"tags":[]}
        resp = sdk.post.site_prioritypolicylocalprefixes(site_id, new_prefix)
        if not resp:
            print(str(jdout(resp)))
            print ("Error adding local prefix " + prefix + " from " + prefix_name)
        else:
            print ("Creating local prefix " + prefix_name + " for site " + site_name + " and adding prefix " + prefix)
    return 
            
            
    
    
                 
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
    config_group.add_argument('--file', '-F',
                              help='Site name or id. More than one can be specified '
                                   'separated by comma, or special string "ALL_SITES".',
                              required=True)
                              

    args = vars(parser.parse_args())
    
    file_name = args['file']

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
    
    with open(file_name, 'r') as read_obj:
        csv_dict_reader = DictReader(read_obj)
        for row in csv_dict_reader:
            prefix_name = row['Prefix_Name']
            site_name = row['Site_Name']
            prefix = row['IP']
            addLocalPrefix(cgx, site_name, prefix_name, prefix)
    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()