import json
import os
import biplist
import xattr
import pprint
import urlparse
import platform
import objc
import commands
import argparse
from Foundation import NSBundle

DEBUG = False


def system_info():
    ##Mac specific imports needed for direct Obj-C calls to get EFI & Board-ID's
    ## rather using iokit / system_profiler - Thanks to Piker-Alpha for the pointers on this. See their code here:
    ## https://github.com/Piker-Alpha/HandyScripts/blob/master/efiver.py & issue https://github.com/duo-labs/EFIgy/issues/8
    ## Also, shameless lifted from Duo Labs EFIgy project.
    ## https://github.com/duo-labs/EFIgy
    IOKit_bundle = NSBundle.bundleWithIdentifier_('com.apple.framework.IOKit')
    functions = [("IOServiceGetMatchingService", b"II@"),
                 ("IOServiceMatching", b"@*"),
                 ("IORegistryEntryCreateCFProperty", b"@I@@I"),
                 ("IORegistryEntryFromPath", b"II*"),
                 ]
    objc.loadBundleFunctions(IOKit_bundle, globals(), functions)

    def io_key(keyname):
        return IORegistryEntryCreateCFProperty(
            IOServiceGetMatchingService(0, IOServiceMatching("IOPlatformExpertDevice")), keyname, None, 0)

    hw_version = str(
        IORegistryEntryCreateCFProperty(IOServiceGetMatchingService(0, IOServiceMatching("IOPlatformExpertDevice")),
                                        "model", None, 0)).replace("\x00", "")
    smc_version = str(
        IORegistryEntryCreateCFProperty(IOServiceGetMatchingService(0, IOServiceMatching("AppleSMC")), "smc-version",
                                        None, 0))
    raw_efi = str(
        IORegistryEntryCreateCFProperty(IORegistryEntryFromPath(0, "IODeviceTree:/rom"), "version", None, 0)).replace(
        "\x00", "").split(".")

    efi_version = "%s.%s.%s" % (raw_efi[0], raw_efi[2], raw_efi[3])

    sys_uuid = str(
        IORegistryEntryCreateCFProperty(IOServiceGetMatchingService(0, IOServiceMatching("IOPlatformExpertDevice")),
                                        "IOPlatformUUID", None, 0)).replace("\x00", "")
    board_id = str(
        IORegistryEntryCreateCFProperty(IOServiceGetMatchingService(0, IOServiceMatching("IOPlatformExpertDevice")),
                                        "board-id", None, 0)).replace("\x00", "")

    os_version = commands.getoutput("/usr/bin/sw_vers -productVersion")
    build_num = commands.getoutput("/usr/bin.sw_vers -buildVersion")

    system_summary = {
        'hw_version': hw_version,
        'smc_version': smc_version,
        'raw_efi': raw_efi,
        'efi_version': efi_version,
        'os_version': os_version,
        'build_num': build_num,
        'board_id': board_id,
        'sys_uuid': sys_uuid
    }

    return system_summary


class SecurityBat:
    """
    Security Bat is an application designed to look at threats in real-time and squash them.
    """

    def __init__(self):

        self.url_set = set()
        self.master_dict = {}
        self.jamf_results = []
        self.score = 0

        pass

    def _build_homedir_list(self, user_folder='Downloads'):
        """
        Builds a list of User home directories on the system
        :return: list obj of home folders in the /Users/ directory
        """
        NON_USER_DIRS = [
            'Shared',
            'Deleted Users',
            'Guest',
            '_mbsetupuser'
        ]

        dirs = os.listdir('/Users')

        homedirs = []

        for path in dirs:
            if os.path.isdir(os.path.join('/Users', path)) and path not in NON_USER_DIRS:
                homedirs.append(os.path.join('/Users', path, user_folder))

        return homedirs

    def build_file_list(self, directory_list):
        """

        :param directory_list: a list obj of directories to inspect.
        :return: a list of file paths to inspect.
        """
        master_file_list = []

        for directory in directory_list:
            try:
                master_file_list.append({'path': directory, 'files': os.listdir(directory)})
            except IOError as e:
                if DEBUG:
                    print "Error in %s. %s" % (directory, e)
                exit(1)

        if DEBUG:
            pprint.pprint(master_file_list)
        return master_file_list

#Pull metadata from files in a particular file path
    def _get_meta_data(self, file_path, *args, **kwargs):
        """

        :param file_path: a single string file path.
        :param args:
        :param kwargs: override the attributes gathered.
        :return: a dictionary of attributes
        """

        ATTRIBUTES = [
            'com.apple.metadata:kMDItemWhereFroms',
            'com.apple.metadata:kMDItemUserSharedSentTransport',
            'com.apple.metadata:kMDItemKind',
            'com.apple.metadata:kMDItemUserSharedSentRecipient',
            'com.apple.metadata:kMDItemUserSharedSentRecipientHandle',
            'com.apple.metadata:kMDItemFSCreationDate',
            'com.apple.metadata:kMDItemFSContentChangeDate',
            'com.apple.quarantine'
        ]

        file_attrs = xattr.xattr(file_path)
        attr_list = []
        attr_dict = {}

        for local_attr in file_attrs.list():
            """
            Loop through the attributes provided and update the attr_dictionary when a match is found. Not all files
            will have all of  the attributes provided.
            """
            if local_attr in ATTRIBUTES:
                try:
                    attr_value = biplist.readPlistFromString(file_attrs.get(local_attr))

                    if local_attr == 'com.apple.metadata:kMDItemWhereFroms':
                        url_list = []

                        for url in attr_value:
                            if len(url) is not 0:
                                url_list.append(urlparse.urlsplit(url)[1])
                                self.url_set.add(urlparse.urlsplit(url)[1])

                        attr_value = url_list
                except Exception as e:
                    attr_value = None

                attr_list.append({'attribute': local_attr, 'attribute_value': attr_value})

        attr_dict.update({
            'file': file_path,
            'attrs': attr_list
        })

        return attr_dict

    def get_file_attributes(self, file_list):
        ## TODO: Clean up, document, and add failure conditions
        """

        :param file_list: is a list of dictionary objs containing a path and a list of files within that path.
        :return: True if it can gather data.
        """

        meta_data_list = []

        for dir_data in file_list:

            for file_data in dir_data['files']:

                file_path = os.path.join(dir_data['path'], file_data)
                if os.path.isfile(file_path):
                    meta_data_list.append(self._get_meta_data(file_path))

        self.master_dict.update(
            {'file_attributes': meta_data_list,
             'file_attribute_domains_count': len(self.url_set),
             'file_attribute_domains': list(self.url_set)
             })
        return True

#Test for third part kext info
    def get_thirdparty_kexts(self):
        ## TODO: Add fail conditions
        """
        This method will get the running kexts that are not apple
        :return: True if it can collect information
        """
        kext_list = []

        for kext in commands.getoutput('/usr/sbin/kextstat -list-only | /usr/bin/grep -v com.apple').split('\n'):

            split_kext = kext.split()

            kext_info = {
                'kext_name': split_kext[5],
                'kext_version': split_kext[6],
                'kext_id': split_kext[7]
            }

            kext_list.append(kext_info)

        self.master_dict.update({'third_party_kext': kext_list, 'third_party_kext_count': len(kext_list)})

        return True

#Test the status of FileVault
    def get_filevault_status(self):
        """
        Checks the status of the filevault by running a few commands.
        :return: A Bool of the filevault status
        """

        fv_status = commands.getoutput('/usr/bin/fdesetup status')
        fv_return_status = False

        if fv_status == "FileVault is On.":
            self.score += 1
            return True

        self.master_dict.update({'firewall_status': fv_return_status})
        self.jamf_results = "<result>%s</result>" % fv_return_status

        return True

#Test gatekeeper status
    def get_gatekeeper_status(self):
        """
        Checks the status of Gatekeeper
        :return: Bool of the gatekeeper status
        """

        status = commands.getoutput('/usr/sbin/spctl --status')
        gatekeeper_status = False

        if 'assessments enabled' == status:
            gatekeeper_status = True
            self.score += 1

        self.master_dict.update(
            {
                'gatekeeper_status': gatekeeper_status
            }
        )

        self.jamf_results = '<result>%s</result>' % gatekeeper_status
        return gatekeeper_status

#Test for available updates from the app store
    def get_available_updates(self, quick=False):

        header = """Software Update Tool

Finding available software"""

        command_string = "/usr/sbin/softwareupdate -l"

        if quick:
            command_string += ' --no-scan'

        availables_update = commands.getoutput(command_string).replace(header, '').split('\n')
        update_list = []



        for update in availables_update:

            if update == 'software Update found the following new or updated software:':
                self.master_dict.update({'available_updates', True})

            # This is just to get the line with the important update information.
            elif '),'in update:

                recommended = False
                restart_required = False

                if '[recommended]' in update:
                    recommended = True

                if '[restart]' in update:
                    restart_required = True

                parsed_update = update.split(',')
                update_list.append({
                    'name': update.split('(')[0].strip(),
                    #'version': parsed_update[0].split()[-1],
                    'size': parsed_update[1].split()[0],
                    'recommended': recommended,
                    'restart_required': restart_required
                }
                )

        self.master_dict.update({
            'available_updates': update_list,
            'available_updates_count': len(update_list)
        })

        self.jamf_results = "<result>%s</result>" % len(update_list)

        if len(update_list) < 1:
            self.score += 1
            return True

        return False


#Test for firewall status
    def get_firewall_status(self):
        """
        Returns several key elements related to the application firewall on the endpoint.
        :return: Bool of the firewall status
        """

        fw_dict = {}

        firewall_status = False

        fw_status = int(commands.getoutput('/usr/bin/defaults read /Library/Preferences/com.apple.alf globalstate'))
        fw_blockall = commands.getoutput('/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall')
        fw_allow_signed = commands.getoutput('/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned')
        fw_stealth_mode = commands.getoutput('/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode')
        fw_list_allowed_apps = commands.getoutput('/usr/libexec/ApplicationFirewall/socketfilterfw --listapps')
        fw_allowed_apps_count = int(
            commands.getoutput(
                '/usr/libexec/ApplicationFirewall/socketfilterfw --listapps |  grep -v Block | grep Allow | wc -l'
            )
        )
        fw_logging_mode = commands.getoutput('/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode')

        if fw_status == 1:
            # This means it's enabled
            fw_dict['fw_enabled'] = True
            firewall_status = True
            self.score += 1
        else:
            fw_dict['fw_enabled'] = False

        if fw_blockall == 'Block all DISABLED!':
            fw_dict['block_all'] = False
        else:
            fw_dict['block_all'] = True

        for status in fw_allow_signed.split('\n'):
            if status == 'Automatically allow signed built-in software ENABLED':
                fw_dict['allow_signed_builtin_software'] = True
            elif status == 'Automatically allow signed built-in software DISABLED':
                fw_dict['allow_signed_builtin_software'] = False

            if status == 'Automatically allow downloaded signed software ENABLED':
                fw_dict['allow_signed_downloaded_software'] = True
            elif status == 'Automatically allow downloaded signed software ENABLED':
                fw_dict['allow_signed_downloaded_software'] = False

        if fw_stealth_mode == 'Stealth mode enabled':
            fw_dict['stealth_mode_enabled'] = True
        else:
            fw_dict['stealth_mode_enabled'] = False

        if fw_logging_mode == 'Log mode is on':
            fw_dict['logging_mode_enabled'] = True
        else:
            fw_dict['logging_mode_enabled'] = False

        fw_dict['allowed_apps'] = fw_list_allowed_apps
        fw_dict['allowed_apps_count'] = fw_allowed_apps_count

        self.master_dict.update(fw_dict)

        self.jamf_results = "<result>%s</result>" % firewall_status
        return firewall_status

#Test for current process count
    def get_process_count(self):
        """
        Get a count of the number of processes running on a system.
        :return: dict with the process number count.
        """

        processes = int(commands.getoutput('/bin/ps aux | wc -l'))

        self.master_dict.update({'process_count': processes})
        self.jamf_results = "<result>%s</result>" % processes

        return True

    def _get_system_info(self):
        """

        :return: dict of system information
        """
        # shamelessly stolen from https://gist.github.com/pudquick/c7dd1262bd81a32663f0

        ####

        system_dict = {
            'node_name': os.name,
            'system_type': platform.system(),
            'os_version': platform.mac_ver()[0],
            'hw_summary': system_info()
        }

        self.master_dict.update(system_dict)
        return True

    def get_sip_status(self):
        """
        Check the SIP status of the system.
        :return: Boolean
        """

        status = commands.getoutput('/usr/bin/csrutil status')
        return_status = False

        if status == 'System Integrity Protection status: enabled.':
            self.score += 1
            return_status = True

        self.master_dict.update({'sip_status': return_status})
        self.jamf_results = "<result>%s</result>" % return_status

        return return_status

    def get_listening_services(self):
        """
        Creates a list of things that are listing on an endpoint.
        :return: list of listening services.
        """

        services = commands.getoutput('/usr/sbin/lsof -n -iTCP | grep LISTEN').split('\n')
        services_list = []

        for service in services:
            parsed_services = service.split()
            services_list.append(
                {
                    'name': parsed_services[0],
                    'pid': parsed_services[1],
                    'owner': parsed_services[2],
                    'type': parsed_services[4],
                    'interface': parsed_services[8].split(':')[0],
                    'port': parsed_services[8].split(':')[1]
                }
            )

        self.master_dict.update({'services': services_list, 'services_count': len(services_list)})
        self.jamf_results = "<result>%s</result>" % len(services_list)

        return True

    def get_login_items(self):

        login_items_list = []

        for home_dir in self._build_homedir_list('Library'):

            startup_files = os.listdir(os.path.join(home_dir, 'LaunchAgents'))

            for launchagent in startup_files:
                login_items_list.append(
                    os.path.join(home_dir, 'LaunchAgents', launchagent)
                )

        self.master_dict.update({'login_items': login_items_list, 'login_items_count': len(login_items_list)})
        return True

    def get_last_reboot(self):
        """

        :return: dict with the last reboot time
        """

        # Just grab the top result
        reboot_time = commands.getoutput('/usr/bin/last reboot').split('~')[1].split('\n')[0].strip()

        self.master_dict.update({'reboot_time': reboot_time})

        return True

    def get_sshd_logs(self):

        logs = commands.getoutput('/bin/cat /var/log/system.log | grep sshd').split('\n')
        log_list = []

        for log in logs:
            if len(log) > 0:
                log_list.append(log)

        self.master_dict.update(
            {'sshd_logs': log_list, 'ssh_log_count': len(log_list)}
        )

        return True

    def get_download_dir_file_attrs(self, bat):

        ## TODO: Move the dict update into this method.

        file_list = bat.build_file_list(bat._build_homedir_list())
        bat.get_file_attributes(file_list)

        return True

    def get_master_dict(self, bat):
        self.get_download_dir_file_attrs(bat)
        self._get_system_info()
        self.get_thirdparty_kexts()
        self.get_process_count()
        self.get_listening_services()
        self.get_login_items()
        self.get_last_reboot()
        self.get_sshd_logs()

#Parsing args

        # JAMFable
        self.get_gatekeeper_status()

        #JAMFable
        self.get_sip_status()

        #JAMFable
        self.get_filevault_status()

        #JAMFable
        self.get_firewall_status()

        # JAMFable
        self.get_available_updates()

        return self.master_dict

    def get_score(self):
        """
        This method will check the 5 important attributes and return a score.
        :return:
        """

        self.get_sip_status()
        self.get_firewall_status()
        self.get_available_updates()
        self.get_filevault_status()
        self.get_gatekeeper_status()

        return self.score

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Update Santa Configuration File')
    parse_group = parser.add_mutually_exclusive_group()
    parse_group2 = parser.add_mutually_exclusive_group()

    parse_group2.add_argument('--jamf',
                        help='report a single value for JAMF extended attribute.',
                        choices=['true'])

    parse_group2.add_argument('--all',
                        help="Run all of the methods and return a nice JSON string.",
                        choices=['true'])

    parse_group.add_argument('--gatekeeper',
                             help="Run a test to find gatekeeper status.",
                             choices=['true'])

    parse_group.add_argument('--sip',
                             help="Run a test to find SIP (system Integrity protection) status.",
                             choices=['true'])

    parse_group.add_argument('--score',
                             help="Returns a score (out of 5 possible) to determine the security health of your endpoint."
                             ,choices=['true'])

    parse_group.add_argument('--filevault',
                             help="Run a test to find FileVault status.",
                             choices=['true'])

    parse_group.add_argument('--updates',
                             help="Run a test to find if there are available software updates from the app store, that are not installed.",
                             choices=['true'])

    parse_group.add_argument('--firewall',
                             help="Run a test to find the Firewall Status",
                             choices=['true'])

    args = parser.parse_args()

    # Run if --all flag is listed or if no flags are listed
    sbat = SecurityBat()

    if args.all and not args.jamf:

        master_data = sbat.get_master_dict(sbat)
        print json.dumps(master_data, indent=3)

    if args.score:
        if args.jamf:
            print "<result>%s</result>" % sbat.get_score()
        else:
            print json.dumps(dict({
                'security_score': sbat.get_score()
            })
            )

    if args.gatekeeper:
        if args.jamf:
            print "<result>%s</result>" % sbat.get_gatekeeper_status()
        else:
            print json.dumps(dict({
                'Gatekeeper Enabled': sbat.get_gatekeeper_status()
            })
            )

    if args.sip:
        if args.jamf:
            print "<result>%s</result>" % sbat.get_sip_status()
        else:
            print json.dumps(dict({
                'System Integrety Protection Enabled': sbat.get_sip_status()
            })
            )

    if args.filevault:
        if args.jamf:
            print "<result>%s</result>" % sbat.get_filevault_status()
        else:
            print json.dumps(dict({
                'Filevault2 Enabled': sbat.get_filevault_status()
            })
            )

    if args.updates:
        if args.jamf:
            print "<result>%s</result>" % sbat.get_available_updates()
        else:
            print json.dumps(dict({
                'Updates available': sbat.get_available_updates()
            })
            )

    if args.updates:
        if args.jamf:
            print "<result>%s</result>" % sbat.get_firewall_status()
        else:
            print json.dumps(dict({
                'firewall status': sbat.get_firewall_status()
            })
            )