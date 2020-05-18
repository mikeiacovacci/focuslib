# Copyright 2020 Mike Iacovacci
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from base64 import b64decode
from datetime import datetime
import logging
from os import listdir, path, stat
from random import randrange
from re import search
from shlex import split
from shutil import copyfile
from stat import ST_CTIME
from subprocess import CalledProcessError, call, CompletedProcess, DEVNULL, Popen, run
from sys import stderr
from time import sleep


class FocusLogger(object):

    def __init__(self, log_file=None, message_format=None, log_level=None):

        if log_file is None:
            log_file = str(str(path.expanduser("~/.focus.log")))
        elif isinstance(log_file, str):
            log_file = log_file
        else:
            log_file = False

        if message_format is None:
            message_format = str("%(levelname)s:%(message)s")
        elif isinstance(message_format, str):
            message_format = message_format
        else:
            message_format = False

        if log_level is None:
            log_level = logging.DEBUG
        elif log_level == "CRITICAL":
            log_level = logging.CRITICAL
        elif log_level == "DEBUG":
            log_level = logging.DEBUG
        elif log_level == "ERROR":
            log_level = logging.ERROR
        elif log_level == "INFO":
            log_level = logging.INFO
        elif log_level == "WARNING":
            log_level = logging.WARNING
        else:
            log_level = False

        logging.basicConfig(filename=log_file, format=message_format, level=log_level)
        self.stderr = stderr
        self.logger = logging.getLogger()

    def critical(self, message):
        """ SUMMARY:  Outputs critical text to debug log file
              INPUT:  critical message (str)
             OUTPUT:  no return value, prints to STDERR and file """

        self.logger.critical(message)

    def debug(self, message):
        """ SUMMARY:  Outputs debug text to debug log file
              INPUT:  debug message (str)
             OUTPUT:  no return value, prints to file """

        self.logger.debug(message)

    def error(self, message):
        """ SUMMARY:  Outputs error text to debug log file
              INPUT:  error message (str)
             OUTPUT:  no return value, prints to STDERR and file """

        self.logger.error(message)

    def info(self, message):
        """ SUMMARY:  Outputs info text to debug log file
              INPUT:  info message (str)
             OUTPUT:  no return value, prints to file """

        self.logger.info(message)

    def warning(self, message):
        """ SUMMARY:  Outputs warning text to debug log file
              INPUT:  warning message (str)
             OUTPUT:  no return value, prints to file """

        self.logger.debug(message)


class FocusUserConfiguration(object):

    def __init__(self, logger=None, PCAP_filename_suffix_method=None, readonly_folder_name=None,
                 shared_folder_root_path=None, snapshot_name_prefix=None, snapshot_name_suffix_method=None,
                 snapshot_regex=None, VM_storage_root_path=None, VMware_install_path=None,
                 vmnet_sniffer_binary_path=None, vmnet_sniffer_termination_script_path=None, vmrun_binary_path=None,
                 vmrun_method=None, writeable_folder_name=None):

        if logger is None:
            self.logger = FocusLogger().logger
        elif isinstance(logger, type(FocusLogger().logger)):
            self.logger = logger
        else:
            self.logger = False
            stderr.write("ERROR: Failed in initialize FocusUserConfiguration object. Invalid FocusLogger.\n")
            return

        if PCAP_filename_suffix_method is None:
            self.PCAP_filename_suffix = PCAP_filename_suffix
        elif callable(PCAP_filename_suffix_method):
            self.PCAP_filename_suffix = PCAP_filename_suffix_method
        else:
            self.PCAP_filename_suffix = False

        if readonly_folder_name is None:
            self.readonly_folder_name = "ro"
        elif isinstance(readonly_folder_name, str):
            self.readonly_folder_name = readonly_folder_name
        else:
            self.readonly_folder_name = False

        if shared_folder_root_path is None:
            self.shared_folder_root_path = "/opt/shared/"
        elif isinstance(shared_folder_root_path, str):
            self.shared_folder_root_path = shared_folder_root_path
        else:
            self.shared_folder_root_path = False

        if snapshot_name_prefix is None:
            self.snapshot_name_prefix = "focus-"
        elif isinstance(snapshot_name_prefix, str):
            self.snapshot_name_prefix = snapshot_name_prefix
        else:
            self.snapshot_name_prefix = False

        if snapshot_name_suffix_method is None:
            self.snapshot_name_suffix = snapshot_name_suffix
        elif callable(snapshot_name_suffix_method):
            self.snapshot_name_suffix = snapshot_name_suffix_method
        else:
            self.snapshot_name_suffix = False

        if snapshot_regex is None:
            if snapshot_name_suffix_method is None:
                self.snapshot_regex = str(self.snapshot_name_prefix + "[0-9a-z]{6,7}$")
            else:
                self.snapshot_regex = False
        elif isinstance(snapshot_regex, str):
            self.snapshot_regex = snapshot_regex
        else:
            self.snapshot_regex = False

        if VM_storage_root_path is None:
            self.VM_storage_root_path = "/opt/vms/"
        elif isinstance(VM_storage_root_path, str):
            self.VM_storage_root_path = VM_storage_root_path
        else:
            self.VM_storage_root_path = False

        if VMware_install_path is None:
            self.VMware_install_path = "/Applications/VMware Fusion.app/Contents/"
        elif isinstance(VMware_install_path, str):
            self.VMware_install_path = VMware_install_path
        else:
            self.VMware_install_path = False

        if vmnet_sniffer_binary_path is None and isinstance(self.VMware_install_path, str):
            self.vmnet_sniffer_binary_path = str(self.VMware_install_path + "Library/vmnet-sniffer")
        elif isinstance(vmnet_sniffer_binary_path, str):
            self.vmnet_sniffer_binary_path = vmnet_sniffer_binary_path
        else:
            self.vmnet_sniffer_binary_path = False

        if vmnet_sniffer_termination_script_path is None:
            self.vmnet_sniffer_termination_script_path = "/opt/focus/lib/kill-vmnet-sniffer.sh"
        elif isinstance(vmnet_sniffer_termination_script_path, str):
            self.vmnet_sniffer_termination_script_path = vmnet_sniffer_termination_script_path
        else:
            self.vmnet_sniffer_termination_script_path = False

        if vmrun_binary_path is None and isinstance(self.VMware_install_path, str):
            self.vmrun_binary_path = str(self.VMware_install_path + "Public/vmrun")
        elif isinstance(vmrun_binary_path, str):
            self.vmrun_binary_path = vmrun_binary_path
        else:
            self.vmrun_binary_path = False

        if vmrun_method is None:
            self.vmrun = vmrun
        elif callable(vmrun_method):
            self.vmrun = vmrun_method
        else:
            self.vmrun = False

        if writeable_folder_name is None:
            self.writeable_folder_name = "rw"
        elif isinstance(writeable_folder_name, str):
            self.writeable_folder_name = writeable_folder_name
        else:
            self.writeable_folder_name = False


class VMwareFusionPro(object):

    def __init__(self, config=None, full_initialization=True):

        if config is None:
            self.config = FocusUserConfiguration()
            self.config.logger.debug("VMwareFusionPro:__init__:self.config = FocusUserConfiguration()")
        elif isinstance(config, FocusUserConfiguration):
            self.config = config
            self.config.logger.debug("VMwareFusionPro:__init__:self.config = config")
        else:
            self.config = False
            stderr.write("ERROR: Failed in initialize VMwareFusionPro object. Invalid FocusUserConfiguration.\n")
            return

        self.config.logger.debug("VMwareFusionPro:__init__:Retrieving running_VMX_list")
        self.running_VMX_list = self.get_running_VMXes()

        self.running_VMs = []
        if full_initialization is True:
            self.config.logger.debug("VMwareFusionPro:__init__:Instantiating running_VMs")
            self.refresh()
        self.config.logger.info("VMwareFusionPro:__init__:Initialization complete.")

    def get_running_VMXes(self):
        """ SUMMARY:  retrieves list of running VM .vmx full file paths via vmrun subprogram
              INPUT:  none
             OUTPUT:  listing of full file paths for corresponding running VMs (list of strings) or False on error """

        if not self.config or not isinstance(self.config, FocusUserConfiguration):
            stderr.write("ERROR: Invalid FocusUserConfiguration.\n")
            return False

        if not self.config.vmrun_binary_path or not isinstance(self.config.vmrun_binary_path, str):
            self.config.logger.error("VMwareFusionPro:get_running_VMXes:Invalid or missing vmrun_binary_path.")
            return False

        if not self.config.vmrun or not callable(self.config.vmrun):
            self.config.logger.error("VMwareFusionPro:get_running_VMXes:Invalid or missing vmrun method.")
            return False

        VMX_list = []

        self.config.logger.debug("VMwareFusionPro:get_running_VMXes:Calling vmrun method.")
        vmrun_proc = self.config.vmrun(self.config.vmrun_binary_path, "list")

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.config.logger.error("VMwareFusionPro:get_running_VMXes:Invalid or missing vmrun_binary_path.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.config.logger.error("VMwareFusionPro:get_running_VMXes:Invalid return code from vmrun subprocess.")
            return False

        if vmrun_proc.returncode == 0:
            output_lines = vmrun_proc.stdout.decode().split("\n")
            for line in output_lines:
                if search("vmx$", str(line)):
                    VMX_list.append(line)
            self.config.logger.info(str("VMwareFusionPro:get_running_VMXes:" +
                                        str(VMX_list.__len__()) + " running VMs."))
            self.config.logger.info("VMwareFusionPro:get_running_VMXes:Success")
            return VMX_list
        else:
            self.config.logger.error("VMwareFusionPro:get_running_VMXes:Non-zero return code for vmrun subprocess.")
            return False

    def refresh(self):
        """ SUMMARY:  instantiates virtual machine objects (which inherit config settings) for each running VMX
              INPUT:  none
             OUTPUT:  True or False if an error occurs """

        if not self.config or not isinstance(self.config, FocusUserConfiguration):
            stderr.write("ERROR: Invalid FocusUserConfiguration.\n")
            self.running_VMs = False
            return False

        if not self.running_VMX_list or not isinstance(self.running_VMX_list, list):
            self.running_VMs = False
            self.config.logger.error("VMwareFusionPro:refresh:Invalid or missing running_VMX_list.")
            return False

        if self.running_VMX_list.__len__() <= 0:
            self.config.logger.info("VMwareFusionPro:refresh:No VMs currently running.")
            self.running_VMs = False
            self.config.logger.info("VMwareFusionPro:refresh:Success")
            return True
        else:
            for VMX_file in self.running_VMX_list:
                self.config.logger.info(str("VMwareFusionPro:refresh:Instantiating " + VMX_file))
                self.running_VMs.append(VMwareFusionVirtualMachine(VMX_file, config=self.config, running=True))

            self.config.logger.info("VMwareFusionPro:refresh:Success")
            return True


class VMwareFusionVirtualMachine(object):

    def __init__(self, VMX_file_path, config=None, VMX_file_path_quoted=None, VMX_file_content=None, display_name=None,
                 get_password_method=None, get_username_method=None, ip_address=None, last_focus_snapshot=None,
                 last_snapshot=None, password=None, PCAP_filename_prefix=None, primary_network_interface=None,
                 vmnet=None, primary_readonly_shared_folder=None, primary_writeable_shared_folder=None, running=None,
                 shared_folders=None, snapshots=None, username=None, VM_folder=None):

        if isinstance(VMX_file_path, str):
            self.VMX_file_path = VMX_file_path
        else:
            self.VMX_file_path = False
            stderr.write("ERROR: Failed in initialize VMwareFusionVirtualMachine object. Invalid VMX_file_path.\n")
            return

        if config is None:
            init_config = FocusUserConfiguration()
            self.logger = init_config.logger
            self.PCAP_filename_suffix = init_config.PCAP_filename_suffix
            self.readonly_folder_name = init_config.readonly_folder_name
            self.shared_folder_root_path = init_config.shared_folder_root_path
            self.snapshot_name_prefix = init_config.snapshot_name_prefix
            self.snapshot_name_suffix = init_config.snapshot_name_suffix
            self.snapshot_regex = init_config.snapshot_regex
            self.VM_storage_root_path = init_config.VM_storage_root_path
            self.VMware_install_path = init_config.VMware_install_path
            self.vmnet_sniffer_binary_path = init_config.vmnet_sniffer_binary_path
            self.vmnet_sniffer_termination_script_path = init_config.vmnet_sniffer_termination_script_path
            self.vmrun_binary_path = init_config.vmrun_binary_path
            self.vmrun = init_config.vmrun
            self.writeable_folder_name = init_config.writeable_folder_name
            self.logger.info("VMwareFusionVirtualMachine:__init__:Configuration processing complete.")
        elif isinstance(config, FocusUserConfiguration):
            self.logger = config.logger
            self.PCAP_filename_suffix = config.PCAP_filename_suffix
            self.readonly_folder_name = config.readonly_folder_name
            self.shared_folder_root_path = config.shared_folder_root_path
            self.snapshot_name_prefix = config.snapshot_name_prefix
            self.snapshot_name_suffix = config.snapshot_name_suffix
            self.snapshot_regex = config.snapshot_regex
            self.VM_storage_root_path = config.VM_storage_root_path
            self.VMware_install_path = config.VMware_install_path
            self.vmnet_sniffer_binary_path = config.vmnet_sniffer_binary_path
            self.vmnet_sniffer_termination_script_path = config.vmnet_sniffer_termination_script_path
            self.vmrun_binary_path = config.vmrun_binary_path
            self.vmrun = config.vmrun
            self.writeable_folder_name = config.writeable_folder_name
            self.logger.info("VMwareFusionVirtualMachine:__init__:Configuration processing complete.")
        else:
            self.logger = False
            self.PCAP_filename_suffix = False
            self.readonly_folder_name = False
            self.shared_folder_root_path = False
            self.snapshot_name_prefix = False
            self.snapshot_name_suffix = False
            self.snapshot_regex = False
            self.VM_storage_root_path = False
            self.VMware_install_path = False
            self.vmnet_sniffer_binary_path = False
            self.vmnet_sniffer_termination_script_path = False
            self.vmrun_binary_path = False
            self.vmrun = False
            self.writeable_folder_name = False
            stderr.write("ERROR: Failed in initialize VMwareFusionVirtualMachine object. Invalid config.\n")
            return

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.VMX_file_path_quoted")
        if VMX_file_path_quoted is None and isinstance(self.VMX_file_path, str):
            self.VMX_file_path_quoted = str("\"" + self.VMX_file_path + "\"")
        elif isinstance(VMX_file_path_quoted, str):
            self.VMX_file_path_quoted = VMX_file_path_quoted
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid VMX_file_path_quoted.")
            self.VMX_file_path_quoted = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.VMX_file_content")
        if VMX_file_content is None:
            self.VMX_file_content = self.read_vmx()
        elif isinstance(VMX_file_content, list):
            self.VMX_file_content = VMX_file_content
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid VMX_file_content.")
            self.VMX_file_content = VMX_file_content

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.display_name")
        if display_name is None:
            self.display_name = self.get_display_name()
        elif isinstance(display_name, str):
            self.display_name = display_name
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid display_name.")
            self.display_name = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.get_password method")
        if get_password_method is None:
            self.get_password = get_password
        elif callable(get_password_method):
            self.get_password = get_password_method
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid get_password_method.")
            self.get_password = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.VM_folder")
        if VM_folder is None:
            self.VM_folder = str("/".join(self.VMX_file_path.split("/")[:-1]) + "/")
        elif isinstance(VM_folder, str):
            self.VM_folder = VM_folder
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid VM_folder.")
            self.VM_folder = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.get_username method")
        if get_username_method is None:
            self.get_username = get_username
        elif callable(get_username_method):
            self.get_username = get_username_method
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid get_username_method.")
            self.get_username = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.password")
        if password is None:
            self.password = self.get_password(self.VM_folder)
        elif isinstance(password, str):
            self.password = password
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid password.")
            self.password = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.PCAP_filename_prefix")
        if PCAP_filename_prefix is None:
            if self.display_name and isinstance(self.display_name, str):
                self.PCAP_filename_prefix = str(self.display_name + "-")
            else:
                self.PCAP_filename_prefix = "focus-"
        elif isinstance(PCAP_filename_prefix, str):
            self.PCAP_filename_prefix = PCAP_filename_prefix
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid PCAP_filename_prefix.")
            self.PCAP_filename_prefix = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.primary_network_interface")
        if primary_network_interface is None:
            self.primary_network_interface = "ethernet0"
        elif isinstance(primary_network_interface, str):
            self.primary_network_interface = primary_network_interface
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid primary_network_interface.")
            self.primary_network_interface = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.vmnet")
        if vmnet is None:
            self.vmnet = self.get_vmnet()
        elif isinstance(vmnet, str):
            self.vmnet = vmnet
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid vmnet.")
            self.vmnet = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.primary_readonly_shared_folder")
        if primary_readonly_shared_folder is None:
            if self.vmnet and self.shared_folder_root_path and self.readonly_folder_name and \
                    isinstance(self.vmnet, str) and isinstance(self.shared_folder_root_path, str) and \
                    isinstance(self.readonly_folder_name, str):
                self.primary_readonly_shared_folder = str(self.shared_folder_root_path + self.vmnet + "/" +
                                                          self.readonly_folder_name + "/")
            else:
                self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid primary_readonly_shared_folder.")
                self.primary_readonly_shared_folder = False
        elif isinstance(primary_readonly_shared_folder, str):
            self.primary_readonly_shared_folder = primary_readonly_shared_folder
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid primary_readonly_shared_folder.")
            self.primary_readonly_shared_folder = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.primary_writeable_shared_folder")
        if primary_writeable_shared_folder is None:
            if self.vmnet and self.shared_folder_root_path and self.writeable_folder_name and \
                    isinstance(self.vmnet, str) and isinstance(self.shared_folder_root_path, str) and \
                    isinstance(self.writeable_folder_name, str):
                self.primary_writeable_shared_folder = str(self.shared_folder_root_path + self.vmnet + "/" +
                                                           self.writeable_folder_name + "/")
            else:
                self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid primary_writeable_shared_folder.")
                self.primary_writeable_shared_folder = False
        elif isinstance(primary_writeable_shared_folder, str):
            self.primary_writeable_shared_folder = primary_writeable_shared_folder
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid primary_writeable_shared_folder.")
            self.primary_writeable_shared_folder = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.running")
        if running is True:
            self.running = True
        else:
            self.running = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.shared_folders")
        if shared_folders is None:
            self.shared_folders = self.get_shared_folders()
        elif isinstance(shared_folders, list):
            self.shared_folders = shared_folders
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid shared_folders.")
            self.shared_folders = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.snapshots")
        if snapshots is None:
            self.snapshots = self.get_snapshots()
        elif isinstance(snapshots, list):
            self.snapshots = snapshots
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid snapshots.")
            self.snapshots = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.ip_address")
        if ip_address is None:
            self.ip_address = self.get_ip_address()
        elif isinstance(ip_address, str):
            self.ip_address = ip_address
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid ip_address.")
            self.ip_address = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.last_focus_snapshot")
        if last_focus_snapshot is None:
            if isinstance(self.snapshots, list):
                self.last_focus_snapshot = self.get_last_focus_snapshot()
            else:
                self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid snapshots.")
        elif isinstance(last_focus_snapshot, str):
            self.last_focus_snapshot = last_focus_snapshot
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid last_focus_snapshot.")
            self.last_focus_snapshot = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.last_snapshot")
        if last_snapshot is None:
            if isinstance(self.snapshots, list):
                if self.snapshots.__len__() > 0:
                    self.last_snapshot = self.snapshots[-1]
                else:
                    self.last_snapshot = False
            else:
                self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid snapshots.")
                self.last_snapshot = False
        elif isinstance(last_snapshot, str):
            self.last_snapshot = last_snapshot
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid last_snapshot.")
            self.last_snapshot = False

        self.logger.debug("VMwareFusionVirtualMachine:__init__:Setting self.username")
        if username is None:
            self.username = self.get_username(self.VM_folder)
        elif isinstance(username, str):
            self.username = username
        else:
            self.logger.error("VMwareFusionVirtualMachine:__init__:Invalid username.")
            self.username = False

        self.logger.info("VMwareFusionVirtualMachine:__init__:Initialization complete.")

    def acquire_memory_sample(self, destination_path=None, snapshot_name=None):
        """ SUMMARY:  creates a temporary VM snapshot and copies its .vmem and .vmsn files to a specified directory
              INPUT:  1) destination folder where the files are saved (str) 2) name for temporary snapshot (str)
             OUTPUT:  True or False """

        if not self.VM_folder or not isinstance(self.VM_folder, str):
            self.logger.error("VMwareFusionVirtualMachine:acquire_memory_sample:Invalid VM_folder.")
            return False

        if not self.display_name or not isinstance(self.display_name, str):
            self.logger.error("VMwareFusionVirtualMachine:acquire_memory_sample:Invalid display_name.")
            return False

        if snapshot_name is None:
            if isinstance(self.snapshot_name_prefix, str):
                snapshot_name = str(self.snapshot_name_prefix + "VMEM-ACQUISITION")
            else:
                self.logger.error("VMwareFusionVirtualMachine:acquire_memory_sample:Invalid snapshot_name_prefix.")
                return False

        if destination_path is None:
            if isinstance(self.primary_readonly_shared_folder, str):
                destination_path = self.primary_readonly_shared_folder
            else:
                self.logger.error(str("VMwareFusionVirtualMachine:acquire_memory_sample:" +
                                      "Invalid primary_readonly_shared_folder."))
                return False

        if not path.exists(destination_path) or not self.snapshot(snapshot_name):
            self.logger.error(str("VMwareFusionVirtualMachine:acquire_memory_sample:" +
                                  "Invalid destination_path and/or snapshot_name."))
            return False

        all_files = []
        results = []

        self.logger.debug("VMwareFusionVirtualMachine:acquire_memory_sample:Enumerating files in VM_folder.")
        try:
            for filename in listdir(self.VM_folder):
                all_files.append(path.join(self.VM_folder, filename))
        except OSError:
            self.logger.error(str("VMwareFusionVirtualMachine:acquire_memory_sample:" +
                                  "OS error while enumerating files in VM_folder."))
            return False
        else:
            self.logger.debug("VMwareFusionVirtualMachine:acquire_memory_sample:Searching for .vmem files.")
            for filename in all_files:
                if search("-Snapshot[0-9]+.vmem$", filename):
                    results.append((stat(filename), filename))

            target_VMEM_file = sorted(results, key=lambda x: x[0][ST_CTIME], reverse=True)[0][1]
            target_VMSN_file = str(target_VMEM_file[:-5] + ".vmsn")

            if target_VMEM_file:
                destination_VMEM = str(destination_path + self.display_name + "-" +
                                       str(datetime.utcnow().strftime("%Y-%b-%d-%H%M%S")) + "-UTC.vmem")
                self.logger.debug("VMwareFusionVirtualMachine:acquire_memory_sample:Copying .vmem file.")
                try:
                    copyfile(target_VMEM_file, destination_VMEM)
                except OSError:
                    self.logger.error(str("VMwareFusionVirtualMachine:acquire_memory_sample:" +
                                          "OS error while copying target_VMEM_file to destination_file."))
                    return False
            else:
                self.logger.error("VMwareFusionVirtualMachine:acquire_memory_sample:No target_VMEM_file found.")
                return False

            if target_VMSN_file:
                destination_VMSN = str(destination_VMEM[:-5] + ".vmsn")
                self.logger.debug("VMwareFusionVirtualMachine:acquire_memory_sample:Copying .vmsn file.")
                try:
                    copyfile(target_VMSN_file, destination_VMSN)
                except OSError:
                    self.logger.error(str("VMwareFusionVirtualMachine:acquire_memory_sample:" +
                                          "OS error while copying target_VMEM_file to destination_file."))
                    return False
            else:
                self.logger.error("VMwareFusionVirtualMachine:acquire_memory_sample:No target_VMSN_file found.")
                return False

        self.logger.debug("VMwareFusionVirtualMachine:acquire_memory_sample:Deleting temporary snapshot.")
        if not self.delete_snapshot(snapshot_name):
            self.logger.error("VMwareFusionVirtualMachine:acquire_memory_sample:Failed to delete temporary snapshot.")
            return False

        self.logger.info("VMwareFusionVirtualMachine:acquire_memory_sample:Success")
        return True

    def capture_vmnet_packets(self, duration_seconds, destination_path=None):
        """ SUMMARY:  initiates vmnet-sniffer subprogram to write virtual network packets to a file
              INPUT:  1) number of seconds to capture packets (int) 2) destination folder for .pcap file (str)
             OUTPUT:  True or False """

        if not isinstance(duration_seconds, int):
            self.logger.error("VMwareFusionVirtualMachine:capture_vmnet_packets:Invalid duration_seconds.")
            return False

        if not self.vmnet:
            self.logger.error("VMwareFusionVirtualMachine:capture_vmnet_packets:Missing vmnet.")
            return False

        if not isinstance(self.PCAP_filename_prefix, str) or not callable(self.PCAP_filename_suffix):
            self.logger.error(str("VMwareFusionVirtualMachine:capture_vmnet_packets:" +
                                  "Invalid PCAP_filename_prefix and/or PCAP_filename_suffix method."))
            return False

        PCAP_suffix = self.PCAP_filename_suffix()

        if not isinstance(PCAP_suffix, str):
            self.logger.error("VMwareFusionVirtualMachine:capture_vmnet_packets:Invalid PCAP_suffix.")
            return False

        if destination_path is None:
            if self.primary_readonly_shared_folder and isinstance(self.primary_readonly_shared_folder, str):
                destination_path = self.primary_readonly_shared_folder
            else:
                self.logger.error(str("VMwareFusionVirtualMachine:capture_vmnet_packets:" +
                                      "Invalid primary_readonly_shared_folder."))
                return False

        if not isinstance(destination_path, str):
            self.logger.error("VMwareFusionVirtualMachine:capture_vmnet_packets:Invalid destination_path.")
            return False

        PCAP_file = str(destination_path + self.PCAP_filename_prefix + str(duration_seconds) + "s-" + PCAP_suffix)

        try:
            with open(PCAP_file, mode="w"):
                pass
        except OSError:
            self.logger.error("VMwareFusionVirtualMachine:capture_vmnet_packets:Failed to create PCAP_file.")
            return False
        else:
            self.logger.debug("VMwareFusionVirtualMachine:capture_vmnet_packets:Running vmnet-sniffer.")
            proc = self.vmnet_sniffer(self.vmnet, PCAP_file)

            if proc:
                timer = 0
                while timer < duration_seconds:
                    sleep(1)
                    timer += 1
                self.logger.debug("VMwareFusionVirtualMachine:capture_vmnet_packets:Terminating vmnet-sniffer.")
                if not self.terminate_vmnet_sniffer(proc.pid):
                    self.logger.error(str("VMwareFusionVirtualMachine:capture_vmnet_packets:" +
                                          "Failed to terminate vmnet-sniffer subprocess."))
                    return False
                else:
                    self.logger.info("VMwareFusionVirtualMachine:capture_vmnet_packets:Success")
                    return True
            else:
                self.logger.error("VMwareFusionVirtualMachine:capture_vmnet_packets:Failed to run vmnet-sniffer.")
                return False

    def connect_device(self, device_name):
        """ SUMMARY:  causes VMware to connect the named device to the VM
              INPUT:  name of the device to connect (str)
             OUTPUT:  True or False """

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:connect_device:Invalid or missing vmrun method.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:connect_device:Invalid or missing vmrun_binary_path.")
            return False

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:connect_device:Invalid or missing VMX_file_path_quoted.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:connect_device:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("connectNamedDevice " + self.VMX_file_path_quoted +
                                                            str(" " + device_name)))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:connect_device:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:connect_device:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:connect_device:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:connect_device:Nonzero return code from vmrun.")
            return False

    def create_linked_clone(self, snapshot_name, clone_name, destination_path=None):
        """ SUMMARY:  creates a new VM, via linked cloning, from a specified source snapshot
              INPUT:  1) name of source snapshot (str) 2) name of new clone (str) 3) folder to store new VM (str)
             OUTPUT:  True or False """

        if destination_path is None:
            if isinstance(self.VM_storage_root_path, str):
                destination_path = self.VM_storage_root_path
            else:
                self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Invalid destination_path.")
                return False
        elif not isinstance(destination_path, str):
            return False

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Invalid vmrun_binary_path.")
            return False

        if not snapshot_name or not isinstance(snapshot_name, str):
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Invalid snapshot_name.")
            return False

        if not clone_name or not isinstance(clone_name, str):
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Invalid clone_name.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:create_linked_clone:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("clone " + self.VMX_file_path_quoted + " " +
                                                            destination_path + " linked -snapshot=\"" +
                                                            snapshot_name + "\" -cloneName=\"" + clone_name + "\""))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:create_linked_clone:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:create_linked_clone:Nonzero return code from vmrun.")
            return False

    def delete_snapshot(self, snapshot_name):
        """ SUMMARY:  deletes the specified snapshot
              INPUT:  name of the snapshot to be deleted (str)
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot:Invalid vmrun_binary_path.")
            return False

        if not snapshot_name or not isinstance(snapshot_name, str):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot:Invalid snapshot_name.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:delete_snapshot:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("deleteSnapshot " + self.VMX_file_path_quoted + " \"" +
                                                            snapshot_name + "\""))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:delete_snapshot:Success")
            return True
        else:
            if vmrun_proc.returncode == 255 and search(" ", self.VMX_file_path_quoted) and \
                    vmrun_proc.stdout.decode() == "Error: The specified directory is not empty\n":
                self.logger.warning("VMwareFusionVirtualMachine:delete_snapshot:Ignoring vmrun deleteSnapshot bug.")
                self.logger.info("VMwareFusionVirtualMachine:delete_snapshot:Success")
                return True
            else:
                self.logger.error("VMwareFusionVirtualMachine:delete_snapshot:Nonzero return code from vmrun.")
                return False

    def delete_snapshot_and_children(self, snapshot_name):
        """ SUMMARY:  deletes the specified snapshot and all child snapshots
              INPUT:  name of the main snapshot to be deleted (str)
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot_and_children:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot_and_children:Invalid vmrun_binary_path.")
            return False

        if not snapshot_name or not isinstance(snapshot_name, str):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot_and_children:Invalid snapshot_name.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot_and_children:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:delete_snapshot_and_children:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("deleteSnapshot " + self.VMX_file_path_quoted + " \"" +
                                                            snapshot_name + "\" andDeleteChildren"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error(str("VMwareFusionVirtualMachine:delete_snapshot_and_children:" +
                                  "CompletedProcess not returned by vmrun."))
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot_and_children:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:delete_snapshot_and_children:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:delete_snapshot_and_children:Nonzero return code from vmrun.")
            return False

    def disconnect_device(self, device_name):
        """ SUMMARY:  causes VMware to disconnect the named device from the VM
              INPUT:  name of the device to disconnect (str)
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:disconnect_device:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:disconnect_device:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:disconnect_device:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:disconnect_device:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("disconnectNamedDevice " + self.VMX_file_path_quoted +
                                                            str(" " + device_name)))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:disconnect_device:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:disconnect_device:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:disconnect_device:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:disconnect_device:Nonzero return code from vmrun.")
            return False

    def get_snapshots(self):
        """ SUMMARY:  retrieves ordered listing of all VM snapshots
              INPUT:  none
             OUTPUT:  chronological listing of all VM snapshots, oldest is at zero index (list) or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:get_snapshots:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:get_snapshots:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:get_snapshots:Invalid vmrun method.")
            return False

        snapshot_list = []

        self.logger.debug("VMwareFusionVirtualMachine:get_snapshots:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("listSnapshots " + self.VMX_file_path_quoted))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:get_snapshots:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:get_snapshots:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            output = vmrun_proc.stdout.decode().split("\n")[:-1][1:]
            if output.__len__() >= 0:
                for snapshot in output:
                    snapshot_list.append(snapshot)
                self.logger.info("VMwareFusionVirtualMachine:get_snapshots:Success")
                return snapshot_list
            else:
                self.logger.info("VMwareFusionVirtualMachine:get_snapshots:No snapshots found.")
                return False
        else:
            self.logger.error("VMwareFusionVirtualMachine:get_snapshots:Nonzero return code from vmrun.")
            return False

    def get_display_name(self):
        """ SUMMARY:  parses the VM's .vmx file contents for the display name attribute
              INPUT:  none
             OUTPUT:  VM display name value (str) or False on error """

        for line in self.VMX_file_content:
            if search("displayName", line):
                self.logger.info("VMwareFusionVirtualMachine:get_display_name:Success")
                return line.split("\"")[1]

        self.logger.warning("VMwareFusionVirtualMachine:get_display_name:No display name found.")
        return False

    def get_ip_address(self):
        """ SUMMARY:  retrieves the IP address of the VM's guest OS via vmrun
              INPUT:  none
             OUTPUT:  VM's IP address (str) or False on error """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:get_ip_address:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:get_ip_address:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:get_ip_address:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:get_ip_address:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("getGuestIPAddress " + self.VMX_file_path_quoted))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:get_ip_address:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:get_ip_address:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:get_ip_address:Success")
            return vmrun_proc.stdout.decode().split("\n")[0]
        else:
            self.logger.warning("VMwareFusionVirtualMachine:get_ip_address:Nonzero return code from vmrun.")
            return False

    def get_last_focus_snapshot(self):
        """ SUMMARY:  finds the most-recent VM snapshot taken by focus via vmrun and regex name matching
              INPUT:  none
             OUTPUT:  name of most recent focus snapshot (str) or False """

        if not self.snapshots:
            self.logger.info("VMwareFusionVirtualMachine:get_last_focus_snapshot:No snapshots.")
            return False

        if not isinstance(self.snapshots, list):
            self.logger.info("VMwareFusionVirtualMachine:get_last_focus_snapshot:Invalid snapshots.")
            return False

        if not self.snapshot_regex or not isinstance(self.snapshot_regex, str):
            self.logger.info("VMwareFusionVirtualMachine:get_last_focus_snapshot:Invalid snapshot_regex.")
            return False

        index = self.snapshots.__len__()
        while index > 0:
            if search(self.snapshot_regex, self.snapshots[index - 1]):
                self.logger.info("VMwareFusionVirtualMachine:get_last_focus_snapshot:Success")
                return self.snapshots[index - 1]
            index -= 1

        self.logger.info("VMwareFusionVirtualMachine:get_last_focus_snapshot:No snapshots found.")
        return False

    def get_shared_folders(self):
        """ SUMMARY:  parse VM's .vmx file content to retrieve listing of all configured shared folders
              INPUT:  none
             OUTPUT:  a list of dictionaries describing the shared folder attributes or False """

        if not self.VMX_file_content or not isinstance(self.VMX_file_content, list):
            self.logger.error("VMwareFusionVirtualMachine:get_shared_folders:Invalid or missing VMX_file_content.")
            return False

        maxNum = int()
        shared_folder_list = []

        self.logger.debug("VMwareFusionVirtualMachine:get_shared_folders:Searching VMX content for maxNum value.")
        for line in self.VMX_file_content:
            if search("^sharedFolder.maxNum", line):
                maxNum = int(line.split("\"")[1])
                break

        if maxNum > 0:
            current_dict = {}
            for i in range(maxNum):
                current_dict.update({"id": i})
                for line in self.VMX_file_content:
                    if search(str("^sharedFolder" + str(i)), line):
                        self.logger.debug(
                            "VMwareFusionVirtualMachine:get_shared_folders:Found 'sharedFolder' line in VMX content.")
                        if search("present", line):
                            self.logger.debug(
                                "VMwareFusionVirtualMachine:get_shared_folders:Found 'present' line in VMX content.")
                            if line.split("\"")[1] == "TRUE":
                                current_dict.update({"present": True})
                            else:
                                current_dict.update({"present": False})

                        if search("enabled", line):
                            self.logger.debug(
                                "VMwareFusionVirtualMachine:get_shared_folders:Found 'enabled' line in VMX content.")
                            if line.split("\"")[1] == "TRUE":
                                current_dict.update({"enabled": True})
                            else:
                                current_dict.update({"enabled": False})

                        if search("readAccess", line):
                            self.logger.debug(
                                "VMwareFusionVirtualMachine:get_shared_folders:Found 'readAccess' line in VMX content.")
                            if line.split("\"")[1] == "TRUE":
                                current_dict.update({"readAccess": True})
                            else:
                                current_dict.update({"readAccess": False})

                        if search("writeAccess", line):
                            self.logger.debug(str(
                                "VMwareFusionVirtualMachine:get_shared_folders:" +
                                "Found 'writeAccess' line in VMX content."))
                            if line.split("\"")[1] == "TRUE":
                                current_dict.update({"writeAccess": True})
                            else:
                                current_dict.update({"writeAccess": False})

                        if search("hostPath", line):
                            self.logger.debug(
                                "VMwareFusionVirtualMachine:get_shared_folders:Found 'hostPath' line in VMX content.")
                            current_dict.update({"hostPath": str(line.split("\"")[1] + "/")})

                        if search("guestName", line):
                            self.logger.debug(
                                "VMwareFusionVirtualMachine:get_shared_folders:Found 'guestName' line in VMX content.")
                            current_dict.update({"guestName": line.split("\"")[1]})
                shared_folder_list.append(current_dict)
                current_dict = {}

            self.logger.info("VMwareFusionVirtualMachine:get_shared_folders:Success")
            return shared_folder_list

        else:
            self.logger.info("VMwareFusionVirtualMachine:get_shared_folders:No shared folders configured.")
            return False

    def get_vmnet(self, network_interface=None):
        """ SUMMARY:  parses target VM's .vmx file content for networking details to identify the vmnet in use
              INPUT:  name of network interface (str)
             OUTPUT:  vmnet name (str) or False """

        if not self.VMX_file_content or not isinstance(self.VMX_file_content, list):
            self.logger.error("VMwareFusionVirtualMachine:get_vmnet:Invalid or missing VMX_file_content.")
            return False

        if network_interface is None:
            if self.primary_network_interface and isinstance(self.primary_network_interface, str):
                network_interface = self.primary_network_interface
            else:
                self.logger.error("VMwareFusionVirtualMachine:get_vmnet:Invalid network_interface.")
                return False
        elif not isinstance(network_interface, str):
            self.logger.error("VMwareFusionVirtualMachine:get_vmnet:Invalid network_interface.")
            return False

        connectionType_pattern = str(network_interface + ".connectionType")
        vnet_pattern = str(network_interface + ".vnet")

        self.logger.debug("VMwareFusionVirtualMachine:get_vmnet:Searching VMX content for vmnet.")
        for line in self.VMX_file_content:

            if search(connectionType_pattern, line):
                self.logger.debug("VMwareFusionVirtualMachine:get_vmnet:Found 'connectionType' line in VMX content.")
                if line.split("\"")[1] == "custom":
                    self.logger.debug("VMwareFusionVirtualMachine:get_vmnet:Found 'custom' line in VMX content.")
                    continue

                elif line.split("\"")[1] == "nat":
                    self.logger.debug("VMwareFusionVirtualMachine:get_vmnet:Found 'nat' line in VMX content.")
                    self.logger.info("VMwareFusionVirtualMachine:get_vmnet:Success")
                    return "vmnet8"

                elif line.split("\"")[1] == "hostonly":
                    self.logger.debug("VMwareFusionVirtualMachine:get_vmnet:Found 'hostonly' line in VMX content.")
                    self.logger.info("VMwareFusionVirtualMachine:get_vmnet:Success")
                    return "vmnet1"

                else:
                    self.logger.warning("VMwareFusionVirtualMachine:get_vmnet:Unknown or missing connection type.")
                    pass

            elif search(vnet_pattern, line):
                self.logger.debug("VMwareFusionVirtualMachine:get_vmnet:Found 'vnet' line in VMX content.")
                self.logger.info("VMwareFusionVirtualMachine:get_vmnet:Success")
                return line.split("\"")[1]

        self.logger.info("VMwareFusionVirtualMachine:get_vmnet:No vmnet configuration found.")
        return False

    def pause(self):
        """ SUMMARY:  causes VMware to pause the VM's execution
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:pause:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:pause:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:pause:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:pause:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("pause " + self.VMX_file_path_quoted))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:pause:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:pause:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:pause:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:pause:Nonzero return code from vmrun.")
            return False

    def read_vmx(self):
        """ SUMMARY:  reads the target VM's .vmx file content into memory
              INPUT:  none
             OUTPUT:  VMX file content (list of strings) or False if an error occurs """

        if not self.VMX_file_path or not isinstance(self.VMX_file_path, str):
            self.logger.error("VMwareFusionVirtualMachine:read_vmx:Invalid VMX_file_path.")
            return False

        VMX_lines = []

        self.logger.debug("VMwareFusionVirtualMachine:read_vmx:Opening VMX file.")
        if path.exists(self.VMX_file_path):
            try:
                VMX_file = open(self.VMX_file_path, mode="r")
            except OSError:
                self.logger.error("VMwareFusionVirtualMachine:read_vmx:OS error while reading VMX file.")
                return False
            else:
                for line in VMX_file:
                    VMX_lines.append(line)
                self.logger.info("VMwareFusionVirtualMachine:read_vmx:Success")
                return VMX_lines
        else:
            self.logger.error("VMwareFusionVirtualMachine:read_vmx:Specified VMX file does not exist.")
            return False

    def reset(self):
        """ SUMMARY:  causes VMware to perform a hard reset of the VM
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:reset:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:reset:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:reset:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:reset:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("reset " + self.VMX_file_path_quoted + " hard"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:reset:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:reset:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:reset:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:reset:Nonzero return code from vmrun.")
            return False

    def reset_soft(self):
        """ SUMMARY:  causes VMware to soft-reset the VM
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:reset_soft:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:reset_soft:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:reset_soft:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:reset_soft:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("reset " + self.VMX_file_path_quoted + " soft"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:reset_soft:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:reset_soft:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:reset_soft:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:reset_soft:Nonzero return code from vmrun.")
            return False

    def revert_to_snapshot(self, snapshot_name):
        """ SUMMARY:  causes VMware to delete current execution state and restore to the state of a specified snapshot
              INPUT:  name of the snapshot to which the VM's execution state will be restored (str)
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:revert_to_snapshot:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:revert_to_snapshot:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:revert_to_snapshot:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:revert_to_snapshot:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("revertToSnapshot " + self.VMX_file_path_quoted + " " +
                                                            snapshot_name))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:revert_to_snapshot:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:revert_to_snapshot:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:revert_to_snapshot:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:revert_to_snapshot:Nonzero return code from vmrun.")
            return False

    def run_program(self, program_path, program_arguments=None):
        """ SUMMARY:  authenticates to the VM's OS and executes a specified program within the guest
              INPUT:  1) path to the program on the VM's filesystem (str) 2) optional program arguments (str)
             OUTPUT:  True or False """

        if not program_path or not isinstance(program_path, str):
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid program_path.")
            return False

        if program_arguments is None:
            program_arguments = ""
        elif isinstance(program_arguments, str):
            program_arguments = str(" \"" + program_arguments + "\"")
        else:
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid program_arguments.")
            return False

        if not self.username or not self.password:
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid or missing username and/or password.")
            return False
        elif isinstance(self.username, str) and isinstance(self.password, str):
            auth_flags = str("-gu \"" + self.username + "\" -gp \"" + self.password + "\"")
        else:
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid username and/or password.")
            return False

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:run_program:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str(auth_flags + " runProgramInGuest " +
                                                            self.VMX_file_path_quoted + " " +
                                                            program_path + program_arguments))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:run_program:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:run_program:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:run_program:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:run_program:Nonzero return code from vmrun.")
            return False

    def start(self):
        """ SUMMARY:  causes VMware to start the powered-off or suspended VM with graphics displayed on the screen
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:start:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:start:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:start:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:start:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("start " + self.VMX_file_path_quoted + " gui"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:start:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:start:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:start:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:start:Nonzero return code from vmrun.")
            return False

    def start_nogui(self):
        """ SUMMARY:  causes VMware to start the powered-off or suspended VM with no graphical user interface displayed
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:start_nogui:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:start_nogui:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:start_nogui:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:start_nogui:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("start " + self.VMX_file_path_quoted + " nogui"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:start_nogui:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:start_nogui:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:start_nogui:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:start_nogui:Nonzero return code from vmrun.")
            return False

    def stop(self):
        """ SUMMARY:  causes VMware to hard-shutdown the running VM
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:stop:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:stop:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:stop:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:stop:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("stop " + self.VMX_file_path_quoted + " hard"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:stop:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:stop:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:stop:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:stop:Nonzero return code from vmrun.")
            return False

    def stop_soft(self):
        """ SUMMARY:  causes VMware to send shutdown command to the running VM's OS
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:stop_soft:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:stop_soft:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:stop_soft:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:stop_soft:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("stop " + self.VMX_file_path_quoted + " soft"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:stop_soft:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:stop_soft:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:stop_soft:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:stop_soft:Nonzero return code from vmrun.")
            return False

    def snapshot(self, snapshot_name=None):
        """ SUMMARY:  creates a snapshot of the VM's current execution state
              INPUT:  name to assign to the new snapshot (str)
             OUTPUT:  True or False """

        if snapshot_name is None:
            if self.snapshot_name_prefix and self.snapshot_name_suffix \
                    and isinstance(self.snapshot_name_prefix, str) and callable(self.snapshot_name_suffix):
                snapshot_name = str(self.snapshot_name_prefix + str(self.snapshot_name_suffix()))
            else:
                self.logger.error(str("VMwareFusionVirtualMachine:snapshot:" +
                                      "Invalid or missing snapshot_name_prefix and/or snapshot name suffix method."))
        elif not snapshot_name or not isinstance(snapshot_name, str):
            self.logger.error("VMwareFusionVirtualMachine:snapshot:Invalid or missing snapshot_name.")
            return False

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:snapshot:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:snapshot:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:snapshot:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:snapshot:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("snapshot " + self.VMX_file_path_quoted + " \"" +
                                                            snapshot_name + "\""))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:snapshot:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:snapshot:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:snapshot:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:snapshot:Nonzero return code from vmrun.")
            return False

    def suspend(self):
        """ SUMMARY:  causes VMware to forcibly halt the running VM while maintaining execution state to resume later
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:suspend:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:suspend:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:suspend:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:suspend:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, ("suspend " + self.VMX_file_path_quoted + " hard"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:suspend:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:suspend:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:suspend:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:suspend:Nonzero return code from vmrun.")
            return False

    def suspend_soft(self):
        """ SUMMARY:  causes VMware to send suspend command to the running VM's OS to preserve current execution state
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:suspend_soft:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:suspend_soft:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:suspend_soft:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:suspend_soft:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, ("suspend " + self.VMX_file_path_quoted + " soft"))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:suspend_soft:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:suspend_soft:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:suspend_soft:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:suspend_soft:Nonzero return code from vmrun.")
            return False

    def terminate_vmnet_sniffer(self, parent_pid):
        """ SUMMARY:  runs the vmnet-sniffer termination script to kill a vmnet-sniffer process based on process lineage
              INPUT:  the process ID number for the bash 'grandparent' process of the target vmnet-sniffer process (int)
             OUTPUT:  True or False on error """

        if not parent_pid or not isinstance(parent_pid, int):
            self.logger.error("VMwareFusionVirtualMachine:terminate_vmnet_sniffer:Invalid or missing parent_pid.")
            return False

        if not self.vmnet_sniffer_termination_script_path \
                or not isinstance(self.vmnet_sniffer_termination_script_path, str):
            self.logger.error(str("VMwareFusionVirtualMachine:terminate_vmnet_sniffer:" +
                                  "Invalid or missing vmnet_sniffer_termination_script_path."))
            return False

        self.logger.debug("VMwareFusionVirtualMachine:terminate_vmnet_sniffer:Terminating vmnet-sniffer via sudo.")
        try:
            call(str("sudo \"" + self.vmnet_sniffer_termination_script_path + "\" " + str(parent_pid)), shell=True)
        except OSError:
            self.logger.error(str("VMwareFusionVirtualMachine:terminate_vmnet_sniffer:" +
                                  "OS error while terminating vmnet-sniffer."))
            return False

        else:
            self.logger.info("VMwareFusionVirtualMachine:terminate_vmnet_sniffer:Success")
            return True

    def unpause(self):
        """ SUMMARY:  causes VMware to unpause the VM's execution
              INPUT:  none
             OUTPUT:  True or False """

        if not self.VMX_file_path_quoted or not isinstance(self.VMX_file_path_quoted, str):
            self.logger.error("VMwareFusionVirtualMachine:unpause:Invalid VMX_file_path_quoted.")
            return False

        if not self.vmrun_binary_path or not isinstance(self.vmrun_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:unpause:Invalid vmrun_binary_path.")
            return False

        if not self.vmrun or not callable(self.vmrun):
            self.logger.error("VMwareFusionVirtualMachine:unpause:Invalid vmrun method.")
            return False

        self.logger.debug("VMwareFusionVirtualMachine:unpause:Calling vmrun method.")
        vmrun_proc = self.vmrun(self.vmrun_binary_path, str("unpause " + self.VMX_file_path_quoted))

        if not vmrun_proc or not isinstance(vmrun_proc, CompletedProcess):
            self.logger.error("VMwareFusionVirtualMachine:unpause:CompletedProcess not returned by vmrun.")
            return False

        if not isinstance(vmrun_proc.returncode, int):
            self.logger.error("VMwareFusionVirtualMachine:unpause:Invalid or missing return code.")
            return False

        if vmrun_proc.returncode == 0:
            self.logger.info("VMwareFusionVirtualMachine:unpause:Success")
            return True
        else:
            self.logger.error("VMwareFusionVirtualMachine:unpause:Nonzero return code from vmrun.")
            return False

    def vmnet_sniffer(self, vmnet, PCAP_file):
        """ SUMMARY:  runs the vmnet-sniffer binary subprogram to capture a vmnet's network packets to a file
              INPUT:  1) name of the vmnet to capture (str) 2) output .pcap file name to create
             OUTPUT:  Process object created by subprocess.Popen or False if an error occurs """

        if not vmnet or not isinstance(vmnet, str):
            self.logger.error("VMwareFusionVirtualMachine:vmnet_sniffer:Invalid or missing vmnet.")
            return False

        if not PCAP_file or not isinstance(PCAP_file, str):
            self.logger.error("VMwareFusionVirtualMachine:vmnet_sniffer:Invalid or missing PCAP_file.")
            return False

        if not self.vmnet_sniffer_binary_path or not isinstance(self.vmnet_sniffer_binary_path, str):
            self.logger.error("VMwareFusionVirtualMachine:vmnet_sniffer:Invalid or missing vmnet_sniffer_binary_path.")
            return False

        if not self.vmnet_sniffer_termination_script_path \
                or not isinstance(self.vmnet_sniffer_termination_script_path, str):
            self.logger.error(str("VMwareFusionVirtualMachine:vmnet_sniffer:" +
                                  "Invalid or missing vmnet_sniffer_termination_script_path."))
            return False

        if not path.exists(self.vmnet_sniffer_termination_script_path):
            self.logger.error(str("VMwareFusionVirtualMachine:vmnet_sniffer:" +
                                  "vmnet-sniffer termination script not found."))
            return False

        self.logger.debug("VMwareFusionVirtualMachine:vmnet_sniffer:Calling vmnet-sniffer via sudo.")
        command = str("sudo \"" + self.vmnet_sniffer_binary_path + "\" " + "-w \"" + PCAP_file + "\" " + vmnet +
                      " &> /dev/null")

        try:
            proc = Popen(command, shell=True, stderr=DEVNULL)
        except OSError:
            self.logger.error("VMwareFusionVirtualMachine:vmnet_sniffer:OS error while running vmnet-sniffer.")
            return False
        else:
            self.logger.info("VMwareFusionVirtualMachine:vmnet_sniffer:Success")
            return proc


def snapshot_name_suffix():
    """ SUMMARY:  generates a random VM snapshot name suffix string
          INPUT:  none
         OUTPUT:  six to seven random hexadecimal characters (str) """

    return str("%x" % randrange(10 ** 8))


def PCAP_filename_suffix():
    """ SUMMARY:  generates a .pcap filename suffix based on the local system's current time in UTC
          INPUT:  none
         OUTPUT:  time-based .pcap filename suffix (str) """

    return str(datetime.utcnow().strftime("%Y-%b-%d-%H%M%S")) + "-UTC.pcap"


def get_password(folder):
    """ SUMMARY:  parses 'focus' file for password data returning decoded plaintext
          INPUT:  filesystem location to search for 'focus' file (str)
         OUTPUT:  plaintext password data (str) or False if error occurs """

    if not isinstance(folder, str):
        stderr.write("ERROR: Failed to retrieve VM password. Invalid folder.\n")
        return False

    focus_file = str(folder + "focus")

    try:
        if path.exists(focus_file):
            with open(focus_file, mode="r") as open_file:
                open_file.readline()
                encoded_password = open_file.readline()
            return b64decode(encoded_password).decode("ascii")
        else:
            return False
    except OSError:
        stderr.write("ERROR: Failed to retrieve VM password. OS error in get_password function.\n")
        return False


def get_username(folder):
    """ SUMMARY:  parses 'focus' file for username data returning decoded plaintext
          INPUT:  filesystem location to search for 'focus' file (str)
         OUTPUT:  plaintext username data (str) """

    if not isinstance(folder, str):
        stderr.write("ERROR: Failed to retrieve VM username. Invalid folder.\n")
        return False

    focus_file = str(folder + "focus")

    try:
        if path.exists(focus_file):
            with open(focus_file, mode="r") as open_file:
                encoded_username = open_file.readline()
            return b64decode(encoded_username).decode("ascii")
        else:
            return False
    except OSError:
        stderr.write("ERROR: Failed to retrieve VM username. OS error in get_username function.\n")
        return False


def vmrun(binary_path, command):
    """ SUMMARY:  runs vmrun binary subprogram to interact with VMware Fusion virtual machines
          INPUT:  1) full path to the vmrun binary (str) 2) complete input text, command + arguments (str)
         OUTPUT:  CompletedProcess object or False if an error occurs """

    if not isinstance(binary_path, str) or not isinstance(command, str):
        stderr.write("ERROR: Failed to execute vmrun subprocess. Invalid binary path and/or command.\n")
        return False

    full_command = str("\"" + binary_path + "\" " + command)

    try:
        vmrun_proc = run(split(full_command), capture_output=True)
    except CalledProcessError as e:
        stderr.write(str("Error: CalledProcessError while running " + e.cmd + "\n" + e.stderr + "\n"))
        return False
    else:
        return vmrun_proc
