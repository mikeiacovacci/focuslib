<div align="center">
  <h1>focuslib</h1>
</div>
<p align="center">
  <b>focuslib</b> is a simple Python module for programmatically interacting with virtual machines in VMware Fusion Pro 
  with the aim of automating certain digital forensics tasks.
</p>
<br>
<div align="center">
  <!-- macOS -->
  <a href="https://github.com/mikeiacovacci/focuslib">
    <img src="https://img.shields.io/badge/macOS-10.15.4-red?style=flat"
      alt="macOS" />
  </a>
  <!-- VMware Fusion Pro -->
  <a href="https://github.com/mikeiacovacci/focuslib">
    <img src="https://img.shields.io/badge/VMware%20Fusion%20Pro-11.5.3-orange?style=flat"
      alt="VMware Fusion Pro" />
  </a>
  <!-- Python -->
  <a href="https://github.com/mikeiacovacci/focuslib">
    <img src="https://img.shields.io/badge/Python-3.7.3-yellow?style=flat"
      alt="Python" />
  </a>
  <!-- License -->
  <a href="https://github.com/mikeiacovacci/focuslib/blob/master/LICENSE">
    <img src="https://img.shields.io/github/license/mikeiacovacci/focuslib"
      alt="License" />
  </a>
  <!-- Release -->
  <a href="https://github.com/mikeiacovacci/focuslib/releases">
    <img src="https://img.shields.io/github/v/release/mikeiacovacci/focuslib"
      alt="Release" />
  </a>
  <!-- Blind Rage -->
  <a href="https://payl0ad.run">
    <img src="https://img.shields.io/badge/powered%20by-blind%20rage-purple?style=flat"
    alt="Blind Rage" />
  </a>
</div>

---

## Table of Contents

- [Motivation](#motivation)
- [Implementation](#implementation)
- [Dependencies](#dependencies)
- [Security](#security)
  - [Guest OS credentials](#guest-os-credentials)
  - [Capturing packets as root](#capturing-packets-as-root)
  - [Shared folder conventions](#shared-folder-conventions)
- [Installation](#installation)
  - [python3](#python3)
  - [focuslib.py](#focuslibpy)
  - [kill-vmnet-sniffer.sh](#kill-vmnet-sniffersh)
  - [Configuring sudo](#configuring-sudo)
- [Usage](#usage)
  - [Single-VM Example](#single-vm-example)
  - [Multi-VM Example](#multi-vm-example)
- [Configuration](#configuration)
- [Known Limitations](#known-limitations)
- [Contributing](#contributing)
  - [Opening Issues](#opening-issues)
  - [Writing & Submitting Code](#writing--submitting-code)
- [License](#license)

## Motivation

 - VM artifact acquisition is more forensically sound at the hypervisor level verses within an untrusted OS.
 - Manual, interactive forensic acquisition of VM content is slow, tedious and error-prone.
 - Projects like Vagrant cater to development environemnts and impose related conventions.
 - A Python interface better integrates with the ecosystem of existing digital forensics tools.

## Implementation

VMware Fusion has had a JSON API since 2017, but the publicly-available documentation indicates it doesn't support all 
the features needed to perform certain forensics tasks. Instead, **focuslib** enables programmatic interaction with VMs 
through the following approaches:

- wrapping a small subset of functions provided by VMware Fusion's utility binaries (e.g. `vmrun`, `vmnet-sniffer`)
- implementing basic, default conventions for snapshot naming, shared folder usage, VM storage locations, etc. 
- parsing virtual machine .vmx files (an undocumented file format)

Using the REST API is probably the more correct, reliable design for the long term, but since it doesn't provide all the 
functionality I need today (and in the interest of simplifying installation and reducing dependencies) I decided the 
current approach would be 'good enough' for now.

## Dependencies

- macOS Catalina
- VMware Fusion Professional 11.5
- Virtual machines with VMware Tools installed
- Python 3

## Security

**focuslib** is designed for experimental use cases in lab environments where strict security protocols aren't 
necessarily needed and users generally understand the security hazards involved. Do not use **focuslib** on critical 
systems or in secured environments where doing so would create unacceptable risks.

### Guest OS credentials

In order to execute programs inside a target VM a valid username and password must be supplied to authenticate to the 
guest OS. By default, these values are expected to be stored in a two-line text file named `focus` within the target 
VM's `.vmwarevm` directory. The first line should contain a base64-encoded username, and the second line should contain 
a base64-encoded password. When a `VMwareFusionVirtualMachine` object is instantiated, the default `get_username()` and 
`get_password()` methods will read this file and return the plaintext, decoded values. Users should be aware that any 
process on the host OS with read access to this file can steal the credentials.

This credential retrieval method can be easily replaced with a more secure one (e.g. to integrate with some password 
manager or secrets service), but the plaintext values must still be present within the object's corresponding attributes 
for the module to function properly. Therefore, any code that can read the Python interpreter's memory can 
hypothetically steal VM credentials as well.

### Capturing packets as root

VMware Fusion Pro includes a binary, `vmnet-sniffer`, that provides virtual network packet capturing capabilities, but 
the root user must run the binary for it to work. **focuslib** expects the host OS to be configured to allow execution 
of this binary as root, via `sudo`, without needing to supply a password. The security implications of allowing this 
elevated process to be launched by an unprivileged user has not been thoroughly researched. Malicious root privilege 
escalation is hypothetically possible in the event of a vulnerability in the `vmnet-sniffer` binary.

Additionally, in order to automatically terminate the elevated process (i.e. once packet capturing has occurred for the 
specified duration) the host OS must also be configured to allow execution of the included utility script, 
`kill-vmnet-sniffer.sh`, as root (without entering a password) via `sudo`. The user must carefully install this script, 
paying attention to permission and ownership settings of the file and related directories, to avoid creating a root 
privilege escalation vulnerability.

### Shared folder conventions

By default, **focuslib** expects VMs to use shared folders that correspond to host filesystem paths named after the VM's 
vmnet value. For example, if a VM uses vmnet8, **focuslib** sets the primary shared folder attributes to 
`/opt/shared/vmnet8/ro/` and `/opt/shared/vmnet8/rw/` for readonly and writeable folders respectively. This means that 
**focuslib** will operate as if all VMs on the same vmnet are also using the same shared folders.

Furthermore, a VM's `primary_readonly_shared_folder` attribute is used as the default destination for PCAP files and 
memory samples. Therefore, untrusted userspace processes in a VM's guest OS could hypothetically read sensitive system 
data by accessing its own memory sample files, and every VM on a given vmnet (by virtue of using the same shared 
folders) can read packet captures and memory samples created by 'neighboring' VMs.

**focuslib** assumes that, if a user configured VMs to share a virtual network, he or she has no expectation that those 
VMs are isolated.

## Installation

To install **focuslib** perform the following procedures:

0. Verify that your macOS installation has [python3](#python3) installed/enabled.
1. Download the [latest release](https://github.com/mikeiacovacci/focuslib/releases/latest) and verify the PGP 
signature.
2. Place the [`focuslib.py`](#focuslibpy) and [`kill-vmnet-sniffer.sh`](#kill-vmnet-sniffersh) files in the right 
locations.
3. [Configure](#configuring-sudo) `sudo` to allow passwordless execution as the root user.

### python3

To enable Python 3 on macOS Catalina, run `/usr/bin/python3` in the terminal to trigger installation of the command line 
developer tools. Alternatively, install Python 3 through your package manager of choice such as 
[Homebrew](https://github.com/Homebrew). **focuslib** has only been tested on the Python interpreter distributed by 
Apple.

### focuslib.py

If you anticipate running more than one application on the same system that will import **focuslib**, consider saving 
`focuslib.py` to your site packages directory at `/Library/Python/3.7/site-packages` for simplified importing. 
Otherwise, or if you don't mind relative importing, just place the file in your application's folder hierarchy.

### kill-vmnet-sniffer.sh

The script necessary to correctly terminate the `vmnet-sniffer` program must be indefinitely saved to a directory that 
can only be modified by the root user. By default, **focuslib** expects this script in the location `/opt/focus/lib/`. 
Wherever you install it be very careful to ensure the script cannot be modified or replaced by any user except root.

### Configuring sudo

**focuslib** must non-interactively execute certain privileged processes to function properly. This requires modifying 
the host system's `sudo` configuration. Specifically, the end user must allow passwordless execution of `vmnet-sniffer` 
and `kill-vmnet-sniffer.sh` as root.

To make this change run `sudo visudo` and add the following entries:

```
mike		ALL = (root) NOPASSWD: /Applications/VMware\ Fusion.app/Contents/Library/vmnet-sniffer
mike		ALL = (root) NOPASSWD: /opt/focus/lib/kill-vmnet-sniffer.sh
```

Replace the username and file paths to correspond to your own installation.

## Usage

For usage details, in an interactive Python shell, import the **focuslib** module and read the class method docstrings 
by calling `help()` like so:

```python
from focuslib import *

help(VMwareFusionVirtualMachine)
help(VMwareFusionPro)

```

### Single-VM Example

For simple use cases, such as interacting with a single VM, import the `VMwareFusionVirtualMachine` class and 
instantiate a corresponding object by supplying the full path to the VM's .vmx file. You can then utilize over 30 class 
methods and reference nearly the same number of attributes (typically strings or boolean values) to create applications 
that interact with the VM on your behalf.

For example, running a malicious executable in a sandbox (and acquiring a memory sample) could be accomplished like 
this:

```python
from focuslib import VMwareFusionVirtualMachine

VM = VMwareFusionVirtualMachine("/opt/vms/sandbox.vmwarevm/sandbox.vmx")

VM.revert_to_snapshot(snapshot_name="Clean")
VM.start()
VM.run_program(program_path="Z:\\ro\\malware.exe")
VM.acquire_memory_sample()
VM.stop()
```

### Multi-VM Example

For more complex use cases (e.g. multiple VMs) import the `VMwareFusionPro` class and create an instance. Then utilize 
the `running_VMs` list attribute to interact with any of the VMs running on the system.

Here's an example of simulating a multi-tiered command and control infrastructure (and collecting memory and network 
traffic samples) using three or more VMs:

```python
from focuslib import VMwareFusionPro

fusion = VMwareFusionPro()
c2_servers, redirectors, victims = [], [], []

for VM in fusion.running_VMs:
    if VM.display_name == "C2 Server": c2_servers.append(VM)
    elif VM.display_name == "Redirector": redirectors.append(VM)
    elif VM.display_name == "Victim": victims.append(VM)
    else: VM.suspend_soft()

c2_addresses, redirector_addresses = [], []

for node in c2_servers:
    node.revert_to_snapshot(snapshot_name="Staged")
    node.start_nogui()
    node.run_program(program_path="/usr/bin/python3", program_arguments="/opt/server.py -p 1337")
    c2_addresses.append(node.ip_address)

for proxy in redirectors:
    proxy.revert_to_snapshot(snapshot_name="Ready")
    proxy.start_nogui()
    proxy.run_program(program_path="/opt/redirect.sh", 
                      program_arguments=str("-p 443 " + c2_addresses[0] + ":1337"))
    redirector_addresses.append(proxy.ip_address)

for bot in victims:
    bot.revert_to_snapshot(snapshot_name="Private networking")
    bot.start()
    bot.run_program(program_path="Z:\\ro\\implant.exe", 
                    program_arguments=str("https://" + redirector_addresses[0]))

c2_servers[0].run_program(program_path="/usr/bin/python3", 
                          program_arguments="/opt/command.py --all-nodes report")

victims[0].capture_vmnet_packets(duration_seconds=120)
victims[0].acquire_memory_sample()

fusion.refresh()
for VM in fusion.running_VMs: VM.stop()
```

## Configuration

For configuration details, in an interactive Python shell, import the **focuslib** module and read the class definitions 
by calling `help()` like so:

```python
from focuslib import *

help(FocusLogger)
help(FocusUserConfiguration)

```

Generally, to make it easier to get started using **focuslib**, class arguments are optional. If no value is provided 
when instantiating an object, then a reasonable default value (often one returned by a class method) is used. Of the 
four classes in the module only the `VMX_file_path` argument is required when instantiating a 
`VMwareFusionVirtualMachine` object.

To work properly the `VMwareFusionPro` and `VMwareFusionVirtualMachine` classes rely on configuration settings specified 
in a `FocusUserConfiguration` object. If no configuration object is provided a default object is created. Additionally, 
`VMwareFusionVirtualMachine` instances implicitly inherit configuration settings from their parent `VMwareFusionPro` 
object if applicable.

Over a dozen settings can be customized like so:

```python
from lib.focuslib import FocusLogger, FocusUserConfiguration, VMwareFusionPro

my_logger = FocusLogger(log_file="/tmp/focuslib.log")

app_settings = FocusUserConfiguration(logger=my_logger, 
                                      VM_storage_root_path="/Users/mike/Virtual Machines.localized/", 
                                      VMware_install_path="/opt/VMware Fusion.app/Contents/")

fusion = VMwareFusionPro(config=app_settings)
```

## Known Limitations

- Only actively running VMs are discovered. No VM library parsing or filesystem searching is performed.
- VM state is only updated at object instantiation and when the `VMwareFusionPro.refresh()` method is invoked.
- `VMwareFusionVirtualMachine` class methods are generally blocking, so most VM interaction is sequential only.
- Multi-instance usage (threading, 2+ concurrent apps on the same system, etc.) has not been tested.
- VM context is not validated before attempting to execute any state-transitioning functions.
- Network settings aren't detected when the VM's network adapter is configured to use 'Autodetect' Bridged Networking.
- Packet capturing only works at the vmnet level, and the implementation ~is janky as hell~ could be improved.
- The default authentication method insecurely stores plaintext VM passwords on the host filesystem.
- Only snapshot chronology (not lineage) is detected, so complex use cases will require user-defined conventions.
- Basic logging is implemented, but robust exception handling is absent. Most functions just return False on error.

## Contributing

### Opening Issues

Feel free to [open an issue](https://github.com/mikeiacovacci/focuslib/issues/new/choose) in any of the following 
scenarios:

1. [Bug](https://github.com/mikeiacovacci/focuslib/issues/new?assignees=&labels=bug&template=bug_report.md&title=%5BBUG%5D)
2. [Security weakness](https://github.com/mikeiacovacci/focuslib/issues/new?assignees=&labels=bug&template=bug_report.md&title=%5BBUG%5D) 
not addressed [above](#security)
3. Significant [UX problem](https://github.com/mikeiacovacci/focuslib/issues/new?assignees=&labels=enhancement&template=ux-problem.md&title=%5BUX%5D)
4. Missing or inaccurate [documentation](https://github.com/mikeiacovacci/focuslib/issues/new?assignees=&labels=documentation&template=documentation.md&title=%5BDOCS%5D)
5. [Inefficiency](https://github.com/mikeiacovacci/focuslib/issues/new?assignees=&labels=bug&template=bug_report.md&title=%5BBUG%5D) 
(e.g. algorithmic)
6. Request for a reasonable [new feature](https://github.com/mikeiacovacci/focuslib/issues/new?assignees=&labels=enhancement&template=feature_request.md&title=%5BFEATURE%5D)

Please **do not** open any issues in the following scenarios:

1. A [known limitation](#known-limitations) (without proposing a solution)
2. Request for feature that harms end user security or privacy
3. Request for feature antithetical to the project ethos

### Writing & Submitting Code

To avoid duplication of effort only work on code changes represented by an 
[open issue](https://github.com/mikeiacovacci/focuslib/issues) and only after the issue has been assigned to you. When 
writing code for **focuslib** try to adhere to Python's style guide (PEP 8) but also observe other existing conventions 
in the code. Feel free to suggest style and convention changes that you think will improve the project.

Once you have code to submit [open a new pull request](https://github.com/mikeiacovacci/focuslib/pull/new/master) 
targeting the master branch and fill out the 
[template](https://github.com/mikeiacovacci/focuslib/blob/master/.github/pull_request_template.md).

## License

**focuslib** is made available under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).
