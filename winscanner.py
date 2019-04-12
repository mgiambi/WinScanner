import winrm
import sys
import os
import argparse
import urllib3
import re
import json
import datetime
import requests
import wmi_client_wrapper as wmi
from winrm.protocol import Protocol
from os import listdir
from os.path import isfile, join


###########################
### SERIALIZABLE OBJECT ###
###########################

class Object:
    def to_json(self):
        return json.dumps(self, default=lambda o: o.__dict__,\
                sort_keys=True, indent=4)


#################
### CONSTANTS ###
#################

HTTP_PORT = "5985"
HTTPS_PORT = "5986"

PID_INDEX = 1
USER_INDEX = 6

api_url = "https://api.msrc.microsoft.com/"
api_key = "15ec9ebc4fe9469784f10724bf752f82"

#################
### FUNCTIONS ###
#################

### Print the progress bar
def progressbar_update(current_val, end_val, file, bar_length = 30):
    percent = float(current_val) / end_val
    hashes = "#" * int(round(percent * bar_length))
    spaces = "-" * (bar_length - len(hashes))
    sys.stdout.write("\rProgress: [{0}] {1}% {2}".format(\
                hashes + spaces, int(round(percent * 100)), file))
    sys.stdout.flush()
### End progress bar function

### Download security update reports from microsoft database
def download_monthly_update_files():

    # Check if new reports are issued
    url = "{}updates?api-version={}".format(api_url,\
                str(datetime.datetime.now().year))
    headers = {'api-key': api_key}
    response = requests.get(url, headers=headers)

    report_list = set()
    if response.status_code == 200:
        data = json.loads(response.content)
        for element in data["value"]:
            report_list.add(element["ID"])

        reports = [f for f in listdir("data/reports") if \
                        isfile(join("data/reports", f))]

        # If a report is issued and not present in the local
        # repository, download it
        index = 0
        print("Downloading missing reports...")
        for element in report_list:
            if element not in reports:
                url = "{}cvrf/{}?api-version={}".format(api_url,\
                        element, str(datetime.datetime.now().year))
                headers = {'api-key': api_key, 'Accept': \
                        'application/json'}
                response = requests.get(url, headers = headers)

                if response.status_code == 200:
                    data = json.loads(response.content)
                    with open("data/reports/" + element, "w") \
                            as json_file:
                        json.dump(data, json_file, sort_keys = True,\
                            indent = 4)
                    index += 1
                    progressbar_update(index, len(report_list) -\
                                        len(reports), element)
                else:
                    print("Error: the security update " + element +\
                            " cannot be downloaded")
                    exit()
        print("\nThe security update repository is up-to-date.")
    else:
        print("Error: security update list cannot be downloaded.")
        exit()
### End security update reports function

### Helper function to print error messages
def display_err(error_msg, print_error, command):
    if print_error and error_msg:
        print("\nCommand: " + command + "\n" + error_msg)
### End error function

### Connect to the remote machine
def auth(ip, user, password, secure, custom_port):

        # Authentication to WMI query service
        wmic = wmi.WmiClientWrapper(\
                username = user,\
                password = password,\
                host = ip)

        # Authentication to WinRM (to execute cmd commands)
        if secure:
            protocol = "https"
            port = HTTPS_PORT
            print("\nUsing HTTPS")
        else:
            protocol = "http"
            port = HTTP_PORT
            print("\nWARNING: using HTTP, connection not secure")

        if custom_port:
            port = custom_port

        return winrm.Session(\
                protocol + "://" + ip + ":" + port + "/wsman",\
                auth = (user, password)),\
                wmic
### End authentication function

### Open a shell with limited capabilities on target system
def shell_mode(session, shell, print_error, output_file):

    print("Shell mode: press Ctrl+C to exit")
    while(True):
        try:
            command = input("\n" + shell + " >> ")

            if shell == "CMD":
                result = session.run_cmd(command)
            else:
                result = session.run_ps(command)

            err = ""
            if print_error and result.std_err.decode():
                display_err(result.std_err.decode(),\
                    print_error, command)
                err = result.std_err.decode()
            print("\n" + result.std_out.decode())

            with open(output_file, "a") as file:
                file.write(command + "\n\n" + err + "\n" +\
                            result.std_out.decode() + "\n")
        except KeyboardInterrupt:
            exit()
### End shell function

### Run .bat or .ps1 script read by a file
def run_file(session, path, print_error, output_file):

    with open(path, 'r') as myFile:
        script = myFile.read()

        if path.endswith(".bat"):
            result = session.run_cmd(script)
        elif path.endswith(".ps1"):
            result = session.run_ps(script)
        else:
            print("\nFile extension not supported. Only .bat" +\
                    " and .ps1 files are accepted.")
            exit()

        err = ""
        if print_error and result.std_err.decode():
            display_err(result.std_err.decode(), print_error, command)
            err = result.std_err.decode()
        print("\n" + result.std_out.decode())

    if output_file:
        with open(output_file, "w") as file:
            file.write(script + "\n\n" + err + "\n" +\
                result.std_out.decode())
### End file function

### Gather assorted info about target system
def get_info(session, wmic, print_error, output_file):

    output = Object()

    ##
    ## WMI QUERIES
    ##

    # SYSTEM NAME
    system_name = wmic.query("SELECT Name " +\
                "FROM Win32_ComputerSystem")
    output.systemName = system_name[0]["Name"]

    # INSTALLATION DATE
    install_date = wmic.query("SELECT InstallDate " +\
                              "FROM Win32_OperatingSystem")
    output.installDate = install_date[0]["InstallDate"]

    # HARDWARE MODEL
    hw_model = wmic.query("SELECT Model FROM Win32_ComputerSystem")
    output.hwModel = hw_model[0]["Model"]

    # HARDWARE VENDOR
    hw_vendor = wmic.query("SELECT Manufacturer " +\
                           "FROM Win32_ComputerSystem")
    output.hwVendor = hw_vendor[0]["Manufacturer"]

    # SERIAL NUMBER
    serial_id = wmic.query("SELECT SerialNumber " +\
                           "FROM Win32_OperatingSystem")
    output.serialID = serial_id[0]["SerialNumber"]

    # OS NAME
    os_name = wmic.query("SELECT Name FROM Win32_OperatingSystem")
    output.osName = os_name[0]["Name"]

    # OS VERSION
    os_version = wmic.query("SELECT Version " +\
                            "FROM Win32_OperatingSystem")
    output.osVersion = os_version[0]["Version"]

    # ANTIVIRUS NAME
    # ANTIVIRUS VERSION

    # LAST UPDATE DATE
    # OS PATCHES INSTALLED (ADMIN ONLY)
    os_patches = wmic.query("SELECT HotFixID, InstalledOn " +\
                            "FROM Win32_QuickFixEngineering")
    osUpdates = []
    for k in os_patches:
        patch = Object()
        patch.ID = k["HotFixID"]
        patch.date = k["InstalledOn"]
        osUpdates.append(patch)
    output.osUpdates = osUpdates

    # IP ADDRESS
    # SUBNET MASK
    # DEFAULT GATEWAY
    # MAC ADDRESS
    # CONNECTIVITY INTERFACE
    ip_addr = wmic.query("SELECT Caption, IPAddress, " +\
                         "IPSubnet, DefaultIPGateway, " +\
                         "MACAddress, SettingID " +\
                         "FROM Win32_NetworkAdapterConfiguration")
    ipAddr = []
    for k in ip_addr:
        addr = Object()
        addr.caption = k["Caption"]
        addr.ip = k["IPAddress"][0] + "/" + k["IPSubnet"][0]
        addr.gateway = k["DefaultIPGateway"]
        addr.mac = k["MACAddress"]
        addr.ifaceID = k["SettingID"]
        ipAddr.append(addr)
    output.interfaces = ipAddr

    # DOMAIN
    domain = wmic.query("SELECT Domain FROM Win32_ComputerSystem")
    output.domain = domain[0]["Domain"]

    # COMMUNICATION PROTOCOL TYPE
    proto = wmic.query("SELECT Name FROM Win32_NetworkProtocol")
    protocols = []
    for k in proto:
        protocols.append(k["Name"])
    output.protocols = protocols

    # USERS
    users = wmic.query("SELECT Name FROM Win32_UserAccount")
    user = []
    for k in users:
        user.append(k["Name"])
    output.users = user

    # GROUPS
    groups = wmic.query("SELECT Name FROM Win32_Group")
    group = []
    for k in groups:
        group.append(k["Name"])
    output.groups = group

    # SHARED FOLDERS
    shared = wmic.query("SELECT Name, Path FROM Win32_Share")
    folders = []
    for k in shared:
        folder = Object()
        folder.Name = k["Name"]
        folder.Path = k["Path"]
        folders.append(folder)
    output.shared = folders

    # CPU
    cpu = wmic.query("SELECT Name FROM Win32_Processor")
    processors = []
    for k in cpu:
        processors.append(k["Name"])
    output.cpu = processors

    # RAM
    ram = wmic.query("SELECT TotalPhysicalMemory " +\
                     "FROM Win32_ComputerSystem")
    output.ram = ram[0]["TotalPhysicalMemory"]

    # HDD SIZE
    # HDD TYPE AND PROTECTION
    hdd = wmic.query("SELECT Size, Description " +\
                     "FROM Win32_LogicalDisk")
    drives = []
    for k in hdd:
        drive = Object()
        drive.description = k["Description"]
        drive.size = k["Size"]
        drives.append(drive)
    output.hdd = drives

    # CONNECTIVITY SERVICE
    # CONNECTIVITY RATE
    connectivity = wmic.query("SELECT Name, AdapterType, Speed " +\
                              "FROM Win32_NetworkAdapter")
    conn = []
    for k in connectivity:
        interface = Object()
        interface.name = k["Name"]
        interface.type = k["AdapterType"]
        interface.rate = k["Speed"]
        conn.append(interface)
    output.adapters = conn

    ##
    ## CMD COMMAND EXECUTION
    ##

    # SW INSTALLED AND VERSION
    result = session.run_cmd(\
                r"reg query HKLM\Software\Microsoft\Windows" +\
                r"\CurrentVersion\Uninstall /s /v "
                r"DisplayName | findstr DisplayName")
    display_err(result.std_err.decode(), print_error, "sw")
    app_result = result.std_out.decode().split("\n")[:-1]

    result = session.run_cmd(\
                r"reg query HKLM\Software\WoW6432Node" +\
                r"\Microsoft\Windows\CurrentVersion" +\
                r"\Uninstall /s /v DisplayName " +\
                r"| findstr DisplayName")
    display_err(result.std_err.decode(), print_error, "sw")
    app_result.extend(result.std_out.decode().split("\n")[:-1])

    app = []
    for k in app_result:
        if bool(re.search("SZ[\s]*(.*?)\\r", k)):
            app.append(re.search("SZ[\s]*(.*?)\\r", k).group(1))

    result = session.run_cmd(\
                r"reg query HKLM\Software\Microsoft\Windows" +\
                r"\CurrentVersion\Uninstall /s /v " +\
                r"DisplayVersion | findstr DisplayVersion")
    display_err(result.std_err.decode(), print_error, "sw")
    ver_result = result.std_out.decode().split("\n")[:-1]

    result = session.run_cmd(\
                "reg query HKLM\Software\WoW6432Node" +\
                r"\Microsoft\Windows\CurrentVersion" +\
                r"\Uninstall /s /v DisplayVersion " +\
                r"| findstr DisplayVersion")
    display_err(result.std_err.decode(), print_error, "sw")
    ver_result.extend(result.std_err.decode().split("\n")[:-1])

    ver = []
    for k in ver_result:
        if bool(re.search("SZ[\s]*(.*?)\\r", k)):
            ver.append(re.search("SZ[\s]*(.*?)\\r", k).group(1))

    software = []
    for k in range(0, len(app)):
        sw = Object()
        sw.name = app[k]
        sw.version = ver[k]
        software.append(sw)
    output.software = software

    # APPLICATION PATCHES INSTALLED
    result = session.run_cmd(\
                "reg query HKLM\Software\WoW6432Node" +\
                r"\Microsoft\Updates\ /s | findstr WoW6432No")
    display_err(result.std_err.decode(), print_error, "sw")
    patches_result = result.std_out.decode().split("\n")[:-1]
    patches = []
    for k in patches_result:
        if bool(re.search("Updates(.*?)\\r", k)):
            patches.append(re.search("Updates(.*?)\\r", k).group(1))
    output.swPatches = patches

    # HOST FIREWALL
    result = session.run_cmd("netsh advfirewall show all state")
    display_err(result.std_err.decode(), print_error, "firewall")
    firewall_up = result.std_out.decode().replace("\r", "")\
                    .split("\n\n")[:-1]
    profiles = []
    for k in firewall_up:
        profile = Object()
        if bool(re.search("(.*?)Settings: ", k)):
            profile.name = re.search("(.*?)Settings: ", k).group(1)
        profile.state = "OFF"

        if "    ON" in k:
            profile.state = "ON"
        profiles.append(profile)

    output.firewall = profiles

    # REMOTE ACCESS TYPE
    connectivity = []

    # Check RDP enabled
    result = session.run_cmd('reg query "HKLM\System' +
                '\CurrentControlSet\Control\Terminal ' +\
                'Server" /v fDenyTsConnections | findstr /i 0x0')
    display_err(result.std_err.decode(), print_error, "check rpc")
    if result.std_out.decode():
        connectivity += "RDP"

    # Check VNC enabled (default port only)
    result = session.run_cmd("netstat -an | findstr LISTENING " +\
                "| findstr :5900")
    display_err(result.std_err.decode(), print_error, "check vnc")
    if result.std_out.decode():
        connectivity += "VNC"

    output.remote = connectivity

    # COMMUNICATION PORT NUMBER
    result = session.run_cmd("netstat -aon | findstr /r " +\
                "\.[0-9]:[0-9]*")
    display_err(result.std_err.decode(), print_error, "port")
    port_res = result.std_out.decode().split("\n")[:-1]
    ports = []
    for k in port_res:
        port = Object()
        port.protocol = k.strip().split(" ")[0]
        port.number = re.search("\.[0-9]:(.*?) ", k).group(1)
        ports.append(port)
    output.ports = ports

    # ACTIVE PROCESSES
    result = session.run_cmd("tasklist /v /fo csv /nh")
    display_err(result.std_err.decode(), print_error, "proc")
    proc_res = result.std_out.decode().split("\n")[:-1]
    proc = []
    for k in proc_res:
        process = Object()
        proc_temp = k.split(",")
        process.pid = proc_temp[PID_INDEX].replace('"', '')
        process.user = proc_temp[USER_INDEX].replace('"', '')
        proc.append(process)
    output.processes = proc

    # SECURITY LOGGING
    result = session.run_cmd("auditpol /get /category:system")
    display_err(result.std_err.decode(), print_error, "sec_log")
    log_res = result.std_out.decode().split("\n")[3:-1]
    policies = []
    for k in log_res:
        policy = Object()
        s = re.split("\s{2,}", k.strip())
        policy.name = s[0]
        policy.settings = s[1]
        policies.append(policy)
    output.seclog = policies

    # RESTORE (ADMIN ONLY)
    result = session.run_cmd("vssadmin list shadows")
    display_err(result.std_err.decode(), print_error, "vssadmin")
    s = result.std_out.decode().strip().split("\r\n\r\n")[1:]
    shadows = []
    for k in s:
        restore = Object()
        if bool(re.search("Original Volume: (.*?)\\r", k)):
            restore.original = re.search("Original Volume: " +\
                        "(.*?)\\r", k).group(1)
        if bool(re.search("Shadow Copy Volume: (.*?)\\r", k)):
            restore.shadow = re.search("Shadow Copy Volume: " +\
                        "(.*?)\\r", k).group(1)
        if bool(re.search("Shadow Copy ID: (.*?)\\r", k)):
            restore.id = re.search("Shadow Copy ID: \{" +\
                        "(.*?)\}", k).group(1)
        shadows.append(restore)
    output.shadows = shadows

    # BACKUP (ADMIN ONLY)
    # BACKUP FILES (ADMIN ONLY)
    result = session.run_cmd("wbadmin enable backup")
    display_err(result.std_err.decode(), print_error, "backup")
    backup_location = re.search("store backup: (.*)" +\
                "\n", result.std_out.decode()).group(1)
    output.backup = backup_location

    # PRINT OUTPUT
    json_obj = output.to_json()

    print(json_obj)
    if output_file:
        if not output_file.endswith(".json"):
            output_file += ".json"
        with open(output_file, "w") as outfile:
            outfile.write(json_obj)
### End info gathering function


####################
### MAIN PROGRAM ###
####################

# Import SSL certificates from local machine (DEBAIN ONLY)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
os.environ["REQUESTS_CA_BUNDLE"] = os.path.join("/etc/ssl/certs/",\
                                        "ca-certificates.crt")

# Parse input
parser = argparse.ArgumentParser(description = "Remote diagnostics" +\
        " and management tool for Windows machines.")
parser.add_argument("i", metavar = "ip", type = str,\
        nargs = 1, help = "the ip address of target machine")
parser.add_argument("u", metavar = "username", type = str,\
        nargs = 1, help = "the username for remote " +\
        "authentication")
parser.add_argument("w", metavar = "password", type = str,\
        nargs = 1, help = "the password for remote "+\
        "authentication")
group = parser.add_mutually_exclusive_group()
group.add_argument("-b", action = "store_true",\
        help = "open a CMD shell on target machine")
group.add_argument("-ps", action = "store_true",\
        help = "open a PS shell on target machine")
group.add_argument("-f", metavar = "script file", type = str,\
        nargs = 1, help = "run the script in the specified file")
parser.add_argument("-u", action = "store_true",\
        help = "update local security update repository")
parser.add_argument("-p", metavar = "port", type = str,\
        nargs = 1, help = "port to connect to " +\
        "(if different from default)")
parser.add_argument("-o", metavar = "output file", type = str,\
        nargs = 1, help = "save the output in the specified file")
parser.add_argument("-e", action = "store_true",\
        help = "print StdErr output")
parser.add_argument("-s", action = "store_true",\
        help = "use HTTPS for secure connection")
args = parser.parse_args()

# Connect to remote machine
if args.p is None:
    port = ""
else:
    port = args.p[0]

session, wmic = auth(args.i[0], args.u[0], args.w[0], args.s, port)

# Perform chosen tasks
if args.o is None:
    output_file = ""
else:
    output_file = args.o[0]

print_error = args.e

if args.b:
    shell_mode(session, "CMD", print_error, output_file)
elif args.ps:
    shell_mode(session, "PS", print_error, output_file)
elif args.f is not None:
    run_file(session, args.f[0], print_error, output_file)
elif args.u:
    download_monthly_update_files()
else:
    get_info(session, wmic, print_error, output_file)
