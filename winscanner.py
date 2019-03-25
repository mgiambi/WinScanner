import winrm
import sys
import os
import argparse
import urllib3
import xml.dom.minidom
import re
import json
import wmi_client_wrapper as wmi
from hurry.filesize import size, si
from winrm.protocol import Protocol


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


#################
### FUNCTIONS ###
#################

### Helper function to print error messages
def display_err(error_msg, print_error, command):
	if print_error and error_msg:
		print("\nCommand: " + command + "\n" + error_msg)

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

### Run a .bat or .ps1 script from standard input
def run_script(session, script, shell, print_error):

	if shell == "batch":
		print("\nCMD >> " + script)
		result = session.run_cmd(script)

		display_err(result.std_err.decode(), print_error, \
				script)
	else:
		print("\nPS >> " + script)
		result = session.run_ps(script)

		if print_error and result.std_err:
			if result.status_code:
				print("\n" + result.std_err)
			else:
				dom = xml.dom.minidom.parseString(\
				result.std_err.decode()\
					.split("\n", 1)[1])
				print("\n" + dom.toprettyxml())

	print("\n" + result.std_out.decode())
### End script function

### Run .bat or .ps1 script read by a file
def run_file(session, path, print_error):

	with open(path, 'r') as myFile:
		script = myFile.read()

	if path.endswith(".bat"):
		run_script(session, script, "batch", print_error)
	elif path.endswith(".ps1"):
		run_script(session, script, "ps", print_error)
	else:
		print("\nFile extension not supported. Only .bat" +\
			" and .ps1 files are accepted.")
### End file function

### Gather assorted info about target system
def get_info(session, wmic, print_error, output):

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
	hw_model = wmic.query("SELECT Model " +\
			      "FROM Win32_ComputerSystem")
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
	os_name = wmic.query("SELECT Name " +\
			     "FROM Win32_OperatingSystem")
	output.osName = os_name[0]["Name"]

	# OS VERSION
	os_version = wmic.query("SELECT Version " +\
				"FROM Win32_OperatingSystem")
	output.osVersion = os_version[0]["Version"]

	# ANTIVIRUS NAME

	# ANTIVIRUS VERSION

	# LAST UPDATE DATE
	# OS PATCHES INSTALLED
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
		addr.ip = k["IPAddress"][0] + "/" +\
				k["IPSubnet"][0]
		addr.gateway = k["DefaultIPGateway"]
		addr.mac = k["MACAddress"]
		addr.interfaceID = k["SettingID"]
		ipAddr.append(addr)
	output.interfaces = ipAddr

	# DOMAIN
	domain = wmic.query("SELECT Domain " +\
			    "FROM Win32_ComputerSystem")
	output.domain = domain[0]["Domain"]

	# COMMUNICATION PROTOCOL TYPE
	proto = wmic.query("SELECT Name " +\
			   "FROM Win32_NetworkProtocol")
	protocols = []
	for k in proto:
		protocols.append(k["Name"])
	output.protocols = protocols

	# USERS
	users = wmic.query("SELECT Name " +\
			   "FROM Win32_UserAccount")
	user = []
	for k in users:
		user.append(k["Name"])
	output.users = user

	# GROUPS
	groups = wmic.query("SELECT Name " +\
			    "FROM Win32_Group")
	group = []
	for k in groups:
		group.append(k["Name"])
	output.groups = group

	# SHARED FOLDERS
	shared = wmic.query("SELECT Name, Path "+\
			    "FROM Win32_Share")
	folders = []
	for k in shared:
		folder = Object()
		folder.Name = k["Name"]
		folder.Path = k["Path"]
		folders.append(folder)
	output.shared = folders

	# CPU
	cpu = wmic.query("SELECT Name " +\
			 "FROM Win32_Processor")
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
		interface.speed = k["Speed"]
		conn.append(interface)
	output.connectivity = conn

	##
	## CMD COMMAND EXECUTION
	##

	# SW INSTALLED AND VERSION
	result = session.run_cmd(\
			"reg query HKLM\Software\Microsoft\Windows" +\
			r"\CurrentVersion\Uninstall /s /v "
			r"DisplayName | findstr DisplayName")
	display_err(result.std_err.decode(), print_error, "sw")
	app_result = result.std_out.decode().split("\n")[:-1]

	result = session.run_cmd(\
			"reg query HKLM\Software\WoW6432Node" +\
			r"\Microsoft\Windows\CurrentVersion" +\
			r"\Uninstall /s /v DisplayName " +\
			r"| findstr DisplayName")
	app_result.extend(result.std_out.decode().split("\n")[:-1])

	app = []
	for k in app_result:
		app.append(re.search("SZ[\s]*(.*?)\\r", k).group(1))

	result = session.run_cmd(\
			"reg query HKLM\Software\Microsoft\Windows" +\
			r"\CurrentVersion\Uninstall /s /v " +\
			"DisplayVersion | findstr DisplayVersion")
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
		patches.append(re.search("Updates(.*?)\\r", k)\
				.group(1))
	output.softwarePatches = patches

	# HOST FIREWALL
	result = session.run_cmd("netsh advfirewall show " +\
				"all state")
	display_err(result.std_err.decode(), print_error, "firewall")
	firewall_up = result.std_out.decode().replace("\r", "")\
			.split("\n\n")[:-1]
	profiles = []
	for k in firewall_up:
		profile = Object()
		profile.name = re.search("(.*?)Settings: ", k)\
				.group(1)
		profile.state = "ON"
		if "    OFF" in k:
			profile.state = "OFF"
		profiles.append(profile)
	output.firewallProfiles = profiles

	# REMOTE ACCESS TYPE
	connectivity = []

	# Check RDP enabled
	result = session.run_cmd('reg query "HKLM\System' +
			'\CurrentControlSet\Control\Terminal ' +\
			'Server" /v fDenyTsConnections ' +\
			'| findstr /i 0x0')
	display_err(result.std_err.decode(), print_error, "check rpc")
	if result.std_out.decode():
		connectivity += "RDP"

	# Check VNC enabled (default port only)
	result = session.run_cmd("netstat -an | " +\
			"findstr LISTENING | findstr :5900")
	display_err(result.std_err.decode(), print_error, "check vnc")
	if result.std_out.decode():
		connectivity += "VNC"

	output.remoteAccess = connectivity

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

	# SECURITY LOGGING (ADMIN ONLY)
	result = session.run_cmd("auditpol /get /category:system")
	display_err(result.std_err.decode(), print_error, "sec_log")
	log_res = result.std_out.decode().split("\n")[3:-1]
	policies = []
	for k in log_res:
		policy = Object()
		s = re.split("\s{2,}", k.strip())
		policy.name = s[0]
		policy.setting = s[1]
		policies.append(policy)
	output.seclog = policies

	# RESTORE (ADMIN ONLY)
	result = session.run_cmd("vssadmin list shadows")
	display_err(result.std_err.decode(), print_error, "vssadmin")
	s = result.std_out.decode().strip().split("\r\n\r\n")[1:]
	shadows = []
	for k in s:
		restore = Object()
		restore.original = re.search("Original Volume: " +\
				"(.*?)\\r", k).group(1)
		restore.shadow = re.search("Shadow Copy Volume: " +\
				"(.*?)\\r", k).group(1)
		restore.id = re.search("Shadow Copy ID: \{" +\
				"(.*?)\}", k).group(1)
		shadows.append(restore)
	output.shadows = shadows

	# BACKUP (ADMIN ONLY)
	# BACKUP FILES (ADMIN ONLY)
	result = session.run_cmd("wbadmin enable backup")
	display_err(result.std_err.decode(), print_error, "backup")
	backup_location = re.search("store backup: (.*)" +\
				"\n", result.std_out.decode())\
				.group(1)
	output.backup = backup_location

	print(output.to_json())
## End info gathering function


####################
### MAIN PROGRAM ###
####################

# Import SSL certificates from local machine
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)
os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(\
    '/etc/ssl/certs/',\
    'ca-certificates.crt')

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
parser.add_argument("-p", metavar = "port", type = str,\
		nargs = 1, help = "port to connect to " +\
		"(if different from default)")
parser.add_argument("-b", action = "store_true",\
		help = "open a CMD shell on target machine")
parser.add_argument("-ps", action = "store_true",\
		help = "open a PS shell on target machine")
parser.add_argument("-f", metavar = "file", type = str,\
		nargs = 1, help = "the path to a .bat o .ps file" +\
		" to run on target machine")
parser.add_argument("-e", action = "store_true",\
		help = "view StdErr output")
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
print_error = args.e
output = Object()

if args.b is not None:
	run_script(session, args.b[0], "batch", print_error)

if args.ps is not None:
	run_script(session, args.ps[0], "ps", print_error)

if args.f is not None:
	run_file(session, args.f[0], print_error)

if args.b is None and args.ps is None and args.f is None:
	get_info(session, wmic, print_error, output)
