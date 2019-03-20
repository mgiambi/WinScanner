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


#####################
### OUTPUT OBJECT ###
#####################

class Object:
	def toJSON(self):
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
def get_info(session, wmic, print_error):

	##
	## WMI QUERIES
	##

	# SYSTEM NAME
	system_name = wmic.query("SELECT Name " +\
				 "FROM Win32_ComputerSystem")
	print(system_name)

	# INSTALLATION DATE
	install_date = wmic.query("SELECT InstallDate " +\
				  "FROM Win32_OperatingSystem")
	print(install_date)

	# HARDWARE MODEL
	hw_model = wmic.query("SELECT Model " +\
			      "FROM Win32_ComputerSystem")
	print(hw_model)

	# HARDWARE VENDOR
	hw_vendor = wmic.query("SELECT Manufacturer " +\
			       "FROM Win32_ComputerSystem")
	print(hw_vendor)

	# SERIAL NUMBER
	serial_id = wmic.query("SELECT SerialNumber " +\
			       "FROM Win32_OperatingSystem")
	print(serial_id)

	# OS NAME
	os_name = wmic.query("SELECT Name " +\
			     "FROM Win32_OperatingSystem")
	print(os_name)

	# OS VERSION
	os_version = wmic.query("SELECT Version " +\
				"FROM Win32_OperatingSystem")
	print(os_version)

	# ANTIVIRUS NAME

	# ANTIVIRUS VERSION

	# LAST UPDATE DATE & OS PATCHES INSTALLED
	os_patches = wmic.query("SELECT HotFixID, InstalledOn " +\
				"FROM Win32_QuickFixEngineering")
	print(os_patches)

	# IP ADDRESS AND SUBNET MASK
	ip_addr = wmic.query("SELECT Caption, IPAddress, IPSubnet " +\
			     "FROM Win32_NetworkAdapterConfiguration")
	print(ip_addr)

	# DEFAULT GATEWAY
	gateway = wmic.query("SELECT DefaultIPGateway " +\
			     "FROM Win32_NetworkAdapterConfiguration")
	print(gateway)

	# DOMAIN
	domain = wmic.query("SELECT Domain " +\
			    "FROM Win32_ComputerSystem")
	print(domain)

	# MAC ADDRESS
	mac = wmic.query("SELECT MACAddress " +\
			 "FROM Win32_NetworkAdapterConfiguration")
	print(mac)

	# COMMUNICATION PROTOCOL TYPE
	proto = wmic.query("SELECT Name " +\
			   "FROM Win32_NetworkProtocol")
	print(proto)

	# USERS
	users = wmic.query("SELECT Name " +\
			   "FROM Win32_UserAccount")
	print(users)

	# GROUPS
	groups = wmic.query("SELECT Name " +\
			    "FROM Win32_Group")
	print(groups)

	# SHARED FOLDERS
	shared = wmic.query("SELECT * "+\
			    "FROM Win32_Share")
	print(shared)

	# CONECTIVITY INTERFACES
	conn = wmic.query("SELECT SettingID " +\
			  "FROM Win32_NetworkAdapterConfiguration")
	print(conn)

	# CPU
	cpu = wmic.query("SELECT Name " +\
			 "FROM Win32_Processor")
	print(cpu)

	# RAM
	ram = wmic.query("SELECT TotalPhysicalMemory " +\
			 "FROM Win32_ComputerSystem")
	print(ram)

	# HDD SIZE
	hdd_size = wmic.query("SELECT Size " +\
			      "FROM Win32_LogicalDisk")
	print(hdd_size)

	# HDD TYPE AND PROTECTION
	hdd_type = wmic.query("SELECT Description " +\
			      "FROM Win32_LogicalDisk")
	print(hdd_type)

	# CONNECTIVITY SERVICE & CONNECTIVITY RATE
	connectivity = wmic.query("SELECT AdapterType,Speed " +\
				  "FROM Win32_NetworkAdapter")
	print(connectivity)

	##
	## CMD COMMAND EXECUTION
	##

	# SW INSTALLED
	result = session.run_cmd(\
			"reg query HKLM\Software\Microsoft\Windows" +\
			r"\CurrentVersion\Uninstall /s /v DisplayName")
	display_err(result.std_err.decode(), print_error, "sw")
	print(result.std_out.decode())

	result = session.run_cmd(\
			"reg query HKLM\Software\Microsoft\Windows" +\
			r"\CurrentVersion\Uninstall /s /v " +\
			"DisplayVersion")
	display_err(result.std_err.decode(), print_error, "sw")
	print(result.std_out.decode())

	result = session.run_cmd(\
			"reg query HKLM\Software\WoW6432Node" +\
			r"\Microsoft\Windows\CurrentVersion" +\
			r"\Uninstall /s /v DisplayName")
	display_err(result.std_err.decode(), print_error, "sw")
	print(result.std_out.decode())

	result = session.run_cmd(\
			"reg query HKLM\Software\WoW6432Node" +\
			r"\Microsoft\Windows\CurrentVersion" +\
			r"\Uninstall /s /v DisplayVersion")
	display_err(result.std_err.decode(), print_error, "sw")
	print(result.std_out.decode())

	# APPLICATION PATCHES INSTALLED
	result = session.run_cmd(\
			"reg query HKLM\Software\WoW6432Node" +\
			r"\Microsoft\Updates\ /s")
	display_err(result.std_err.decode(), print_error, "sw")
	print(result.std_out.decode())

	# HOST FIREWALL
	result = session.run_cmd("netsh advfirewall show " +\
				"allprofiles")
	display_err(result.std_err.decode(), print_error, "firewall")
	firewall_up = result.std_out.decode()
	print(firewall_up)

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

	print(connectivity)

	 # COMMUNICATION PORT NUMBER
	result = session.run_cmd("netstat -aon | findstr /r " +\
			"\.[0-9]:[0-9]*")
	display_err(result.std_err.decode(), print_error, "port")
	port_res = result.std_out.decode().split("\n")
	ports = []
	for k in port_res[:-1]:
		ports.append(re.search("\.[0-9]:(.*?) ", k).group(1))
	print(ports)

	# ACTIVE PROCESSES
	result = session.run_cmd("tasklist /v /fo csv /nh")
	display_err(result.std_err.decode(), print_error, "proc")
	proc_res = result.std_out.decode().split("\n")
	proc = []
	for k in proc_res[:-1]:
		proc_temp = k.split(",")
		proc.append(proc_temp[PID_INDEX].replace('"', '')\
				+ " " + proc_temp[USER_INDEX]\
				.replace('"', ''))
	print(proc)

	# SECURITY LOGGING (ADMIN ONLY)
	result = session.run_cmd("auditpol /get /category:system")
	display_err(result.std_err.decode(), print_error, "sec_log")
	print(result.std_out.decode())

	# RESTORE (ADMIN ONLY)
	result = session.run_cmd("vssadmin list shadows")
	display_err(result.std_err.decode(), print_error, "vssadmin")
	print(result.std_out.decode())

	# BACKUP (ADMIN ONLY)
	result = session.run_cmd("wbadmin enable backup")
	display_err(result.std_err.decode(), print_error, "backup")
	backup = False
	if "Location to store backup" in result.std_out.decode():
		backup = True
	print(backup)

	# BACKUP FILES (ADMIN ONLY)
	backup_location = ""
	if backup:
		backup_location = re.search("store backup: (.*)" +\
				"\n", result.std_out.decode())\
				.group(1)
	print(backup_location)
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
parser.add_argument("-b", metavar = "script", type = str,\
		nargs = 1, help = "a batch script to run on target" +\
		" machine")
parser.add_argument("-ps", metavar = "script", type = str,\
		nargs = 1, help = "a powershell script to run" +\
		" on target machine")
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

if args.b is not None:
	run_script(session, args.b[0], "batch", print_error)

if args.ps is not None:
	run_script(session, args.ps[0], "ps", print_error)

if args.f is not None:
	run_file(session, args.f[0], print_error)

if args.b is None and args.ps is None and args.f is None:
	get_info(session, wmic, print_error)
