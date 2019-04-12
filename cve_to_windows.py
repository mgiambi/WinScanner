import json
import requests
import datetime
from pycvesearch import CVESearch

base_url = "https://api.msrc.microsoft.com/"
api_key = "15ec9ebc4fe9469784f10724bf752f82"
cve = CVESearch()

vuln_list = cve.search("microsoft/windows_server_2008")
win_2008 = set()
for element in vuln_list:
    win_2008.add(element["id"])

win_2008_map = []
for cve_id in list(win_2008):
    url = "{}Updates('{}')?api-version={}".format(base_url,\
            cve_id, str(datetime.datetime.now().year))
    headers = {'api-key': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.content)
        id = data["value"][0]["ID"]
        win_2008_map.append({"cve_id":cve_id, "cvrf_id":id})
        print(cve_id + " : " + id)
    else:
        print(cve_id " + not found")

with open("data/versions/windows_server_2008", "w") as outfile:
    outfile.write(json.dumps(win_2008_map, indent = 4,\
                    sort_keys = True))

vuln_list = cve.search("microsoft/windows_server_2012")
win_2012 = set()
for element in vuln_list:
    win_2012.add(element["id"])

win_2012_map = []
for cve_id in list(win_2012):
    url = "{}Updates('{}')?api-version={}".format(base_url,\
           cve_id, str(datetime.datetime.now().year))
    headers = {'api-key': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.content)
        id = data["value"][0]["ID"]
        win_2012_map.append({"cve_id":cve_id, "cvrf_id":id})
        print(cve_id + " : " + id)
    else:
        print(cve_id + " not found")

with open("data/versions/windows_server_2012", "w") as outfile:
    outfile.write(json.dumps(win_2012_map, indent = 4,\
                sort_keys = True))

vuln_list = cve.search("microsoft/windows_server_2016")
win_2016 = set()
for element in vuln_list:
    win_2016.add(element["id"])

win_2016_map = []
for cve_id in list(win_2016):
    url = "{}Updates('{}')?api-version={}".format(base_url,\
        cve_id, str(datetime.datetime.now().year))
    headers = {'api-key': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = json.loads(response.content)
        id = data["value"][0]["ID"]
        win_2016_map.append({"cve_id":cve_id, "cvrf_id":id})
        print(cve_id + " : " + id)
    else:
        print(cve_id + " not found")

with open("data/versions/windows_server_2016", "w") as outfile:
    outfile.write(json.dumps(win_2016_map, indent = 4,\
        sort_keys = True))
