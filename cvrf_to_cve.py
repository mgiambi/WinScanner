import json
import requests
import datetime

base_url = "https://api.msrc.microsoft.com/"
api_key = "15ec9ebc4fe9469784f10724bf752f82"

url = "{}updates?api-version={}".format(base_url,\
        str(datetime.datetime.now().year))
headers = {'api-key': api_key}
response = requests.get(url, headers=headers)

cvrf_id_list = set()
if response.status_code == 200:
    data = json.loads(response.content)
    for element in data["value"]:
        cvrf_id_list.add(element["ID"])

for cvrf_id in list(cvrf_id_list):
    url = "{}cvrf/{}?api-version={}".format(base_url,\
        cvrf_id, str(datetime.datetime.now().year))
    headers = {'api-key': api_key, 'Accept': 'application/json'}
    response = requests.get(url, headers = headers)
    data = json.loads(response.content)
    with open("data/id/" + cvrf_id, "w") as json_file:
        json.dump(data, json_file, sort_keys = True, indent = 4)
    print(cvrf_id)
