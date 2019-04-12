import json
import sys

def cve_to_kb(cve, id_file):
    with open("data/id/" + id_file) as json_file:
        data = json.load(json_file)

        kbs = {"KB{}".format(kb["Description"]["Value"]) for vuln \
                in data["Vulnerability"] if vuln["CVE"] == cve \
                for kb in vuln["Remediations"] if "SubType" in kb \
                and kb["SubType"] != "Monthly Rollup" and "Value" \
                in kb["Description"]}

        return {"cve" : cve, "kbs" : list(kbs)}

def cve_to_kb_map_file(filename):

    print("Creating " + filename + "...\n")

    with open("data/versions/" + filename) as json_file:
        data = json.load(json_file)

        cve_kb_map = []
        index = 0
        for element in data:
            if not element["cvrf_id"] == "2016-Oct":
                cve_kb_map.append(cve_to_kb(element["cve_id"],\
                                    element["cvrf_id"]))
                index += 1
                progressbar_update(index, len(data))

        with open("data/versions/" + filename + "_map", "w") \
                       as outfile:
            outfile.write(json.dumps(cve_kb_map, indent = 4,\
                        sort_keys = True))

def progressbar_update(current_val, end_val, bar_length=50):
    percent = float(current_val) / end_val
    hashes = '#' * int(round(percent * bar_length))
    spaces = ' ' * (bar_length - len(hashes))
    sys.stdout.write("\rProgress: [{0}] {1}%".format(\
                        hashes + spaces, int(round(percent * 100))))
    sys.stdout.flush()

cve_to_kb_map_file("windows_server_2008")
cve_to_kb_map_file("windows_server_2012")
cve_to_kb_map_file("windows_server_2016")
