import re
import os
import sys
import requests

try:
    import config
except:
    print("create a config.py based on template.config.py and set your Malpedia API token!")
    sys.exit()


def delete_existing_dbs():
    """ delete potentially existing old apivector db files """
    for filename in os.listdir("dbs"):
        if re.search(r"\d{4}-\d\d-\d\d-apivectors-v\d+\.csv", filename):
            os.remove("dbs" + os.sep + filename)


def get_newest_db_version():
    """ find ApiVector DB files and return newest version number found """
    max_version = 0
    for filename in os.listdir("dbs"):
        version = re.search(r"\d{4}-\d\d-\d\d-apivectors-v(?P<version_number>\d+)\.csv", filename)
        if version:
            max_version = max(max_version, int(version.group("version_number")))
    return max_version


def download_apivector_db():
    result = {
        "filename": "",
        "content": "",
        "version": 0
    }
    response = requests.get(
        'https://malpedia.caad.fkie.fraunhofer.de/api/list/apiscout/csv',
        headers={'Authorization': 'apitoken ' + config.APITOKEN},
    )
    if response.status_code == 200:
        result["filename"] = response.headers['Content-Disposition'].split("=")[1].strip()
        result["content"] = response.text
        version = re.search(r"\d{4}-\d\d-\d\d-apivectors-v(?P<version_number>\d+)\.csv", result["filename"])
        result["version"] = version
    else:
        print("Failed to download ApiVector DB, response code: ", response.status_code)
    return result


def check_malpedia_version():
    remote_version = 0
    response = requests.get(
        'https://malpedia.caad.fkie.fraunhofer.de/api/get/version'
    )
    if response.status_code == 200:
        response_json = response.json()
        remote_version =response_json["version"]
    else:
        print("Failed to check Malpedia version, response code: ", response.status_code)
    return remote_version


def main():
    db_version = get_newest_db_version()
    malpedia_version = check_malpedia_version()
    if db_version < malpedia_version:
        apivector_update = download_apivector_db()
        if apivector_update["version"]:
            delete_existing_dbs()
            update_db_path = "dbs" + os.sep + apivector_update["filename"]
            with open(update_db_path, "w") as fout:
                fout.write(apivector_update["content"])
            print("Downloaded and stored ApiVector DB file: ", update_db_path)
        else:
            print("ApiVector update download failed.")
    else:
        print("Your ApiVector DB is the most recent ({})".format(malpedia_version))


if __name__ == "__main__":
    sys.exit(main())
