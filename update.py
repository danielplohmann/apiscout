import os
import re
import sys

import requests

try:
    import config
except ImportError:
    print("create a config.py based on template.config.py and set your Malpedia API token!")
    sys.exit(1)


REQUEST_TIMEOUT = 60


def get_db_dir():
    """the dbs folder next to this script, regardless of the current working directory"""
    return os.path.join(os.path.abspath(os.path.dirname(__file__)), "dbs")


def delete_existing_dbs(keep):
    """delete old apivector db files"""
    for filename in os.listdir(get_db_dir()):
        if filename != keep and re.fullmatch(r"\d{4}-\d\d-\d\d-apivectors-v\d+\.csv", filename):
            os.remove(get_db_dir() + os.sep + filename)


def get_newest_db_version():
    """find ApiVector DB files and return newest version number found"""
    max_version = 0
    for filename in os.listdir(get_db_dir()):
        version = re.fullmatch(r"\d{4}-\d\d-\d\d-apivectors-v(?P<version_number>\d+)\.csv", filename)
        if version:
            max_version = max(max_version, int(version.group("version_number")))
    return max_version


def download_apivector_db():
    result = {"filename": "", "content": "", "version": 0}
    response = requests.get(
        "https://malpedia.caad.fkie.fraunhofer.de/api/list/apiscout/csv",
        headers={"Authorization": "apitoken " + config.APITOKEN},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code == 200:
        version = re.search(
            r"\d{4}-\d\d-\d\d-apivectors-v(?P<version_number>\d+)\.csv", response.headers.get("Content-Disposition", "")
        )
        if version:
            result["filename"] = version.group(0)
            result["content"] = response.text
            result["version"] = int(version.group("version_number"))
    else:
        print("Failed to download ApiVector DB, response code: ", response.status_code)
    return result


def check_malpedia_version():
    response = requests.get("https://malpedia.caad.fkie.fraunhofer.de/api/get/version", timeout=REQUEST_TIMEOUT)
    if response.status_code == 200:
        return response.json()["version"]
    print("Failed to check Malpedia version, response code: ", response.status_code)
    return None


def main():
    db_version = get_newest_db_version()
    malpedia_version = check_malpedia_version()
    if malpedia_version is None:
        return 1
    if db_version < malpedia_version:
        apivector_update = download_apivector_db()
        if apivector_update["version"]:
            update_db_path = get_db_dir() + os.sep + apivector_update["filename"]
            with open(update_db_path, "w") as fout:
                fout.write(apivector_update["content"])
            delete_existing_dbs(keep=apivector_update["filename"])
            print("Downloaded and stored ApiVector DB file: ", update_db_path)
        else:
            print("ApiVector update download failed.")
            return 1
    else:
        print(f"Your ApiVector DB is the most recent ({malpedia_version})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
