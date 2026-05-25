import json
import os
import requests
import tempfile
import zipfile
import shutil

DB_VERSION_URL = "https://vuln.go.dev/index/db.json"
VULNDB_ZIP_URL = "https://vuln.go.dev/vulndb.zip"
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

def get_current_version():
    db_json_path = os.path.join(DATA_DIR, "db.json")
    if not os.path.exists(db_json_path):
        print("Local db.json file not found.")
        return None
    try:
        with open(db_json_path, 'r') as file:
            local_db = json.load(file)
        return local_db["modified"]
    except (json.JSONDecodeError, KeyError):
        print("Could not parse local db.json.")
        return None

def get_latest_version():
    try:
        response = requests.get(DB_VERSION_URL, timeout=30)
        response.raise_for_status()
        latest_version = response.json()
        return latest_version["modified"]
    except requests.exceptions.RequestException as e:
        print(f'Error fetching database version: {e}')
        return None
    
def full_update():
    try:
        response = requests.get(VULNDB_ZIP_URL, timeout=120)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error downloading database: {e}")
        return False
    with tempfile.TemporaryDirectory() as tmp_dir:
        zip_path = os.path.join(tmp_dir, 'vulndb.zip')
        with open(zip_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        # Unzips everything
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_file:
                zip_file.extractall(tmp_dir)
        except zipfile.BadZipFile as e:
            print(f"Error: Not a valid zip file: {e}")
            return False
        
        # Update /ID/
        os.makedirs(DATA_DIR, exist_ok=True)
        new_id_dir = os.path.join(tmp_dir, "ID")
        if os.path.exists(new_id_dir) and os.path.isdir(new_id_dir):
            old_id_dir = os.path.join(DATA_DIR, "ID")
            if os.path.exists(old_id_dir):
                shutil.rmtree(old_id_dir)
            shutil.copytree(new_id_dir, old_id_dir)
            print("ID directory updated.")
        else:
            print("Error: ID directory not found in import.")
        # Update modules.json
        new_modules_json = os.path.join(tmp_dir, "index", "modules.json")
        if os.path.exists(new_modules_json):
            shutil.copy2(new_modules_json, os.path.join(DATA_DIR, "modules.json"))
            print("modules.json updated.")
        else:
            print("Error: modules.json not found in import.")

        # Update db.json
        new_db_json = os.path.join(tmp_dir, "index", "db.json")
        if os.path.exists(new_db_json):
            shutil.copy2(new_db_json, os.path.join(DATA_DIR, "db.json"))
            print("db.json updated.")
        else:
            print("Error: db.json not found in import.")

    print("====================================================")
    print("====================================================")
    print("====================================================")
    print("Database updated.")
    return True

def check_for_updates():
    print("Checking for updates...")
    current_version = get_current_version()
    latest_version = get_latest_version()
    if latest_version is None:
        print(f"Could not fetch current version from: {DB_VERSION_URL}")
    elif current_version is None:
        print("Nonexistent or corrupted local db.json file found. Full update underway.")
        success = full_update()
        if success:
            print(f"Database updated to version from {latest_version}")
        else:
            print("Database update failed.")
    elif current_version < latest_version:
        print(f"Found latest version greater than current local versionn. Full update underway.")
        success = full_update()
        if success:
            print(f"Database updated to version from {latest_version}")
        else:
            print("Database update failed.")
    else:
        print(f"Local database is up to date (modified : {current_version})")

if __name__ == "__main__":
    print("Running manual update...")
    check_for_updates()