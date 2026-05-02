import subprocess
import json


# Continuous parsing of json objects
def parse_json(json_string):
    decoder = json.JSONDecoder()
    i = 0
    while i < len(json_string):
        # Count whitespace since raw_decode doesn't
        while i < len(json_string) and json_string[i].isspace():
            i += 1
        if i >= len(json_string): break
        
        obj, last_index = decoder.raw_decode(json_string, i)
        yield obj
        i = last_index

def get_dependencies(path="/"):
    cmd = ["go", "list", "-m", "-json", "all"]

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=path,
        text=True,
    )
    stdout, stderr = process.communicate()
    for dependency in parse_json(stdout):
        yield dependency 

def main():
    for line in get_dependencies("../example_project"):
        print(line)

if __name__ == '__main__':
    main()