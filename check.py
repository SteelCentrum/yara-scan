import os
import re
import subprocess
import argparse

try:
    import yaml
    import yara
    import yarautil
except ImportError as e:
    raise e
    print("import error: \n\trun python3 -m pip install -r requirements.txt\n\tbefore running the script")
    exit(1)



parser = argparse.ArgumentParser(description="")
parser.add_argument("-f", "--file", default="rules.yaml", help="YAML rule file ")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
args = parser.parse_args()

try:
    with open(args.file, "r") as f:
        config = yaml.safe_load(f)
except:
    print("error parsing ", args.f)
    exit(1)


directories = config.get("directories", [])
rules_dict = config.get("rules", {})
regexes = config.get("regexes", [])
kernel_module = config.get("kernel_module", "")

rules = yara.compile(sources=rules_dict)

for d in directories:
    for root, dirs, files in os.walk(d):
        for name in files:
            path = os.path.join(root, name)
            try:
                matches = rules.match(path)
                for m in matches:
                    print(f"file match found: {m.rule} in {path}")
                    if args.verbose:
                        yarautil.visualize.visualize(m)

            except Exception as e:
                print("exc:", e)
                pass

proc_dir = "/proc"
for pid in os.listdir(proc_dir):
    if pid.isdigit():
        cmdline_path = os.path.join(proc_dir, pid, "cmdline")
        if os.path.exists(cmdline_path):
            try:
                with open(cmdline_path, "r") as cmd_file:
                    cmdline = cmd_file.read().replace('\x00', ' ')
                    for pattern in regexes:
                        if re.search(pattern, cmdline):
                            print(f"process {pid} matches regex: {pattern}")
                            yarautil.scanutil.scanmem(pid, rules)
            except:
                pass


# unhide rootkit
_ = os.kill(0, 51)

lsmod_output = subprocess.check_output(["lsmod"], text=True).splitlines()
for line in lsmod_output:
    if kernel_module and kernel_module in line.split():
        print(f"kernel module {kernel_module} is loaded.")
        break
