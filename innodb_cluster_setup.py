#!/usr/bin/env python3
"""
MySQL InnoDB Cluster setup.

Run on the master node:  sudo python3 innodb_cluster_setup.py

Asks for the cluster settings, lets you pick the MySQL version from what the
repository currently offers, then runs playbooks/mysql-innodb.yml on all 3 nodes.
"""

import getpass
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

VERSION = "2.0.0"

BASE_DIR = Path(__file__).resolve().parent
PLAYBOOK = BASE_DIR / "playbooks" / "mysql-innodb.yml"
INVENTORY = BASE_DIR / "playbooks" / "inventory.ini"
CONFIG_FILE = BASE_DIR / "cluster_config.json"
LOG_FILE = BASE_DIR / "cluster_setup.log"
REPORT_FILE = BASE_DIR / "cluster_setup_report.txt"

MAJOR_VERSIONS = ["8.0", "8.4"]
NODE_ROLES = ["Master", "Secondary 1", "Secondary 2"]
TOTAL_STEPS = 6

# Ubuntu: Oracle's APT index only lists the newest build of a series, but older
# builds stay in the pool. Read the newest version from the index, then probe the
# pool for every patch release below it. Prints "server X.Y.Z" / "shell X.Y.Z".
UBUNTU_VERSIONS_CMD = r"""
. /etc/os-release
repo=https://repo.mysql.com/apt/ubuntu
index=$(curl -fsS $repo/dists/$VERSION_CODENAME/__COMPONENT__/binary-amd64/Packages) || exit 1
newest() { echo "$index" | awk -v p="$1" '$0 == "Package: " p {f=1} f && /^Version:/ {sub(/-.*/, "", $2); print $2; exit}'; }
echo "shell $(newest mysql-shell)"
last=$(newest mysql-community-server); last=${last##*.}
for patch in $(seq 0 $last); do
  v=__MAJOR__.$patch
  curl -fsI -o /dev/null $repo/pool/__COMPONENT__/m/mysql-community/mysql-community-server_$v-1ubuntu${VERSION_ID}_amd64.deb && echo "server $v" &
done
wait
"""

# RHEL: every mysql-server build in AppStream, modular streams included.
RHEL_VERSIONS_CMD = "dnf -q repoquery --disable-modular-filtering --qf '%{version}' mysql-server"


# ─── Output and prompts ──────────────────────────────────────────────────────

GREEN, YELLOW, RED, CYAN, BOLD, END = "\033[92m", "\033[93m", "\033[91m", "\033[96m", "\033[1m", "\033[0m"


def step(number, title):
    print(f"\n{BOLD}[{number}/{TOTAL_STEPS}] {title}{END}\n{'─' * 60}")


def info(msg):
    print(f"  {CYAN}{msg}{END}")


def ok(msg):
    print(f"  {GREEN}✓ {msg}{END}")


def fail(msg):
    print(f"  {RED}✗ {msg}{END}")
    sys.exit(1)


def ask(label, default="", check=None, allow_empty=False):
    while True:
        suffix = f" [{default}]" if default else ""
        value = input(f"    {label}{suffix}: ").strip() or default
        if (value or allow_empty) and (check is None or not value or check(value)):
            return value
        print(f"    {RED}Invalid value, try again.{END}")


def ask_password(label, current=""):
    """Ask twice for a password. With a current value, Enter keeps it."""
    hint = " (Enter = keep)" if current else ""
    while True:
        password = getpass.getpass(f"    {label}{hint}: ")
        if not password and current:
            return current
        if len(password) < 4:
            print(f"    {RED}At least 4 characters.{END}")
        elif password != getpass.getpass(f"    {label} (again): "):
            print(f"    {RED}Passwords do not match.{END}")
        else:
            return password


def ask_yes(label, default=True):
    answer = input(f"    {label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    return default if not answer else answer in ("y", "yes")


def choose(label, options, default=None):
    print(f"    {label}:")
    for number, option in enumerate(options, 1):
        print(f"      {number}. {option}{'   (default)' if option == default else ''}")
    default_number = str(options.index(default) + 1) if default in options else ""
    while True:
        answer = input(f"    Choice [{default_number}]: ").strip() or default_number
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1]
        print(f"    {RED}Enter a number between 1 and {len(options)}.{END}")


def is_ip(value):
    try:
        socket.inet_aton(value)
        return value.count(".") == 3
    except OSError:
        return False


def is_hostname(value):
    return re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$", value) is not None


def version_key(version):
    return tuple(int(part) for part in version.split("."))


# ─── Commands ────────────────────────────────────────────────────────────────

def run(command):
    return subprocess.run(command, shell=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, universal_newlines=True)


def run_on_node(ip, command):
    """Run a shell command on a node through Ansible. Returns stdout lines, or None on failure."""
    result = subprocess.run(["ansible", ip, "-i", str(INVENTORY), "-m", "shell", "-a", command],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if result.returncode != 0:
        return None
    # The first line is Ansible's "<ip> | CHANGED | rc=0 >>" header.
    return [line.strip() for line in result.stdout.splitlines()[1:] if line.strip()]


# ─── Steps ───────────────────────────────────────────────────────────────────

def setup_environment():
    step(1, "Environment")
    if os.geteuid() != 0:
        fail("Run as root: sudo python3 innodb_cluster_setup.py")

    if shutil.which("apt-get"):
        install, packages = "apt-get install -y -qq", {"ansible": "ansible", "sshpass": "sshpass"}
        run("apt-get update -qq")
    else:
        install, packages = "dnf install -y -q", {"ansible": "ansible-core", "sshpass": "sshpass"}

    for command, package in packages.items():
        if not shutil.which(command):
            info(f"Installing {package} ...")
            if run(f"{install} {package}").returncode != 0:
                fail(f"Could not install {package}.")

    ok(run("ansible --version").stdout.splitlines()[0])


def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (OSError, ValueError):
        return {}


def save_config(config):
    CONFIG_FILE.write_text(json.dumps(config, indent=4))
    os.chmod(CONFIG_FILE, 0o600)


def show_config(config):
    rows = [(f"{role} node", f"{node['hostname']} ({node['ip']})")
            for role, node in zip(NODE_ROLES, config["nodes"])]
    rows += [
        ("SSH user", config["ssh_user"]),
        ("SSH auth", f"key {config['ssh_key_file']}" if config.get("ssh_key_file") else "password"),
        ("Privilege escalation", config["become_method"]),
        ("Cluster name", config["innodb_cluster_name"]),
        ("Cluster admin user", config["innodb_admin_user"]),
        ("NTP servers", f"{config['ntp_primary']}, {config['ntp_fallback']}"),
    ]
    if config.get("mysql_version_full"):
        rows.append(("MySQL version", config["mysql_version_full"]))
    print()
    for label, value in rows:
        print(f"    {label:<22} {value}")
    print()


def collect_config(old):
    """Ask every setting. Values from the previous answers are offered as defaults."""
    config = {"nodes": []}
    old_nodes = old.get("nodes") or [{}, {}, {}]

    print(f"\n  {BOLD}Cluster nodes{END} (the first node is the master)")
    for role, previous in zip(NODE_ROLES, old_nodes):
        config["nodes"].append({
            "hostname": ask(f"{role} hostname", previous.get("hostname", ""), is_hostname),
            "ip": ask(f"{role} IP address", previous.get("ip", ""), is_ip),
        })

    print(f"\n  {BOLD}SSH connection{END}")
    config["ssh_user"] = ask("SSH user", old.get("ssh_user", "ansible"))
    default_key = old.get("ssh_key_file", os.path.expanduser("~/.ssh/id_rsa"))
    key = ask("SSH key file (empty = password)", default_key if os.path.exists(default_key) else "",
              os.path.exists, allow_empty=True)
    config["ssh_key_file"] = key
    config["ssh_password"] = "" if key else ask_password("SSH password", old.get("ssh_password", ""))
    config["become_method"] = choose("Privilege escalation", ["sudo", "dzdo"], old.get("become_method", "sudo"))
    config["become_password"] = ""
    if ask_yes(f"Does {config['become_method']} need a password?", bool(old.get("become_password"))):
        config["become_password"] = ask_password(f"{config['become_method']} password", old.get("become_password", ""))

    print(f"\n  {BOLD}MySQL{END}")
    config["mysql_root_password"] = ask_password("MySQL root password", old.get("mysql_root_password", ""))
    config["innodb_admin_user"] = ask("Cluster admin user", old.get("innodb_admin_user", "clusterAdmin"))
    config["innodb_admin_password"] = ask_password("Cluster admin password", old.get("innodb_admin_password", ""))
    config["innodb_cluster_name"] = ask("Cluster name", old.get("innodb_cluster_name", "mysql-cluster"))
    config["router_password"] = ask_password("MySQL Router user (routeruser) password", old.get("router_password", ""))

    print(f"\n  {BOLD}NTP{END}")
    config["ntp_primary"] = ask("Primary NTP server", old.get("ntp_primary", "time.google.com"))
    config["ntp_fallback"] = ask("Fallback NTP server", old.get("ntp_fallback", "pool.ntp.org"))

    for key in ("mysql_version", "mysql_version_full", "mysql_shell_version"):
        if old.get(key):
            config[key] = old[key]
    return config


def get_config():
    step(2, "Cluster configuration")
    config = load_config()
    if config:
        info("Saved configuration found:")
        show_config(config)
        if ask_yes("Use it?"):
            return config

    while True:
        config = collect_config(config)
        show_config(config)
        if ask_yes("Is this correct?"):
            break
    save_config(config)
    ok(f"Saved to {CONFIG_FILE}")
    return config


def write_inventory_and_test(config):
    step(3, "Inventory and SSH test")
    lines = ["[mysql_nodes]"]
    lines += [f"{node['ip']} node_hostname={node['hostname']}" for node in config["nodes"]]
    lines += ["", "[mysql_nodes:vars]", f"ansible_user={config['ssh_user']}"]
    if config["ssh_key_file"]:
        lines.append(f"ansible_ssh_private_key_file={config['ssh_key_file']}")
    else:
        lines.append(f"ansible_ssh_pass={config['ssh_password']}")
    lines += ["ansible_ssh_common_args='-o StrictHostKeyChecking=no'",
              "ansible_become=true", f"ansible_become_method={config['become_method']}"]
    if config["become_password"]:
        lines.append(f"ansible_become_pass={config['become_password']}")
    INVENTORY.write_text("\n".join(lines) + "\n")
    os.chmod(INVENTORY, 0o600)
    ok(f"Inventory written: {INVENTORY}")

    unreachable = []
    for role, node in zip(NODE_ROLES, config["nodes"]):
        if run(f"ansible {node['ip']} -i {INVENTORY} -m ping").returncode == 0:
            ok(f"{role:<12} {node['hostname']} ({node['ip']})")
        else:
            print(f"  {RED}✗ {role:<12} {node['hostname']} ({node['ip']}){END}")
            unreachable.append(node["ip"])
    if unreachable:
        fail("Fix SSH access to the nodes above and run the script again.")


def list_versions(master_ip, major):
    """Return (server versions oldest first, newest MySQL Shell version or None) for one series."""
    os_ids = " ".join(run_on_node(master_ip, ". /etc/os-release; echo $ID $ID_LIKE") or [])

    if "debian" in os_ids or "ubuntu" in os_ids:
        component = "mysql-8.0" if major == "8.0" else "mysql-8.4-lts"
        command = UBUNTU_VERSIONS_CMD.replace("__COMPONENT__", component).replace("__MAJOR__", major)
        lines = [line.split() for line in run_on_node(master_ip, command) or []]
        servers = [v for kind, v in lines if kind == "server"]
        shell = next((v for kind, v in lines if kind == "shell"), None)
    else:
        servers = [v for v in run_on_node(master_ip, RHEL_VERSIONS_CMD) or []
                   if v.startswith(major + ".")]
        shell = None  # dnf installs the newest MySQL Shell of the series

    return sorted(set(servers), key=version_key), shell


def select_mysql_version(config):
    step(4, "MySQL version")
    if config.get("mysql_version_full"):
        info(f"Saved choice: MySQL {config['mysql_version_full']}")
        if ask_yes("Keep it?"):
            return

    major = choose("MySQL series", MAJOR_VERSIONS, config.get("mysql_version", "8.0"))
    info(f"Reading the MySQL {major} versions available to {config['nodes'][0]['ip']} ...")
    versions, shell = list_versions(config["nodes"][0]["ip"], major)
    if not versions:
        fail(f"No MySQL {major} packages found. Check the node's repositories and internet access.")

    newest_first = versions[::-1]
    config["mysql_version"] = major
    config["mysql_version_full"] = choose(f"MySQL {major} version", newest_first, newest_first[0])
    config["mysql_shell_version"] = shell or ""
    save_config(config)
    ok(f"MySQL {config['mysql_version_full']} selected"
       + (f" (MySQL Shell {shell})" if shell else ""))


def run_playbook(config):
    step(5, "Deployment")
    master = config["nodes"][0]
    info(f"Cluster {config['innodb_cluster_name']}, master {master['hostname']} ({master['ip']}), "
         f"MySQL {config['mysql_version_full']}")
    if not ask_yes("Start the deployment?"):
        sys.exit(0)

    extra_vars = {key: config[key] for key in (
        "mysql_root_password", "innodb_admin_user", "innodb_admin_password", "innodb_cluster_name",
        "router_password", "ntp_primary", "ntp_fallback",
        "mysql_version", "mysql_version_full", "mysql_shell_version")}
    extra_vars["master_ip"] = master["ip"]
    extra_vars["cluster_hosts"] = config["nodes"]

    vars_file = PLAYBOOK.parent / ".extra_vars.json"
    vars_file.write_text(json.dumps(extra_vars))
    os.chmod(vars_file, 0o600)

    started = time.time()
    output = []
    try:
        process = subprocess.Popen(
            ["ansible-playbook", "-i", str(INVENTORY), str(PLAYBOOK), "--extra-vars", f"@{vars_file}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, bufsize=1)
        with open(LOG_FILE, "w") as log:
            for line in process.stdout:
                sys.stdout.write(line)
                log.write(line)
                output.append(line.rstrip())
        process.wait()
    finally:
        vars_file.unlink()
    return process.returncode, output, time.time() - started


def write_report(config, returncode, output, seconds):
    step(6, "Report")
    nodes = config["nodes"]
    master = nodes[0]

    recap = {}
    for line in output:
        match = re.match(r"(\S+)\s+:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)", line)
        if match:
            recap[match.group(1)] = match.groups()[1:]

    lines = [
        "MySQL InnoDB Cluster Setup Report",
        "=" * 60,
        f"Date            : {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Result          : {'SUCCESS' if returncode == 0 else 'FAILED'} (ansible exit code {returncode})",
        f"Duration        : {int(seconds // 60)} min {int(seconds % 60)} sec",
        f"Cluster         : {config['innodb_cluster_name']}",
        f"MySQL           : {config['mysql_version_full']}",
        f"Cluster admin   : {config['innodb_admin_user']}",
        "Router user     : routeruser",
        "",
        f"{'Node':<44} {'ok':>4} {'changed':>8} {'unreach':>8} {'failed':>7}",
    ]
    for role, node in zip(NODE_ROLES, nodes):
        counts = recap.get(node["ip"], ("-",) * 4)
        lines.append(f"{role + ': ' + node['hostname'] + ' (' + node['ip'] + ')':<44} "
                     f"{counts[0]:>4} {counts[1]:>8} {counts[2]:>8} {counts[3]:>7}")
    lines.append("")
    if returncode == 0:
        lines += [
            "Next steps:",
            f"  mysqlsh {config['innodb_admin_user']}@{master['ip']} -- cluster status",
            f"  mysqlrouter --bootstrap routeruser@{master['ip']}:3306 --user=mysqlrouter",
        ]
    else:
        lines.append(f"Check the log: {LOG_FILE}")

    report = "\n".join(lines) + "\n"
    REPORT_FILE.write_text(report)
    print(report)
    ok(f"Report saved: {REPORT_FILE}")


def main():
    print(f"\n{BOLD}MySQL InnoDB Cluster Setup v{VERSION}{END}")
    try:
        setup_environment()
        config = get_config()
        write_inventory_and_test(config)
        select_mysql_version(config)
        returncode, output, seconds = run_playbook(config)
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}Cancelled.{END}")
        sys.exit(130)
    write_report(config, returncode, output, seconds)
    sys.exit(returncode)


if __name__ == "__main__":
    main()
