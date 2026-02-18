#!/usr/bin/env python3
"""
MySQL InnoDB Cluster Setup Orchestrator
========================================
Deploys a 3-node InnoDB Cluster by running from the master node.

Usage:
    sudo python3 innodb_cluster_setup.py

Features:
    - Automatically sets up the Ansible execution environment
    - Collects required variables (hostname + IP) from the end user
    - Saves variables to a file (skips prompts on subsequent runs)
    - Uses IP addresses for all SSH/Ansible connectivity (DNS-independent)
    - Populates /etc/hosts on all nodes for hostname resolution
    - Streams Ansible playbook output to the terminal in real-time
    - Generates a detailed post-setup report
"""

import os
import sys
import json
import subprocess
import shutil
import socket
import time
import re
import signal
import termios
import tty
from datetime import datetime
from pathlib import Path

# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = "1.2.0"

SCRIPT_DIR = Path(__file__).resolve().parent
PLAYBOOKS_DIR = SCRIPT_DIR / "playbooks"
CONFIG_FILE = SCRIPT_DIR / "cluster_config.json"
INVENTORY_FILE = PLAYBOOKS_DIR / "inventory.ini"
PLAYBOOK_FILE = PLAYBOOKS_DIR / "mysql-innodb.yml"
REPORT_FILE = SCRIPT_DIR / "cluster_setup_report.txt"
LOG_FILE = SCRIPT_DIR / "cluster_setup.log"

REQUIRED_PACKAGES_DEBIAN = [
    "ansible",
    "sshpass",
    "python3-pip",
]

REQUIRED_PACKAGES_REDHAT = [
    "sshpass",
    "python3-pip",
]

ANSIBLE_COLLECTIONS = [
    "community.mysql",
]

TOTAL_STEPS = 7


# ─── Colors & Formatting ────────────────────────────────────────────────────

class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


# ─── Utility Functions ────────────────────────────────────────────────────────

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print(f"\n\n  {Colors.YELLOW}Operation cancelled by user (Ctrl+C).{Colors.END}")
    print(f"  {Colors.CYAN}No changes were applied to the cluster.{Colors.END}\n")
    sys.exit(130)


signal.signal(signal.SIGINT, signal_handler)


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}\
╔══════════════════════════════════════════════════════════════╗
║           MySQL InnoDB Cluster Setup Orchestrator            ║
║                    3-Node Cluster Deployment                 ║
║                                                       v{VERSION} ║
╚══════════════════════════════════════════════════════════════╝\
{Colors.END}"""
    print(banner)


def print_step(step_num, title):
    """Print a step header with progress indicator."""
    progress = f"[Step {step_num}/{TOTAL_STEPS}]"
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'─' * 60}")
    print(f"  {progress} {title}")
    print(f"{'─' * 60}{Colors.END}\n")


def print_section(title):
    print(f"\n{Colors.BLUE}{Colors.BOLD}{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}{Colors.END}\n")


def print_success(msg):
    print(f"  {Colors.GREEN}✓ {msg}{Colors.END}")


def print_warning(msg):
    print(f"  {Colors.YELLOW}⚠ {msg}{Colors.END}")


def print_error(msg):
    print(f"  {Colors.RED}✗ {msg}{Colors.END}")


def print_info(msg):
    print(f"  {Colors.CYAN}ℹ {msg}{Colors.END}")


def print_hint(msg):
    """Print a hint message for guidance."""
    print(f"    {Colors.CYAN}{msg}{Colors.END}")


def print_table_row(label, value, mask=False, col1=30, col2=37):
    """Print a formatted table row for summary display."""
    display_value = '*' * 8 if mask else value
    print(f"  {Colors.BOLD}│{Colors.END} {label:<{col1 - 2}} {Colors.BOLD}│{Colors.END} {display_value:<{col2 - 2}} {Colors.BOLD}│{Colors.END}")


def prompt_input(label, default=None, hint=None):
    """Enhanced input prompt with default value and optional hint."""
    if hint:
        print_hint(hint)
    if default:
        value = input(f"    {Colors.BOLD}{label} [{default}]:{Colors.END} ").strip()
        return value if value else default
    else:
        value = input(f"    {Colors.BOLD}{label}:{Colors.END} ").strip()
        return value


def read_password_masked(prompt_text):
    """Read a password from stdin, showing * for each character."""
    sys.stdout.write(prompt_text)
    sys.stdout.flush()
    password = []
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ('\r', '\n'):
                sys.stdout.write('\r\n')
                break
            elif ch == '\x7f' or ch == '\x08':  # backspace
                if password:
                    password.pop()
                    sys.stdout.write('\b \b')
            elif ch == '\x03':  # Ctrl+C
                sys.stdout.write('\r\n')
                raise KeyboardInterrupt
            else:
                password.append(ch)
                sys.stdout.write('*')
            sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ''.join(password)


def prompt_password(label, min_length=4, confirm=True):
    """Enhanced password prompt with masked input (shows *)."""
    while True:
        password = read_password_masked(f"    {Colors.BOLD}{label}:{Colors.END} ")
        if len(password) < min_length:
            print_error(f"Password must be at least {min_length} characters!")
            continue
        if confirm:
            password_confirm = read_password_masked(f"    {Colors.BOLD}{label} (confirm):{Colors.END} ")
            if password != password_confirm:
                print_error("Passwords do not match! Please try again.")
                continue
        return password


def prompt_yes_no(label, default_yes=True):
    """Yes/No prompt with clear default."""
    suffix = "[Y/n]" if default_yes else "[y/N]"
    choice = input(f"    {Colors.BOLD}{label} {suffix}:{Colors.END} ").strip().lower()
    if default_yes:
        return choice not in ('n', 'no')
    else:
        return choice in ('y', 'yes')


def run_command(cmd, capture=False, check=True, env=None):
    """Execute a shell command with optional streaming output."""
    try:
        if capture:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True,
                check=check, env=env
            )
            return result
        else:
            result = subprocess.run(
                cmd, shell=True, check=check, env=env
            )
            return result
    except subprocess.CalledProcessError as e:
        if capture:
            return e
        raise


def run_command_stream(cmd, log_file=None, env=None):
    """Execute a command and stream output in real-time while capturing it."""
    output_lines = []

    process = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env
    )

    with open(log_file, "a") if log_file else open(os.devnull, "w") as log:
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            output_lines.append(line.rstrip())
            if log_file:
                log.write(line)
                log.flush()

    process.wait()
    return process.returncode, output_lines


def validate_ip(ip):
    """Validate an IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def validate_hostname(hostname):
    """Validate a hostname (not IP)."""
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', hostname):
        return True
    return False


def format_duration(seconds):
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins} min {secs} sec"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours} hr {mins} min"


# ─── Environment Setup ───────────────────────────────────────────────────────

def detect_os_family():
    """Detect the OS family of the local machine (where the script runs).

    Returns 'debian' or 'redhat'. Exits if unsupported.
    """
    os_release = Path("/etc/os-release")
    if os_release.exists():
        content = os_release.read_text().lower()
        if any(d in content for d in ("ubuntu", "debian")):
            return "debian"
        if any(d in content for d in ("rhel", "centos", "rocky", "alma", "fedora", "red hat")):
            return "redhat"

    # Fallback: check for package managers
    if shutil.which("apt-get"):
        return "debian"
    if shutil.which("dnf") or shutil.which("yum"):
        return "redhat"

    print_error("Unsupported operating system. Only Debian/Ubuntu and RedHat/CentOS are supported.")
    sys.exit(1)


def check_root():
    """Check if running as root or with sudo."""
    if os.geteuid() != 0:
        print_error("This script must be run with root privileges.")
        print()
        print_hint("Run with:  sudo python3 innodb_cluster_setup.py")
        print()
        sys.exit(1)


def setup_environment():
    """Install required packages and Ansible collections."""
    print_step(1, "ENVIRONMENT SETUP")

    os_family = detect_os_family()
    print_info(f"Detected OS family: {os_family.upper()}")
    print_info("Checking and installing prerequisites...\n")

    if os_family == "debian":
        required_packages = REQUIRED_PACKAGES_DEBIAN
        update_cmd = "apt-get update -qq"
        check_cmd = "dpkg -l {pkg} 2>/dev/null | grep -q '^ii'"
        install_cmd = "apt-get install -y -qq {pkg}"
    else:
        required_packages = REQUIRED_PACKAGES_REDHAT
        update_cmd = "dnf makecache -q" if shutil.which("dnf") else "yum makecache -q"
        check_cmd = "rpm -q {pkg} >/dev/null 2>&1"
        install_cmd = ("dnf install -y -q {pkg}" if shutil.which("dnf")
                       else "yum install -y -q {pkg}")

    # Update package cache
    sys.stdout.write(f"  {Colors.CYAN}Updating package lists...{Colors.END}")
    sys.stdout.flush()
    result = run_command(update_cmd, capture=True, check=False)
    if result.returncode == 0:
        print(f"\r  {Colors.GREEN}✓ Package lists updated.{Colors.END}          ")
    else:
        print(f"\r  {Colors.YELLOW}⚠ Package list update had issues, continuing...{Colors.END}")

    # Install required OS packages
    for pkg in required_packages:
        sys.stdout.write(f"  {Colors.CYAN}Checking '{pkg}'...{Colors.END}")
        sys.stdout.flush()
        check = run_command(check_cmd.format(pkg=pkg), capture=True, check=False)
        if check.returncode == 0:
            print(f"\r  {Colors.GREEN}✓ {pkg:<30}{Colors.END} {'installed':>12}")
        else:
            print(f"\r  {Colors.YELLOW}  {pkg:<30}{Colors.END} {'installing...':>12}")
            result = run_command(install_cmd.format(pkg=pkg), capture=True, check=False)
            if result.returncode == 0:
                print(f"\033[1A\r  {Colors.GREEN}✓ {pkg:<30}{Colors.END} {'installed':>12}")
            else:
                print_error(f"Failed to install '{pkg}': {result.stderr}")
                sys.exit(1)

    # On RedHat, install Ansible via pip (no EPEL needed)
    if os_family == "redhat":
        pkg = "ansible"
        sys.stdout.write(f"  {Colors.CYAN}Checking '{pkg}'...{Colors.END}")
        sys.stdout.flush()
        check = run_command("ansible --version >/dev/null 2>&1", capture=True, check=False)
        if check.returncode == 0:
            print(f"\r  {Colors.GREEN}✓ {pkg:<30}{Colors.END} {'installed':>12}")
        else:
            print(f"\r  {Colors.YELLOW}  {pkg:<30}{Colors.END} {'installing...':>12}")
            result = run_command(
                "pip3 install ansible", capture=True, check=False
            )
            if result.returncode == 0:
                print(f"\033[1A\r  {Colors.GREEN}✓ {pkg:<30}{Colors.END} {'installed':>12}")
            else:
                print_error(f"Failed to install '{pkg}': {result.stderr}")
                sys.exit(1)

    # Install Ansible collections
    for collection in ANSIBLE_COLLECTIONS:
        sys.stdout.write(f"  {Colors.CYAN}Checking '{collection}'...{Colors.END}")
        sys.stdout.flush()
        check = run_command(
            f"ansible-galaxy collection list {collection} 2>/dev/null | grep -q '{collection}'",
            capture=True, check=False
        )
        if check.returncode == 0:
            print(f"\r  {Colors.GREEN}✓ {collection:<30}{Colors.END} {'installed':>12}")
        else:
            print(f"\r  {Colors.YELLOW}  {collection:<30}{Colors.END} {'installing...':>12}")
            result = run_command(
                f"ansible-galaxy collection install {collection}",
                capture=True, check=False
            )
            if result.returncode == 0:
                print(f"\033[1A\r  {Colors.GREEN}✓ {collection:<30}{Colors.END} {'installed':>12}")
            else:
                print_error(f"Failed to install '{collection}': {result.stderr}")
                sys.exit(1)

    # Verify ansible is accessible
    result = run_command("ansible --version", capture=True, check=False)
    if result.returncode == 0:
        version_line = result.stdout.split('\n')[0]
        print()
        print_success(f"Environment ready. ({version_line})")
    else:
        print_error("Ansible not found after installation!")
        sys.exit(1)

    # Verify playbooks directory exists
    if not PLAYBOOKS_DIR.exists():
        print_error(f"Playbooks directory not found: {PLAYBOOKS_DIR}")
        print_hint("Expected structure:")
        print_hint(f"  {SCRIPT_DIR.name}/")
        print_hint(f"    innodb_cluster_setup.py")
        print_hint(f"    playbooks/")
        print_hint(f"      mysql-innodb.yml")
        print_hint(f"      01-os-preconfigure/")
        print_hint(f"      02-mysql-install/")
        print_hint(f"      03-mysql-innodb-cluster/")
        print_hint(f"      04-mysql-create-innodb-cluster/")
        sys.exit(1)

    if not PLAYBOOK_FILE.exists():
        print_error(f"Playbook file not found: {PLAYBOOK_FILE}")
        sys.exit(1)


# ─── Configuration Management ────────────────────────────────────────────────

def load_config():
    """Load existing configuration if available."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
            return config
        except (json.JSONDecodeError, IOError):
            return None
    return None


def save_config(config):
    """Save configuration to file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)
    os.chmod(CONFIG_FILE, 0o600)
    print_success(f"Configuration saved to: {CONFIG_FILE}")


def display_config_summary(config, title="CONFIGURATION SUMMARY"):
    """Display a formatted summary table of all configuration."""
    print_section(title)

    nodes = config["nodes"]

    COL1 = 30

    # Calculate COL2 dynamically based on longest value
    all_values = [
        f"{node['hostname']} ({node['ip']})" for node in nodes
    ] + [
        config['ssh_user'],
        config.get('ssh_key_file', ''),
        config['innodb_admin_user'],
        config['innodb_cluster_name'],
        config.get('ntp_primary', 'time.google.com'),
        config.get('ntp_fallback', 'pool.ntp.org'),
    ]
    max_val_len = max(len(v) for v in all_values if v)
    COL2 = max(37, max_val_len + 4)  # +4 for padding (2 each side)

    def _row(label, value, mask=False):
        print_table_row(label, value, mask=mask, col1=COL1, col2=COL2)

    def _separator():
        print(f"  {Colors.BOLD}├{'─' * COL1}┼{'─' * COL2}┤{Colors.END}")

    def _section_header(text):
        print(f"  {Colors.BOLD}│{('  ' + text):<{COL1}}│{'':<{COL2}}│{Colors.END}")

    # Table top border
    print(f"  {Colors.BOLD}┌{'─' * COL1}┬{'─' * COL2}┐{Colors.END}")
    _section_header("CLUSTER NODES")
    _separator()
    for i, (label, node) in enumerate([("Master Node", nodes[0]), ("Slave Node 1", nodes[1]), ("Slave Node 2", nodes[2])]):
        _row(label, f"{node['hostname']} ({node['ip']})")

    _separator()
    _section_header("SSH CONNECTION")
    _separator()
    _row("SSH User", config['ssh_user'])
    if config.get("ssh_key_file"):
        _row("SSH Key File", config['ssh_key_file'])
    if config.get("ssh_password"):
        _row("SSH Password", "", mask=True)
    _row("Sudo Password", config.get('become_password', ''), mask=bool(config.get('become_password')))

    _separator()
    _section_header("MYSQL CONFIGURATION")
    _separator()
    _row("MySQL Root Password", "", mask=True)
    _row("Cluster Admin User", config['innodb_admin_user'])
    _row("Cluster Admin Password", "", mask=True)
    _row("Cluster Name", config['innodb_cluster_name'])
    _row("Router User (routeruser)", "", mask=True)

    _separator()
    _section_header("SYSTEM SETTINGS")
    _separator()
    _row("NTP Primary Server", config.get('ntp_primary', 'time.google.com'))
    _row("NTP Fallback Server", config.get('ntp_fallback', 'pool.ntp.org'))
    print(f"  {Colors.BOLD}└{'─' * COL1}┴{'─' * COL2}┘{Colors.END}")
    print()


def collect_node_info(node_num, label):
    """Collect hostname and IP address for a single node."""
    print(f"\n    {Colors.CYAN}[Node {node_num}/3]{Colors.END} {Colors.BOLD}{label}{Colors.END}")

    while True:
        hostname = input(f"      Hostname : ").strip()
        if validate_hostname(hostname):
            break
        print_error("Invalid hostname! Use alphanumeric characters, hyphens and dots only.")

    while True:
        ip = input(f"      IP Address: ").strip()
        if validate_ip(ip):
            break
        print_error("Invalid IP address format! Example: 192.168.1.10")

    print_success(f"{hostname} ({ip})")
    return {"hostname": hostname, "ip": ip}


def collect_variables():
    """Collect all required variables from user in organized sections."""
    print_step(2, "CLUSTER CONFIGURATION")
    print_info("Please provide the required information below.")
    print_hint("Press Enter to accept default values shown in [brackets].\n")

    config = {}

    # ── Section 1: Node Information ──────────────────────────
    print(f"  {Colors.YELLOW}{Colors.BOLD}Section 1/5: Cluster Nodes{Colors.END}")
    print_hint("Enter hostname and IP address for each of the 3 cluster nodes.")
    print_hint("The first node will be the master (primary) node.\n")

    config["nodes"] = []
    config["nodes"].append(collect_node_info(1, "Master Node (Primary)"))
    config["nodes"].append(collect_node_info(2, "Slave Node 1 (Secondary)"))
    config["nodes"].append(collect_node_info(3, "Slave Node 2 (Secondary)"))

    # ── Section 2: SSH Connection ────────────────────────────
    print(f"\n  {Colors.YELLOW}{Colors.BOLD}Section 2/5: SSH Connection{Colors.END}")
    print_hint("Ansible connects to nodes via SSH. Provide credentials below.\n")

    config["ssh_user"] = prompt_input("SSH User", default="ansible")

    default_key = os.path.expanduser("~/.ssh/id_rsa")
    print_hint("If you don't use an SSH key, just press Enter and provide a password instead.")
    ssh_key_input = prompt_input("SSH Key File", default=default_key)

    # User pressed Enter with default but file doesn't exist, or explicitly cleared it
    if ssh_key_input == default_key and not os.path.exists(default_key):
        ssh_key_input = ""

    if ssh_key_input and not os.path.exists(ssh_key_input):
        print_warning(f"SSH key file not found: {ssh_key_input}")
        ssh_key_input = ""

    if not ssh_key_input:
        print_info("No SSH key — switching to password authentication.")
        config["ssh_password"] = prompt_password("SSH Password")
        config["ssh_key_file"] = ""
    else:
        config["ssh_key_file"] = ssh_key_input

    print()
    if prompt_yes_no("Does the SSH user require a sudo password?", default_yes=False):
        config["become_password"] = prompt_password("Sudo Password")
    else:
        config["become_password"] = ""

    # ── Section 3: MySQL Credentials ─────────────────────────
    print(f"\n  {Colors.YELLOW}{Colors.BOLD}Section 3/5: MySQL Credentials{Colors.END}")
    print_hint("Set passwords for MySQL root and the InnoDB cluster admin user.\n")

    config["mysql_root_password"] = prompt_password("MySQL Root Password")
    print_success("MySQL root password set.")

    print()
    config["innodb_admin_user"] = prompt_input(
        "Cluster Admin Username", default="clusterAdmin",
        hint="This user will manage the InnoDB cluster."
    )
    config["innodb_admin_password"] = prompt_password("Cluster Admin Password")
    print_success("Cluster admin credentials set.")

    # ── Section 4: Cluster Settings ──────────────────────────
    print(f"\n  {Colors.YELLOW}{Colors.BOLD}Section 4/5: Cluster Settings{Colors.END}\n")

    config["innodb_cluster_name"] = prompt_input("Cluster Name", default="mysql-cluster")

    print()
    print_hint("A 'routeruser' account will be created for MySQL Router bootstrap.")
    config["router_password"] = prompt_password("Router User Password")
    print_success("Router user password set.")

    # ── Section 5: System Settings ───────────────────────────
    print(f"\n  {Colors.YELLOW}{Colors.BOLD}Section 5/5: System Settings{Colors.END}")
    print_hint("NTP time synchronization servers for all cluster nodes.\n")

    config["ntp_primary"] = prompt_input("Primary NTP Server", default="time.google.com")
    config["ntp_fallback"] = prompt_input("Fallback NTP Server", default="pool.ntp.org")

    return config


def get_configuration():
    """Get configuration - load from file or collect from user."""
    existing_config = load_config()

    if existing_config:
        display_config_summary(existing_config, "EXISTING CONFIGURATION FOUND")

        print_info("A saved configuration was found from a previous run.")
        print()
        if prompt_yes_no("Use this existing configuration?", default_yes=True):
            print_success("Using existing configuration.")
            return existing_config
        else:
            print_info("Starting fresh configuration...\n")

    config = collect_variables()
    config["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Show summary and allow correction
    display_config_summary(config)

    while True:
        if prompt_yes_no("Is this configuration correct?", default_yes=True):
            break
        else:
            print()
            print_info("Which section would you like to change?")
            print(f"    {Colors.BOLD}1{Colors.END} - Cluster Nodes")
            print(f"    {Colors.BOLD}2{Colors.END} - SSH Connection")
            print(f"    {Colors.BOLD}3{Colors.END} - MySQL Credentials")
            print(f"    {Colors.BOLD}4{Colors.END} - Cluster Settings")
            print(f"    {Colors.BOLD}5{Colors.END} - System Settings")
            print(f"    {Colors.BOLD}A{Colors.END} - Re-enter all values")
            print()
            section = input(f"    {Colors.BOLD}Section [1-5/A]:{Colors.END} ").strip().lower()

            if section == '1':
                config["nodes"] = []
                print(f"\n  {Colors.YELLOW}{Colors.BOLD}Re-entering: Cluster Nodes{Colors.END}\n")
                config["nodes"].append(collect_node_info(1, "Master Node (Primary)"))
                config["nodes"].append(collect_node_info(2, "Slave Node 1 (Secondary)"))
                config["nodes"].append(collect_node_info(3, "Slave Node 2 (Secondary)"))
            elif section == '2':
                print(f"\n  {Colors.YELLOW}{Colors.BOLD}Re-entering: SSH Connection{Colors.END}\n")
                config["ssh_user"] = prompt_input("SSH User", default=config.get("ssh_user", "ansible"))
                default_key = os.path.expanduser("~/.ssh/id_rsa")
                config["ssh_key_file"] = prompt_input("SSH Key File", default=config.get("ssh_key_file", default_key))
                if not os.path.exists(config["ssh_key_file"]):
                    print_warning(f"SSH key file not found: {config['ssh_key_file']}")
                    if prompt_yes_no("Connect with SSH password instead?", default_yes=True):
                        config["ssh_password"] = prompt_password("SSH Password")
                        config["ssh_key_file"] = ""
                    else:
                        print_error("An SSH key file or password is required!")
                        sys.exit(1)
                print()
                if prompt_yes_no("Does the SSH user require a sudo password?", default_yes=False):
                    config["become_password"] = prompt_password("Sudo Password")
                else:
                    config["become_password"] = ""
            elif section == '3':
                print(f"\n  {Colors.YELLOW}{Colors.BOLD}Re-entering: MySQL Credentials{Colors.END}\n")
                config["mysql_root_password"] = prompt_password("MySQL Root Password")
                config["innodb_admin_user"] = prompt_input("Cluster Admin Username", default=config.get("innodb_admin_user", "clusterAdmin"))
                config["innodb_admin_password"] = prompt_password("Cluster Admin Password")
            elif section == '4':
                print(f"\n  {Colors.YELLOW}{Colors.BOLD}Re-entering: Cluster Settings{Colors.END}\n")
                config["innodb_cluster_name"] = prompt_input("Cluster Name", default=config.get("innodb_cluster_name", "mysql-cluster"))
                config["router_password"] = prompt_password("Router User Password")
            elif section == '5':
                print(f"\n  {Colors.YELLOW}{Colors.BOLD}Re-entering: System Settings{Colors.END}\n")
                config["ntp_primary"] = prompt_input("Primary NTP Server", default=config.get("ntp_primary", "time.google.com"))
                config["ntp_fallback"] = prompt_input("Fallback NTP Server", default=config.get("ntp_fallback", "pool.ntp.org"))
            elif section == 'a':
                config = collect_variables()
                config["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                print_error("Invalid selection. Please enter 1-5 or A.")
                continue

            display_config_summary(config)

    save_config(config)
    return config


# ─── Inventory & Ansible Execution ──────────────────────────────────────────

def generate_inventory(config):
    """Generate Ansible inventory file.

    Uses IP addresses as inventory hosts for DNS-independent connectivity.
    Sets node_hostname as a host variable for each node so playbooks can
    reference the hostname when needed (e.g. /etc/hosts, MySQL Shell).
    """
    print_step(3, "GENERATING INVENTORY")

    nodes = config["nodes"]

    lines = [
        "[mysql_nodes]",
    ]

    for node in nodes:
        lines.append(f"{node['ip']} node_hostname={node['hostname']}")

    lines.append("")
    lines.append("[mysql_nodes:vars]")
    lines.append(f"ansible_user={config['ssh_user']}")

    if config.get("ssh_key_file"):
        lines.append(f"ansible_ssh_private_key_file={config['ssh_key_file']}")

    if config.get("ssh_password"):
        lines.append(f"ansible_ssh_pass={config['ssh_password']}")

    lines.append("ansible_ssh_common_args='-o StrictHostKeyChecking=no'")
    lines.append("ansible_become=true")
    lines.append("ansible_become_method=sudo")

    if config.get("become_password"):
        lines.append(f"ansible_become_pass={config['become_password']}")
    lines.append("")

    inventory_content = "\n".join(lines)

    with open(INVENTORY_FILE, "w") as f:
        f.write(inventory_content)
    os.chmod(INVENTORY_FILE, 0o600)

    print_info("Generated inventory:")
    for line in lines:
        if "ansible_ssh_pass" in line or "ansible_become_pass" in line:
            key = line.split('=')[0]
            print(f"    {Colors.CYAN}{key}=********{Colors.END}")
        else:
            print(f"    {Colors.CYAN}{line}{Colors.END}")

    print_success(f"Inventory file saved: {INVENTORY_FILE}")


def test_connectivity(config):
    """Test SSH connectivity to all nodes using IP addresses."""
    print_step(4, "SSH CONNECTIVITY TEST")
    print_info("Testing SSH connection to each node...\n")

    nodes = config["nodes"]
    failed_nodes = []
    roles = ["Master", "Slave 1", "Slave 2"]

    for i, node in enumerate(nodes):
        label = f"{node['hostname']} ({node['ip']})"
        sys.stdout.write(f"  {Colors.CYAN}[{roles[i]:>8}] Testing {label}...{Colors.END}")
        sys.stdout.flush()

        result = run_command(
            f"ansible {node['ip']} -i {INVENTORY_FILE} -m ping --one-line"
            f" -e \"ansible_ssh_common_args='-o StrictHostKeyChecking=no -T'\"",
            capture=True, check=False
        )
        if result.returncode == 0 and "SUCCESS" in (result.stdout or ""):
            print(f"\r  {Colors.GREEN}✓ [{roles[i]:>8}] {label:<40} OK{Colors.END}")
        else:
            print(f"\r  {Colors.RED}✗ [{roles[i]:>8}] {label:<40} FAILED{Colors.END}")
            stderr = getattr(result, 'stderr', '') or ''
            stdout = getattr(result, 'stdout', '') or ''
            if stderr:
                print_hint(f"Error: {stderr.strip()[:80]}")
            if stdout:
                print_hint(f"Output: {stdout.strip()[:80]}")
            failed_nodes.append(label)

    print()
    if failed_nodes:
        print_error(f"Unreachable nodes: {', '.join(failed_nodes)}")
        print()
        if not prompt_yes_no("Continue despite failed connections?", default_yes=False):
            print_info("Operation cancelled.")
            sys.exit(1)
    else:
        print_success("All nodes are reachable!")


def build_extra_vars(config):
    """Build the extra-vars JSON for ansible-playbook.

    master_hostname is set to the master's IP address because
    inventory_hostname in Ansible will be the IP (inventory host key).
    """
    nodes = config["nodes"]

    # Build hosts_entries list for /etc/hosts population
    hosts_entries = []
    for node in nodes:
        hosts_entries.append({"ip": node["ip"], "hostname": node["hostname"]})

    extra_vars = {
        "mysql_root_password": config["mysql_root_password"],
        "innodb_admin_user": config["innodb_admin_user"],
        "innodb_admin_password": config["innodb_admin_password"],
        "innodb_cluster_name": config["innodb_cluster_name"],
        "master_hostname": nodes[0]["ip"],       # IP for inventory matching
        "cluster_hosts_entries": hosts_entries,   # for /etc/hosts population
        "router_password": config.get("router_password", ""),
        "ntp_primary": config.get("ntp_primary", "time.google.com"),
        "ntp_fallback": config.get("ntp_fallback", "pool.ntp.org"),
    }
    return json.dumps(extra_vars)


def run_playbook(config):
    """Run the Ansible playbook with real-time output."""
    print_step(6, "RUNNING ANSIBLE PLAYBOOK")

    extra_vars = build_extra_vars(config)

    # Write extra vars to a temp file (more secure than CLI)
    extra_vars_file = PLAYBOOKS_DIR / ".extra_vars.json"
    with open(extra_vars_file, "w") as f:
        f.write(extra_vars)
    os.chmod(extra_vars_file, 0o600)

    cmd = (
        f"ansible-playbook "
        f"-i {INVENTORY_FILE} "
        f"{PLAYBOOK_FILE} "
        f"--extra-vars '@{extra_vars_file}'"
    )

    nodes = config["nodes"]
    print_info(f"Cluster   : {config['innodb_cluster_name']}")
    print_info(f"Master    : {nodes[0]['hostname']} ({nodes[0]['ip']})")
    print_info(f"Playbook  : {PLAYBOOK_FILE.name}")
    print_info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    print_hint("This process may take 10-20 minutes depending on network speed.")
    print_hint("Do not close this terminal until deployment is complete.")
    print(f"\n{Colors.YELLOW}{'═' * 60}{Colors.END}")
    print(f"{Colors.YELLOW}  ANSIBLE OUTPUT{Colors.END}")
    print(f"{Colors.YELLOW}{'═' * 60}{Colors.END}\n")

    # Initialize log file
    with open(LOG_FILE, "w") as f:
        f.write(f"MySQL InnoDB Cluster Setup Log\n")
        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'=' * 60}\n\n")

    start_time = time.time()
    returncode, output_lines = run_command_stream(cmd, log_file=str(LOG_FILE))
    elapsed = time.time() - start_time

    print(f"\n{Colors.YELLOW}{'═' * 60}{Colors.END}")
    print_info(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Duration   : {format_duration(elapsed)}")

    # Append end time to log
    with open(LOG_FILE, "a") as f:
        f.write(f"\n{'=' * 60}\n")
        f.write(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Duration: {elapsed:.1f} seconds\n")
        f.write(f"Exit code: {returncode}\n")

    # Clean up extra vars file
    if extra_vars_file.exists():
        extra_vars_file.unlink()

    return returncode, output_lines, elapsed


# ─── Report Generation ───────────────────────────────────────────────────────

def parse_ansible_recap(output_lines):
    """Parse the PLAY RECAP from ansible output."""
    recap = {}
    in_recap = False
    for line in output_lines:
        if "PLAY RECAP" in line:
            in_recap = True
            continue
        if in_recap and line.strip():
            match = re.match(
                r'(\S+)\s+:\s+ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)',
                line.strip()
            )
            if match:
                recap[match.group(1)] = {
                    "ok": int(match.group(2)),
                    "changed": int(match.group(3)),
                    "unreachable": int(match.group(4)),
                    "failed": int(match.group(5)),
                }
    return recap


def generate_report(config, returncode, output_lines, elapsed):
    """Generate a detailed setup report."""
    print_step(7, "SETUP REPORT")

    recap = parse_ansible_recap(output_lines)
    nodes = config["nodes"]

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    overall_status = "SUCCESS" if returncode == 0 else "FAILED"

    report_lines = []
    report_lines.append("=" * 70)
    report_lines.append("         MySQL InnoDB Cluster Setup Report")
    report_lines.append("=" * 70)
    report_lines.append("")
    report_lines.append(f"  Report Date        : {now}")
    report_lines.append(f"  Total Duration     : {format_duration(elapsed)}")
    report_lines.append(f"  Overall Status     : {overall_status}")
    report_lines.append(f"  Ansible Exit Code  : {returncode}")
    report_lines.append("")
    report_lines.append("-" * 70)
    report_lines.append("  CLUSTER DETAILS")
    report_lines.append("-" * 70)
    report_lines.append(f"  Cluster Name       : {config['innodb_cluster_name']}")
    report_lines.append(f"  Cluster Admin      : {config['innodb_admin_user']}")
    report_lines.append(f"  Router User        : routeruser")
    report_lines.append(f"  Master Node        : {nodes[0]['hostname']} ({nodes[0]['ip']})")
    report_lines.append(f"  Slave Node 1       : {nodes[1]['hostname']} ({nodes[1]['ip']})")
    report_lines.append(f"  Slave Node 2       : {nodes[2]['hostname']} ({nodes[2]['ip']})")
    report_lines.append(f"  SSH User           : {config['ssh_user']}")
    report_lines.append("")
    report_lines.append("-" * 70)
    report_lines.append("  NODE STATUS (Ansible Recap)")
    report_lines.append("-" * 70)

    if recap:
        report_lines.append(f"  {'Node':<35} {'OK':>5} {'Changed':>9} {'Unreachable':>13} {'Failed':>8}")
        report_lines.append(f"  {'─' * 35} {'─' * 5} {'─' * 9} {'─' * 13} {'─' * 8}")
        for node in nodes:
            ip = node["ip"]
            label = f"{node['hostname']} ({ip})"
            if ip in recap:
                r = recap[ip]
                status_icon = "✓" if r["failed"] == 0 and r["unreachable"] == 0 else "✗"
                report_lines.append(
                    f"  {status_icon} {label:<33} {r['ok']:>5} {r['changed']:>9} "
                    f"{r['unreachable']:>13} {r['failed']:>8}"
                )
            else:
                report_lines.append(f"  ? {label:<33} {'N/A':>5} {'N/A':>9} {'N/A':>13} {'N/A':>8}")
    else:
        report_lines.append("  Ansible recap information not available.")

    report_lines.append("")
    report_lines.append("-" * 70)
    report_lines.append("  APPLIED ROLES")
    report_lines.append("-" * 70)
    report_lines.append("  1. pre_tasks                          /etc/hosts + hostname")
    report_lines.append("  2. 01-os-preconfigure                 SSH banner + kernel parameters")
    report_lines.append("  3. 02-mysql-install                   Firewall, Locale, NTP, MySQL install")
    report_lines.append("  4. 03-mysql-innodb-cluster            InnoDB Cluster pre-configuration")
    report_lines.append("  5. 04-mysql-create-innodb-cluster     Cluster creation + Router account")

    report_lines.append("")
    report_lines.append("-" * 70)
    report_lines.append("  NEXT STEPS")
    report_lines.append("-" * 70)

    if returncode == 0:
        report_lines.append("  ✓ Cluster setup completed successfully!")
        report_lines.append("")
        report_lines.append("  Quick cluster status check:")
        report_lines.append(f"    mysqlsh {config['innodb_admin_user']}@{nodes[0]['ip']} -- cluster status")
        report_lines.append("")
        report_lines.append("  Interactive cluster management:")
        report_lines.append(f"    mysqlsh {config['innodb_admin_user']}@{nodes[0]['ip']}")
        report_lines.append("    var cluster = dba.getCluster();")
        report_lines.append("    cluster.status();")
        report_lines.append("")
        report_lines.append("  MySQL Router bootstrap:")
        report_lines.append(f"    mysqlrouter --bootstrap routeruser@{nodes[0]['ip']}:3306 --user=mysqlrouter")
    else:
        report_lines.append("  ✗ Cluster setup encountered errors!")
        report_lines.append(f"    Review the full log: {LOG_FILE}")
        report_lines.append("")
        report_lines.append("  Troubleshooting tips:")
        report_lines.append("    - SSH error       : Verify SSH key/password and user permissions")
        report_lines.append("    - DNS error       : Check /etc/hosts on all nodes")
        report_lines.append("    - Install error   : Check internet connectivity and package sources")
        report_lines.append("    - Firewall        : Ensure ports 3306, 33060, 33061 are open")
        report_lines.append("    - Cluster error   : Check MySQL Shell output above for details")

    report_lines.append("")
    report_lines.append("-" * 70)
    report_lines.append("  FILE LOCATIONS")
    report_lines.append("-" * 70)
    report_lines.append(f"  Configuration  : {CONFIG_FILE}")
    report_lines.append(f"  Inventory      : {INVENTORY_FILE}")
    report_lines.append(f"  Log File       : {LOG_FILE}")
    report_lines.append(f"  This Report    : {REPORT_FILE}")

    report_lines.append("")
    report_lines.append("=" * 70)

    report_content = "\n".join(report_lines)

    # Save report to file
    with open(REPORT_FILE, "w") as f:
        f.write(report_content)

    # Print report to screen
    print(f"\n{Colors.CYAN}{report_content}{Colors.END}")

    print_success(f"Report saved: {REPORT_FILE}")

    return overall_status


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print_banner()

    # Check root
    check_root()

    # Step 1: Setup environment
    setup_environment()

    # Step 2: Get configuration (load or collect)
    config = get_configuration()

    # Step 3: Generate inventory
    generate_inventory(config)

    # Step 4: Test connectivity
    test_connectivity(config)

    # Step 5: Deployment confirmation
    print_step(5, "DEPLOYMENT CONFIRMATION")

    nodes = config["nodes"]
    roles = ["Master", "Slave 1", "Slave 2"]

    print_info("The following deployment will be executed:\n")
    print(f"    {Colors.BOLD}Cluster :{Colors.END} {config['innodb_cluster_name']}")
    print(f"    {Colors.BOLD}Admin   :{Colors.END} {config['innodb_admin_user']}")
    print()
    for i, node in enumerate(nodes):
        icon = "★" if i == 0 else "●"
        print(f"    {icon} {roles[i]:>8} : {node['hostname']} ({node['ip']})")
    print()
    print_hint("This will install MySQL, configure InnoDB Cluster,")
    print_hint("create the router user, and verify cluster status.")
    print()

    if not prompt_yes_no("Proceed with deployment?", default_yes=True):
        print_info("Deployment cancelled.")
        sys.exit(0)

    # Step 6: Run playbook
    returncode, output_lines, elapsed = run_playbook(config)

    # Step 7: Generate report
    status = generate_report(config, returncode, output_lines, elapsed)

    # Final message
    print()
    if returncode == 0:
        print(f"  {Colors.GREEN}{Colors.BOLD}{'═' * 56}{Colors.END}")
        print(f"  {Colors.GREEN}{Colors.BOLD}  MySQL InnoDB Cluster deployed successfully!{Colors.END}")
        print(f"  {Colors.GREEN}{Colors.BOLD}{'═' * 56}{Colors.END}")
    else:
        print(f"  {Colors.RED}{Colors.BOLD}{'═' * 56}{Colors.END}")
        print(f"  {Colors.RED}{Colors.BOLD}  MySQL InnoDB Cluster deployment FAILED!{Colors.END}")
        print(f"  {Colors.RED}{Colors.BOLD}{'═' * 56}{Colors.END}")
        print_info(f"Review the log: {LOG_FILE}")

    print()
    sys.exit(returncode)


if __name__ == "__main__":
    main()
