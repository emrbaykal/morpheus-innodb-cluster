# MySQL InnoDB Cluster Setup

Automated deployment of a 3-node MySQL InnoDB Cluster on Ubuntu and RedHat-based systems using Ansible, orchestrated by a single Python script.

## Directory Structure

```
ansible/
├── innodb_cluster_setup.py            # Main orchestrator script
├── README.md
├── playbooks/
│   ├── mysql-innodb.yml               # Main Ansible playbook
│   ├── 01-config-issue/               # Role: SSH banner configuration
│   ├── 02-mysql-install/              # Role: OS hardening + MySQL installation
│   │   └── tasks/
│   │       ├── main.yml               # Dispatcher (includes OS-specific tasks)
│   │       ├── debian.yml             # Debian/Ubuntu specific tasks
│   │       ├── redhat.yml             # RedHat/CentOS/Rocky/Alma specific tasks
│   │       └── common.yml             # Shared tasks (service start, root password)
│   ├── 03-mysql-innodb-cluster/       # Role: InnoDB Cluster pre-configuration
│   └── 04-mysql-create-innodb-cluster/# Role: Cluster creation (master only)
│
│   # Generated at runtime:
│   └── inventory.ini
│
# Generated at runtime:
├── cluster_config.json                # Saved user configuration (reused on re-runs)
├── cluster_setup.log                  # Full Ansible output log
└── cluster_setup_report.txt           # Post-deployment summary report
```

## Supported Operating Systems

| OS Family | Tested Distributions |
|-----------|---------------------|
| Debian    | Ubuntu 22.04+, Debian 12+ |
| RedHat    | RHEL 8/9, CentOS Stream 8/9, Rocky Linux 8/9, AlmaLinux 8/9 |

The playbooks automatically detect the OS family (`ansible_os_family`) and run the appropriate tasks for each distribution.

## Prerequisites

- **OS:** Ubuntu 22.04+ or RedHat/CentOS 8+ on all 3 target nodes
- **Access:** SSH connectivity from the master node to all nodes (key-based or password)
- **Privileges:** `sudo` access on all target nodes
- **Network:** Internet access on targets for MySQL repository download

The script automatically detects the local OS and installs the following on the master node if not present:

**Debian/Ubuntu:**
- `ansible`, `sshpass`, `python3-pip`

**RedHat/CentOS:**
- `epel-release`, `ansible`, `sshpass`, `python3-pip`

Both:
- `community.mysql` Ansible collection

## Quick Start

```bash
sudo python3 innodb_cluster_setup.py
```

The script guides you through an interactive wizard with 7 steps:

| Step | Description |
|------|-------------|
| 1/7  | Environment setup — detects OS, installs prerequisites |
| 2/7  | Configuration — collects cluster variables in 5 sections |
| 3/7  | Inventory generation — creates Ansible inventory from inputs |
| 4/7  | SSH connectivity test — verifies all nodes are reachable |
| 5/7  | Deployment confirmation — summary review before execution |
| 6/7  | Ansible playbook execution — streams output in real-time |
| 7/7  | Setup report — generates and displays a detailed report |

## Configuration Variables

The wizard collects the following information, grouped into sections:

### Section 1: Cluster Nodes
For each of the 3 nodes (1 master + 2 slaves):
- **Hostname** — e.g. `mysql-innodb-1`
- **IP Address** — e.g. `192.168.42.100`

> Connectivity uses IP addresses directly. DNS is not required — `/etc/hosts` is populated automatically.

### Section 2: SSH Connection
- **SSH User** — default: `ansible`
- **SSH Key File** — default: `~/.ssh/id_rsa` (falls back to password authentication)
- **Sudo Password** — optional, for `become: true` escalation

### Section 3: MySQL Credentials
- **MySQL Root Password**
- **Cluster Admin Username** — default: `clusterAdmin`
- **Cluster Admin Password**

### Section 4: Cluster Settings
- **Cluster Name** — default: `mysql-cluster`
- **Router User Password** — for the `routeruser` account (used by MySQL Router)

### Section 5: System Settings
- **Primary NTP Server** — default: `time.google.com`
- **Fallback NTP Server** — default: `pool.ntp.org`

All values are saved to `cluster_config.json` (mode `0600`). On subsequent runs, the script offers to reuse the saved configuration.

## What Gets Deployed

### Pre-tasks (all nodes)
- Populate `/etc/hosts` with all cluster node entries
- Set hostname on each node

### Role 01: SSH Banner Configuration
- Configures SSH login banner (`/etc/issue`, `/etc/issue.net`)
- OS-aware SSH service restart (`ssh` on Debian, `sshd` on RedHat)

### Role 02: MySQL Installation

OS-specific tasks are automatically selected based on `ansible_os_family`:

| Task | Debian/Ubuntu | RedHat/CentOS |
|------|--------------|---------------|
| Security framework | Stop & disable AppArmor | Set SELinux to permissive |
| Firewall | Disable UFW | Stop & disable firewalld |
| Locale | `locale_gen` module | `localedef` command |
| NTP | `systemd-timesyncd` | `chrony` |
| Package cleanup | Stop `unattended-upgrades`, clear apt/dpkg locks | — |
| MySQL repo | `mysql-apt-config` deb from `repo.mysql.com` | MySQL YUM repo RPM (EL8/EL9 auto-detected) |
| Package install | `apt`: mysql-server, mysql-client, mysql-shell, python3-mysqldb, libmysqlclient-dev | `dnf`/`yum`: mysql-community-server, mysql-community-client, mysql-shell, python3-PyMySQL, mysql-community-devel |
| Version lock | `dpkg_selections` hold | `yum versionlock` |
| Native password config | `/etc/mysql/conf.d/` | `/etc/my.cnf.d/` |

Common tasks (both OS families):
- Start and enable MySQL service (`mysql` on Debian, `mysqld` on RedHat)
- Set MySQL root password (idempotent — works on first run and re-runs)
- Verify service status

### Role 03: InnoDB Cluster Pre-configuration
- Create cluster admin user with full privileges
- Remove anonymous MySQL users and test database
- Set `sql_generate_invisible_primary_key = 1`
- Calculate `innodb_buffer_pool_size` as 80% of total RAM (dynamic)
- Write InnoDB-optimized config file (OS-aware path):
  - Debian: `/etc/mysql/mysql.conf.d/innodb-mysqld.cnf`
  - RedHat: `/etc/my.cnf.d/innodb-mysqld.cnf`
- Tuned parameters:
  - `bind-address = 0.0.0.0`
  - `max_connections = 451`
  - `innodb_use_fdatasync = ON`
  - `binlog_expire_logs_seconds = 604800` (7 days)
  - `gtid_mode = ON`, `enforce_gtid_consistency = ON`
  - `server_id` based on last octet of node IP
- Restart MySQL and verify applied parameters

### Role 04: Cluster Creation (master only)
- Wait for MySQL port 3306 on all nodes
- Configure all instances via MySQL Shell (`dba.configureInstance`)
- Create InnoDB Cluster on primary node (`dba.createCluster`)
- Add secondary nodes with clone recovery (`cluster.addInstance`)
- Verify cluster status (`cluster.status()`)
- Create MySQL Router account (`cluster.setupRouterAccount('routeruser')`)
- Clean up temporary credential and script files

## Re-running

The script is designed to be idempotent:
- Saved configuration is reused (no re-prompting)
- MySQL root password task handles both empty and existing passwords
- Router account creation uses `{update: true}` if user already exists
- Package installations check current state before acting

```bash
# Re-run with saved config
sudo python3 innodb_cluster_setup.py

# Force new configuration (delete saved config first)
sudo rm cluster_config.json
sudo python3 innodb_cluster_setup.py
```

## Post-Deployment

After successful deployment, useful commands:

```bash
# Quick cluster status check
mysqlsh clusterAdmin@<master-ip> -- cluster status

# Interactive cluster management
mysqlsh clusterAdmin@<master-ip>
var cluster = dba.getCluster();
cluster.status();

# Bootstrap MySQL Router
mysqlrouter --bootstrap routeruser@<master-ip>:3306 --user=mysqlrouter
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Missing sudo password` | Re-run and answer "yes" to sudo password prompt |
| `dpkg lock` error (Debian) | Script now waits for locks automatically; also disables `unattended-upgrades` |
| Master node `failed=1` on re-run | Root password task is now idempotent (tries empty, then existing password) |
| Role 04 skipped on all nodes | Ensure `master_hostname` matches the master node's IP in inventory |
| Too verbose output | Ansible runs without `-v` flag by default |

## Network Ports

Ensure the following ports are open between all cluster nodes:

| Port  | Service |
|-------|---------|
| 3306  | MySQL Classic Protocol |
| 33060 | MySQL X Protocol |
| 33061 | Group Replication |

## Files Generated at Runtime

| File | Location | Description |
|------|----------|-------------|
| `cluster_config.json` | Project root | Saved configuration (mode 0600) |
| `inventory.ini` | `playbooks/` | Ansible inventory |
| `cluster_setup.log` | Project root | Full Ansible output |
| `cluster_setup_report.txt` | Project root | Deployment summary report |
