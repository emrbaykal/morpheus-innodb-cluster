# MySQL InnoDB Cluster Setup

Automated deployment of a 3-node MySQL InnoDB Cluster on Ubuntu using Ansible, orchestrated by a single Python script.

## Directory Structure

```
ansible/
├── innodb_cluster_setup.py            # Main orchestrator script
├── README.md
├── playbooks/
│   ├── ubuntu-mysql-innodb.yml        # Main Ansible playbook
│   ├── 01-ubuntu-config-issue/        # Role: SSH banner configuration
│   ├── 02-ubuntu-mysql-install/       # Role: OS hardening + MySQL installation
│   ├── 03-ubuntu-mysql-innodb-cluster/# Role: InnoDB Cluster pre-configuration
│   └── 04-ubuntu-mysql-create-innodb-cluster/  # Role: Cluster creation (master only)
│
│   # Generated at runtime:
│   └── inventory.ini
│
# Generated at runtime:
├── cluster_config.json                # Saved user configuration (reused on re-runs)
├── cluster_setup.log                  # Full Ansible output log
└── cluster_setup_report.txt           # Post-deployment summary report
```

## Prerequisites

- **OS:** Ubuntu 22.04+ on all 3 target nodes
- **Access:** SSH connectivity from the master node to all nodes (key-based or password)
- **Privileges:** `sudo` access on all target nodes
- **Network:** Internet access on targets for MySQL APT repository download

The script automatically installs the following on the master node if not present:
- `ansible`
- `sshpass`
- `python3-pip`
- `community.mysql` Ansible collection

## Quick Start

```bash
sudo python3 innodb_cluster_setup.py
```

The script guides you through an interactive wizard with 7 steps:

| Step | Description |
|------|-------------|
| 1/7  | Environment setup — installs prerequisites |
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
- **Fallback NTP Server** — default: `ntp.ubuntu.com`

All values are saved to `cluster_config.json` (mode `0600`). On subsequent runs, the script offers to reuse the saved configuration.

## What Gets Deployed

### Pre-tasks (all nodes)
- Populate `/etc/hosts` with all cluster node entries
- Set hostname on each node

### Role 01: SSH Banner Configuration
- Configures SSH login banner (`/etc/issue`, `/etc/issue.net`)

### Role 02: MySQL Installation
- Stop and disable AppArmor
- Disable UFW firewall
- Set locale to `en_US.UTF-8`
- Configure NTP time synchronization (`systemd-timesyncd`)
- Wait for dpkg/apt locks to be released
- Stop `unattended-upgrades` service
- Download and install `mysql-apt-config` from `repo.mysql.com`
- Install MySQL Server, Client, Shell, and dependencies
- Hold MySQL server package version (`apt-mark hold`)
- Enable `mysql_native_password` plugin
- Set MySQL root password (idempotent — works on first run and re-runs)
- Verify installed packages, held packages, and service status

### Role 03: InnoDB Cluster Pre-configuration
- Create cluster admin user with full privileges
- Remove anonymous MySQL users and test database
- Set `sql_generate_invisible_primary_key = 1`
- Calculate `innodb_buffer_pool_size` as 80% of total RAM (dynamic)
- Write InnoDB-optimized `mysqld.cnf` with tuned parameters:
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
| `dpkg lock` error | Script now waits for locks automatically; also disables `unattended-upgrades` |
| `decimal.Decimal` error in verification | Fixed — verification uses `shell` + `mysql` instead of `mysql_query` module |
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
