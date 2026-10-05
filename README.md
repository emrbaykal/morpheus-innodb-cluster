# MySQL InnoDB Cluster — Morpheus Setup

Builds a 3-node MySQL InnoDB Cluster on Ubuntu or RHEL with one interactive Python script and four Ansible roles.

## Supported systems

| OS | MySQL Server source | MySQL Shell source |
|----|---------------------|--------------------|
| RHEL 9 / 10 | Red Hat AppStream (supported by Red Hat) | repo.mysql.com tools repository |
| Ubuntu 24.04 / 26.04 | repo.mysql.com (APT pool) | repo.mysql.com (APT pool) |

## Requirements

On all three nodes:

- SSH access with a key or a password, and `sudo` (or `dzdo`)
- HTTPS access to `repo.mysql.com`
- RHEL only: `rhel-<9|10>-for-x86_64-baseos-rpms` and `rhel-<9|10>-for-x86_64-appstream-rpms` enabled

On the master node the script installs Ansible (`ansible` on Ubuntu, `ansible-core` on RHEL) and `sshpass` if they are missing. No Ansible Galaxy collections are needed.

## Quick start

Run on the node that will be the cluster primary:

```bash
git clone https://github.com/emrbaykal/morpheus-innodb-cluster.git
cd morpheus-innodb-cluster
sudo python3 innodb_cluster_setup.py
```

| Step | What happens |
|------|--------------|
| 1. Environment | Installs Ansible and sshpass when missing |
| 2. Cluster configuration | Asks for nodes, SSH, MySQL passwords, cluster name, MySQL Router user and NTP; saves `cluster_config.json` |
| 3. Inventory, SSH and internet access | Writes `playbooks/inventory.ini`, pings every node, then checks that every node reaches `repo.mysql.com` over HTTPS and, on RHEL, its dnf repositories |
| 4. MySQL version | Pick 8.0 or 8.4, then pick the exact version from the list the repository offers today |
| 5. Deployment | Runs `playbooks/mysql-innodb.yml` and logs to `cluster_setup.log` |
| 6. Report | Writes `cluster_setup_report.txt` |

On a re-run the saved answers are offered again. Choosing "n" walks through the questions with the old values as defaults; Enter keeps a value, and a password prompt left empty keeps the saved password.

## How the version list is built

**RHEL.** The list is every `mysql-server` build in AppStream for the chosen series (`dnf repoquery --disable-modular-filtering`). During the install the playbook enables the `mysql:<series>` module stream when the series is a stream (8.4 on RHEL 9), otherwise it resets the module so the plain packages are used. MySQL Shell is the newest build of the same series from Oracle's tools repository, because AppStream does not ship it and Oracle's Shell builds do not follow every AppStream release.

**Ubuntu.** Oracle's APT index only lists the newest build of a series, but older builds stay in the repository pool. The script reads the newest version from the index and checks the pool for every patch release below it. The chosen version and the newest MySQL Shell of the series are downloaded from the pool and installed as local packages.

All MySQL packages are then held (`dnf versionlock` / `apt-mark hold`), so an OS update does not move the version.

## What the playbook does

**Pre-tasks (all nodes)** — removes the node's own name from `127.x` lines in `/etc/hosts` (InnoDB Cluster refuses a hostname that resolves to loopback), adds all three nodes to `/etc/hosts`, sets the hostname.

**01-os-preconfigure (all nodes)**

- SSH login banner from `files/issue.net`
- RHEL: SELinux permissive, firewalld stopped. Ubuntu: ufw, AppArmor and unattended-upgrades stopped
- `en_US.UTF-8` locale; NTP through chrony (RHEL) or systemd-timesyncd (Ubuntu)
- `/etc/security/limits.d/99-mysql.conf`, kernel parameters from `vars/main.yml` in `/etc/sysctl.d/99-01-os-preconfigure.conf`
- Transparent Huge Pages off now and at boot

**02-mysql-install (all nodes)** — installs the chosen version as described above, adds a systemd drop-in that starts `mysqld` under `numactl --interleave=all` with raised limits, starts MySQL and sets the root password.

**03-mysql-innodb-cluster (all nodes)** — writes `innodb-mysqld.cnf`:

```ini
[mysqld]
bind-address = 0.0.0.0
max_connections = 451
innodb_buffer_pool_size = <80% of RAM>G
innodb_use_fdatasync = ON
innodb_numa_interleave = ON
sql_generate_invisible_primary_key = ON
binlog_expire_logs_seconds = 604800
binlog_expire_logs_auto_purge = ON
gtid_mode = ON
enforce_gtid_consistency = ON
server_id = <last octet of the node IP>

[mysqldump]
set-gtid-purged = OFF
```

It then restarts MySQL and creates the cluster admin user (`ALL PRIVILEGES ... WITH GRANT OPTION`) with binary logging off for that session, so the nodes carry no errant GTIDs.

**04-mysql-create-innodb-cluster (master only)** — one MySQL Shell script that runs `dba.configureInstance` on every node, creates the cluster (or reuses it), adds the two secondaries with clone recovery, creates or updates the MySQL Router account (default name `routeruser`, asked in step 2) and prints `cluster.status()`. Re-running it keeps the existing cluster and members.

## After the deployment

```bash
mysqlsh clusterAdmin@<master-ip> -- cluster status
mysqlrouter --bootstrap <router-user>@<master-ip>:3306 --user=mysqlrouter
```

Ports between the nodes: 3306 (classic), 33060 (X protocol), 33061 (Group Replication).

## Re-running parts of the playbook

Each role has a tag: `os`, `install`, `configure`, `cluster`.

```bash
cd playbooks
ansible-playbook -i inventory.ini mysql-innodb.yml --tags cluster --extra-vars @extra_vars.json
```

`extra_vars.json` needs the keys the script writes in step 5 (see `run_playbook()` in the script).

## Files created at runtime

| File | Purpose |
|------|---------|
| `cluster_config.json` (0600) | Saved answers, including passwords |
| `playbooks/inventory.ini` (0600) | Ansible inventory, may contain the SSH/sudo password |
| `cluster_setup.log` | Full Ansible output |
| `cluster_setup_report.txt` | Summary |

## Notes

- `server_id` is the last octet of the node IP. Nodes in different subnets (for example a second data center in a ClusterSet) can end up with the same value; set it by hand in that case.
- The cluster admin user has full privileges from any host (`'%'`). Restrict it if your network requires it.

## License

MIT License

Copyright (c) 2026 Emre Baykal

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
