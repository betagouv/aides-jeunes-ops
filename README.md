# Aides-Jeunes Ops

Set up the [Mes Aides](https://mes-aides.1jeune1solution.beta.gouv.fr/) stack.

## Before starting

The ansible scripts in this repository have been tested only Debian 12 x86_64 server. However, older or newer versions of Debian may be compatible.

## Deployment

### Prerequisites

You will need at most the following ressources:
- an SSH connection as a priviledged user to the remote server
- Ansible >=12.2.0 with Python >3.9 installed on your local machine. See [the documentation](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-ansible-on-specific-operating-systems) for your operating system.

Then, duplicate the file `vps.yaml` in the `inventories` folder and modifiy it to match your needs.

The options are as follow :
```yaml
virtualmachines:
  hosts:
    vps:
      ansible_host: vps-45bb7a36.vps.ovh.net                             # The server adress
      ansible_port: 22                                                   # The ssh port used to connect to the server
      ansible_ssh_user: debian                                           # The user name of the priviledged account on the server
      ansible_ssh_private_key_file: ~/.ssh/id_rsa                        # The path to the SSH key used to connect to the server
      ansible_host_ip: 51.38.232.135                                     # The ip of the server, used to generate DNS records
      fullname: solstice.aides-jeunes.leonides.org                       #
      dns_root: leonides.org                                             # The root of domain name use by your server
      email: random-email@leonides.org                                   # The email used to register Certbot
      github_users:                                                      # The github users that will be able to connect to the server
        - github_username_example
      monitor:                                                           # If set, a monitoring service will be deployed on specified port
        port: 8887
      applications:                                                      # List all applications that will be deployed
        - name: aides_jeunes
          repository: https://github.com/betagouv/aides-jeunes.git
          branch: main
          default_site: true
          https: true
          domain: aides-jeunes.leonides.org
          node_server_port: 8001
          node_instance_number: 4
          openfisca_server_port: 2001
          openfisca_worker_number: 4
```

### Basic security settings (non mandatory)

You can set some basic security settings on your server by running `ansible-playbook -i ./inventories/vps.yaml initialize.yaml`.

This will disable SSH connection to the server using password. This step will not run if the server user file `~/.ssh/authorized_keys` is either empty or missing. The following properties will be modified in `/etc/ssh/sshd_config` :
- set `PasswordAuthentication no`
- set `ChallengeResponseAuthentication no`

It is advised to run this command on a newly installed server, while keeping an active ssh connection in parallel and only if you understand the implication of those parameters. Your hosting service should provide you with an emergency access if you get locked out of the server.

### Listing required DNS record

In order for the server to be successfully deployed, some sub domain name must be specified in the DNS record. In order to know which values are required, simply run `ansible-playbook -i ./inventories/vps.yaml dns-record.yaml`. You will get an output such as this one:
```
monitor.solstice.aides-jeunes                      3600 IN A 5.135.137.147
solstice.aides-jeunes                              3600 IN A 5.135.137.147
www.solstice.aides-jeunes                          3600 IN A 5.135.137.147
openfisca.solstice.aides-jeunes                    3600 IN A 5.135.137.147
aides-jeunes                                       3600 IN A 5.135.137.147
www.aides-jeunes                                   3600 IN A 5.135.137.147
openfisca.aides-jeunes                             3600 IN A 5.135.137.147
```

Then you will have to add all those entries to the associated domain name DNS record.

### Enabling continuous-deployment

In order to enable continuous deployment of this ops repository on your server you need to run the following command once:
```shell
ansible-playbook -i ./inventories/vps.yaml synchronize.yaml
```

A copy of this repository will be created in the folder `/opt/mes-aides` of the server. This repository will be automatically updated and new modifications applied every time an ssh connection is made with the private key associated with the `update_key` defined in the inventory.

Note:
Private and public keys should be generated manually (`ssh-keygen -t ed25519 -C aides-jeunes@beta.gouv.fr -f key`):
- Private should be keys added to Github secrets variable (used [here](https://github.com/betagouv/aides-jeunes-ops/blob/9f5bd32001b1b889f580e7e14213397b7af2227b/.github/workflows/pipeline.yaml#L71) for instance)
- Public keys added to `ops.update_key` variable in the inventory

Warning: Launching the `synchronize.yaml` playbook alone will remove continuous deploiement of server stack. You will need to run the `bootstrap.yaml` playbook again to re-enable it.

### Bootstrap server stack

Run the command `ansible-playbook -i ./inventories/vps.yaml bootstrap.yaml` in order to bootstrap the server basic configuration.

Once done, every applications should be up and running on the server.

Note that you only need to run this command once, but you can re-run it if you modify either Nginx, Python, Mongo configuration or if the bootstrap process failed at some point. All unaltered steps that ran successfully will be automatically skipped by Ansible.

#### First deployment

In order to setup continuous deployment, you will need to:
- Run manually the `synchronize.yaml` playbook
- Run manually the `bootstrap.yaml` playbook
- Connect to the server using one of the private keys associated to your Github account
- switch user to `main`
- run `cd ~/` and cd the application folder you want to deploy
- get the private key (see `ansible_ssh_private_key_file` in inventory)
- set it up in your Github repository as a secret (see [here](https://github.com/betagouv/aides-jeunes/blob/400ab5f90219141b438388d58cd4f27f8fb0ebd6/.github/workflows/cd.yml#L48))

### Automatic MongoDB backup

The `bootstrap` role installs a scheduled backup of the production database. It is applied
by `bootstrap.yaml` like the rest of the server configuration — there is nothing to run by
hand.

Every day at 03:30 a systemd timer runs `mongodb-backup.service`, which dumps each database
listed in `mongodb_backup_databases` into a single compressed archive under
`/var/backups/mongodb`, verifies it, then deletes archives older than the retention window.

| Variable | Default | Purpose |
| --- | --- | --- |
| `mongodb_backup_databases` | `[db_aides_jeunes]` | Databases to dump, one archive each |
| `mongodb_backup_directory` | `/var/backups/mongodb` | Where archives are kept (`0700`, `root:root`) |
| `mongodb_backup_host` / `mongodb_backup_port` | `127.0.0.1` / `27017` | Where mongod listens |
| `mongodb_backup_on_calendar` | `*-*-* 03:30:00` | `OnCalendar=` expression for the timer |
| `mongodb_backup_retention_days` | `14` | Archives older than this are deleted |
| `mongodb_backup_min_archive_bytes` | `4096` | Sanity floor below which an archive is rejected |

#### Checking that it works

```bash
systemctl list-timers mongodb-backup.timer   # when it last ran and when it runs next
systemctl status mongodb-backup.service      # outcome of the last run
journalctl -u mongodb-backup.service         # full history
ls -l /var/backups/mongodb                   # the archives themselves (root only)
```

A run that fails leaves the service in `failed` state, so `systemctl status` and
`systemctl list-units --failed` both report it. The script never swallows an error: a dump
that fails, an archive that is too small, corrupt or truncated all abort the run with a
non-zero exit code, and the bad archive is deleted rather than kept. Rotation only happens
after a successful dump, so a run of failures can never eat the archives that are still good.

You can trigger a run at any time with `systemctl start mongodb-backup.service`.

#### Restoring

Archives are plain `mongodump --archive --gzip` files. To inspect one without touching the
live database, restore it under a different name:

```bash
mongorestore --gzip \
  --archive=/var/backups/mongodb/db_aides_jeunes-20260807T033000.archive.gz \
  --nsFrom='db_aides_jeunes.*' --nsTo='db_aides_jeunes_restore.*'
```

To restore the database in place, after a bad migration or an accidental deletion —
this **replaces** the collections present in the archive:

```bash
systemctl stop mongodb-backup.timer   # avoid backing up the broken state mid-restore
pm2 stop all                          # as user `main`, so nothing writes during the restore
mongorestore --gzip --drop \
  --archive=/var/backups/mongodb/db_aides_jeunes-20260807T033000.archive.gz
pm2 start all
systemctl start mongodb-backup.timer
```

`--drop` drops each collection just before restoring it. Collections created *after* the
backup are not in the archive and are therefore left untouched — drop them by hand if the
point is to get back to the exact state of the archive.

#### Limits you need to know about

**A backup on the same machine is not a backup.** These archives sit on the same disk as
the database they protect. They cover a logical accident — a failed migration, a mistaken
deletion, a bad `tools:cleaner` run — and nothing else. If the machine is lost, wiped, or
its disk fails, the backups go with it, and so does the service. Making this a real backup
means a copy on another machine, ideally another provider: a nightly `rclone` or `restic`
push to object storage (OVH Object Storage, S3), encrypted client-side with a key that is
*not* stored on the server, with its own retention and a restore drill. That is a hosting
decision with a cost attached, so it is deliberately not implemented here — but until it
exists, the single-machine failure mode is uncovered.

**These archives extend how long personal data is kept.** The database holds personal and
financial data, and a daily cron anonymises simulations and follow-ups at 05:00. The backups
are *not* anonymised: an archive taken at 03:30 keeps a copy of everything the 05:00 job
erases, for the whole retention window. A 14-day retention therefore means personal data
survives its deletion by up to 14 days. This is a deliberate trade-off between recovery
ability and data minimisation — it is the team's and the DPO's call, not a technical
default, and `mongodb_backup_retention_days` is the knob. Whatever value is chosen should be
reflected in the record of processing activities.

### Alerting on failed systemd units

A backup that fails silently for a month is the failure mode that actually hurts, and the
status page itself sat in `failed` for a year without anyone noticing. The `bootstrap` role
therefore makes a broken unit announce itself, through the Sentry project the cron jobs
already report to. Nothing to run by hand — `bootstrap.yaml` installs it.

Two triggers, because they catch different things:

| | Fires on | Catches | Misses |
| --- | --- | --- | --- |
| `OnFailure=` drop-in on each watched unit | the *transition* into `failed` | a nightly backup that just died, within seconds | a unit already broken before this was deployed; a unit that is merely stopped |
| `alert-systemd-sweep.timer`, daily at 08:15 | the *state* of the machine | everything in `systemctl --failed`, watched units that are not running, a timer that disappeared, and the alerting units' own failures | nothing until the next morning |

Both run the same script, `/usr/local/sbin/alert_systemd_failure.sh`, which sends one Sentry
event per unit with a fingerprint of `systemd-unit-failure` + the unit name — so a unit gets
one Sentry issue, not one per day, and closing it means the failure is handled.

The sweep reads `systemctl --failed` in full, not just the list below: a failed unit nobody
thought to declare — an `*_openfisca` service, something added later — is still reported. The
list exists for the other half of the job, checking that a unit which should be running
actually is, which no global query can guess. Declared units are examined **first**, before
the global list, and the event cap only bites on what is left: `systemctl` answers in
alphabetical order, so a burst of unrelated failures would otherwise eat the whole budget
before ever reaching `nginx`.

Only **declared** units ship their last 50 journal lines as breadcrumbs, so the alert says
*why* without needing an SSH session. Anything else is reported without its journal: the
sweep also covers application and `*_openfisca` services, whose logs can carry personal and
financial data that has no business being exported to Sentry. **Adding a unit to
`alerting_watched_units` is therefore also a decision to send its journal to Sentry** — worth
a thought for anything that handles user data.

| Variable | Default | Purpose |
| --- | --- | --- |
| `alerting_watched_units` | backup service + timer, `monitor_service`, `mongod`, `nginx`, the sweep itself | Units getting an `OnFailure=` drop-in; those with `expect_active: true` must also be running |
| `alerting_sweep_on_calendar` | `*-*-* 08:15:00` | `OnCalendar=` of the daily sweep |
| `alerting_sweep_max_events` | `10` | Cap on events per sweep, so a machine on fire does not open thirty issues |

Adding a unit is two lines in `alerting_watched_units`. The page on `monitor.<fullname>` also
publishes the state of these units next to its URL probes.

#### Where the DSN comes from

The alerting units run as `root`, and a root unit has no business reading an application
`.env` — that file belongs to the deployment user, and it carries every other application
secret. The units are hardened with `ProtectHome=true` and could not read it anyway.

So ansible, during `bootstrap.yaml`, extracts the single `SENTRY_CRON_DSN` line from the
default application's `.env` and writes it to `/etc/aides-jeunes/alerting.env`, `0600
root:root`, containing that one variable and nothing else. **No DSN is stored in this
repository or in any inventory**, and the value never transits through an ansible variable:
`/usr/local/sbin/sync_alerting_dsn.sh` does the extraction on the machine and only reports
whether it changed.

There is no other channel available: deployment is an SSH forced command that runs
`ansible-playbook --connection=local` on the server itself (`scripts/update_ops.sh`), with no
way to pass `--extra-vars`, so a GitHub secret or an ansible-vault variable could not reach
the play without a vault password file on the server — that is, the same server-side secret
with more machinery. `bootstrap.yaml` replays on every merge to `main`, so rotating
`SENTRY_CRON_DSN` in the `.env` propagates on the next deployment.

The value crosses a privilege boundary — it comes from a file the deployment user owns and
ends up in a file that root-owned units read — so it is treated as untrusted input at every
step:

- **it is validated against a character whitelist** (`A-Za-z0-9:/@._~%?=-`) before being
  written. A `$(…)`, a backtick, a quote or a space is refused outright, with a message that
  never prints the value;
- **no script ever `source`s it.** `sync_alerting_dsn.sh` reads the `.env` with `sed`, and
  `alert_systemd_failure.sh` reads `alerting.env` the same way;
- **the units get it through `EnvironmentFile=`**, which systemd parses itself, with no shell
  in the path.

Any one of those would do; all three are there because a shell substitution reaching a root
unit is not a bug you want to discover in production.

If the `.env` is not there yet — a brand new machine — or if the DSN is malformed, the play
prints a warning and carries on rather than blocking the application deployment, and the
alerting scripts exit non-zero with an explicit message rather than pretending to send
anything.

#### The self-test

An alerting chain that installs "all green" on a machine where nothing will ever be sent
reproduces exactly the silence it exists to break. So at the end of the role, ansible runs
`alert_systemd_failure.sh --self-test`, which sends a real `info` event and fails loudly if
it cannot. The play warns; it does not abort.

It does not run on every deployment — one Sentry event per deployment would reopen a ticket
each time — but it does run whenever something changed, or whenever `alerting.env` is
missing, which covers every case where the chain can be broken without anyone knowing. The
event carries the `systemd-alerting-self-test` fingerprint, so it stays in a single issue.

#### Checking that it works

```bash
systemctl list-timers alert-systemd-sweep.timer   # when the sweep last ran and runs next
systemctl start alert-systemd-sweep.service       # run it now
journalctl -u alert-systemd-sweep.service         # what it found, and whether it could report
systemctl list-units --failed                     # the same question, without Sentry
curl -s https://monitor.<fullname> | jq .units    # unit states on the status page
alert_systemd_failure.sh --self-test              # send one event and check it leaves
```

#### Limits you need to know about

**A unit that restarts forever is invisible here.** A service with `Restart=on-failure` that
crashes slowly enough never exhausts its start limit, so it never enters `failed`, never
triggers `OnFailure=`, and never shows up in `systemctl --failed`. What catches it is the
URL probe on the status page returning 0 or 502 — which is why the two halves of that page
are complementary and neither replaces the other.

**Sentry is a single point of failure.** If the DSN is wrong, the project is full, or the
network is down, nothing arrives. The failure is at least loud locally: `sentry-cli` exits
non-zero, the alerting unit lands in `failed`, and the *next* sweep reports it — verified.
But a sweep whose timer has been disabled reports nothing at all and says nothing about it;
the only remaining witness is then the status page, which is why the sweep units are in the
watched list.

**Nobody is paged.** These events land in Sentry like the cron failures already do, and
inherit whatever notification rules that project has. If nobody has an alert rule on this
project, this mechanism replaces a silence with a line in a web interface. Setting up the
Sentry alert rule for the `systemd-unit-failure` fingerprint is the other half of the job,
and it is not done here.

**Removing a unit from `alerting_watched_units` leaves its drop-in behind.** Ansible writes
`/etc/systemd/system/<unit>.d/50-onfailure.conf` and never removes it; delete it by hand.

**The status page still queries systemd synchronously.** One `systemctl show` covers every
unit, capped at two seconds, so a systemd that stops answering costs the page two seconds
instead of hanging it — but requests are still served one after another while that call runs.
Making the page fully asynchronous is a bigger change than this needed.

**The source `.env` is world-readable** (`0644` in a `0755` directory), so the DSN — and
every other application secret in it — is already readable by any local user. That predates
this mechanism and is not fixed here; `chmod 0600` on the application `.env` would close it,
and the alerting keeps working either way since it reads the file as root.

**The status page reads unit states over the D-Bus system bus.** `monitor_service` runs as
the deployment user, and an unprivileged `systemctl show` needs `/run/dbus/system_bus_socket`
— unlike the alerting units, which run as root and go through systemd's private socket. If
`dbus` is not installed, every unit on the page comes back as `"ok": false` with the bus
error in an `error` field, which is visible but is a false alarm. The Sentry alerting is
unaffected.

**Unit states are published on a page with no authentication**, next to the disk usage and
the URL probes already there. It says a bit about the machine's internals — that a backup is
broken, for instance. Only the units listed in `alerting_watched_units` are published, never
the full `systemctl --failed` output.

### Migrating mongodb collections between servers

> This is a manual, one-shot migration tool, **not** a backup. An operator triggers it, it
> only covers the collections named in the inventory, and it deletes its archive from the
> server afterwards. For the scheduled backup of the whole database, see
> [Automatic MongoDB backup](#automatic-mongodb-backup) above.

It is possible to dump mongodb collections from a server and restore them on another.

In order do dump data, you will need to had specific configuration lines in your inventory application to specify which mongodb collection to target and with which query :
```yaml
mongodb_collections_migration:
  simulations: '{"createdAt": {"$gte": { "$date": "2023-01-01T00:00:00.000Z" }}}'
  followups: '{"createdAt": {"$gte": { "$date": "2023-01-01T00:00:00.000Z" }}}'
```
Then run the following command to download the selected collections locally in a `./.tmp` folder :
```bash
ansible-playbook -i ./inventories/localhost.yaml --tags="dump" mongodb-migration.yaml
```

To restore that data on another server you will need to add the following lines to the inventory applications :
```yaml
mongodb_collections_migration:
  simulations: ""
  followups: ""
```
Then run the command :
```bash
ansible-playbook -i ./inventories/vps.yaml --tags="restore" mongodb-migration.yaml
```

# Local development

In order to run ansible on a local image you will need to have both Vagrant and Docker installed on your machine. You will also need to have a valid public/secret key pair in your local ssh folder (`~/.ssh/`) called `id_rsa.pub` and `id_rsa`.

Navigate to the `local` folder and run the command :
- `vagrant up --provider=virtualbox` to create a VirtualBox VM
- `vagrant up --provider=docker` to create a docker container (recommended if running on an arm64 processor)

Once the image is successfully created, you should be able to run any of the above commands.

# Debug CI/CD Github 
You can use act that works with Docker.
Here is an example:

- `act pull_request --container-architecture linux/amd64  -P ubuntu-24.04=ghcr.io/catthehacker/ubuntu:act-24.04`
