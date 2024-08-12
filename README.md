# Aides-Jeunes Ops

Set up the [Mes Aides](https://mes-aides.1jeune1solution.beta.gouv.fr/) stack.

## Before starting

The ansible scripts in this repository have been tested only Debian 12 x86_64 server. However, older or newer versions of Debian may be compatible.

## Deployment

### Prerequisites

You will need at most the following ressources:
- an SSH connection as a priviledged user to the remote server
- Ansible >2.14.5 with Python >3.9 installed on your local machine. See [the documentation](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-ansible-on-specific-operating-systems) for your operating system.

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
        - guillett
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

### Bootstrap server stack

Run the command `ansible-playbook -i ./inventories/vps.yaml bootstrap.yaml` in order to bootstrap the server basic configuration.

Once done, every applications should be up and running on the server.

Note that you only need to run this command once, but you can re-run it if you modify either Nginx, Python, Mongo configuration or if the bootstrap process failed at some point. All unaltered steps that ran successfully will be automatically skipped by Ansible.

### Backup mongodb collections

It is possible to dump mongodb collections from a server and restore them on another.

In order do dump data, you will need to had specific configuration lines in your inventory application to specify which mongodb collection to target and with which query :
```yaml
mongodb_collections_migration:
  simulations: '{"created_at": {"$gte": { "$date": "2023-01-01T00:00:00.000Z" }}}'
  followups: '{"created_at": {"$gte": { "$date": "2023-01-01T00:00:00.000Z" }}}'
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
