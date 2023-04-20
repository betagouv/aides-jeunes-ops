# Aides-Jeunes Ops

Set up the [Mes Aides](https://mes-aides.1jeune1solution.beta.gouv.fr/) stack.

## Before starting

The ansible scripts in this repository have been tested only Debian 11 x86_64 server. However, older or newer versions of Debian may be compatible.

## Deployment

### Prerequisites

You will need at most the following ressources:
- an SSH connection as a priviledged user to the remote server
- Ansible installed on your local machine. See [the documentation](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-ansible-on-specific-operating-systems) for your operating system.

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
        - Cugniere
      applications:                                                      # List all applications that will be deployed
        - name: aides_jeunes
          repository: https://github.com/betagouv/aides-jeunes.git
          branch: master
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
- set `UsePAM no`

It is advised to run this command on a newly installed and if you understand the implication of those parameters. Your hosting service should provide you with an emergency access if you get locked out of the server.

### Listing required DNS record

In order for the server to be successfully deployed, some sub domain name must be specified in the DNS record. In order to know which values are required, simply run `ansible-playbook -i ./inventories/vps.yaml dns-record.yaml`. You will get an output such as this one:
```
solstice.aides-jeunes                              3600 IN A 5.135.137.147
monitor.solstice.aides-jeunes                      3600 IN A 5.135.137.147
solstice.aides-jeunes                              3600 IN A 5.135.137.147
www.solstice.aides-jeunes                          3600 IN A 5.135.137.147
openfisca.solstice.aides-jeunes                    3600 IN A 5.135.137.147
aides-jeunes                                       3600 IN A 5.135.137.147
www.aides-jeunes                                   3600 IN A 5.135.137.147
openfisca.aides-jeunes                             3600 IN A 5.135.137.147
```

Then you will have to add all those entries to the associated domain name DNS record.

### Synchronize Ops repository

In order to be able to refresh tasks on the server, you will need to synchronize the content of this repository on your server. Once a continuous deployment pipeline connect to your server it will (in a near future) fetch the latest version of the branch used by the application.

Run `ansible-playbook -i ./inventories/vps.yaml synchronize.yaml` to create an exact copy of this repository in the folder `/opt/mes-aides/ops` of your server.

### Bootstrap server stack

Run the command `ansible-playbook -i ./inventories/vps.yaml bootstrap.yaml` in order to bootstrap the server basic configuration.

Once done, every applications should be up and running on the server.

Note that you only need to run this command once, but you can re-run it if you modify either Nginx, Python, Mongo configuration or if the bootstrap process failed at some point. All unaltered steps that ran successfully will be automatically skipped by Ansible.

### Update SSH access

To manage the access to the server through ssh, run the command `ansible-playbook -i ./inventories/vps.yaml ssh-access.yaml`.

This will automatically allow all the users specified in the `github` section of the configuration to connect to the server with their respective private key used to identify to github.

This will also add the public key currently used to connect to the server with Ansible.


# Local development

In order to run ansible on a local image you will need to have both Vagrant and Docker installed on your machine. You will also need to have a valid public/secret key pair in your local ssh folder (`~/.ssh/`) called `id_rsa.pub` and `id_rsa`.

Navigate to the `local` folder and run the command :
- `vagrant up --provider=virtualbox` to create a VirtualBox VM
- `vagrant up --provider=docker` to create a docker container (recommended if running on an arm64 processor)

Once the image is successfully created, you should be able to run any of the above commands.