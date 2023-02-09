# Mes Aides ops

Set up the [Mes Aides](https://mes-aides.1jeune1solution.beta.gouv.fr) stack.

> Déploie l'infrastructure de Mes Aides.


## Initial provisioning

Prerequisite:
- Python 3 and virtualenv
- An SSH connection to the root user of the remote server


```
SERVER=51.91.78.117
NAME=wiru
ssh root@$SERVER -C date

cp aides_jeunes_fabric.yml fabric.yml

virtualenv .venv37 --python=python3.7
source .venv37/bin/activate
pip install --requirement requirements.txt --upgrade

ssh-add ~/.ssh/id_rsa
fab bootstrap --host $SERVER
fab provision --host $SERVER --name $NAME
# fab provision --host $SERVER --name $NAME --dns-ok # Once DNS have been updated
```

## Deploy project (Aides-Jeunes)

### Installation for deployment

In your machine clone aides-jeunes-ops and run the following command:

```
cp aides_jeunes_fabric.yml fabric.yml

virtualenv .venv37 --python=python3.7
source .venv37/bin/activate
pip install --requirement requirements.txt --upgrade
```

If you are using MacOS with a M1 processor, you need to use a version of Python superior or equal to `Python 3.9.7` in  order to be able to install and use `Fabric`.

### Update production provisioning

Run the following command in your machine:

```
fab sync --host=mes-aides.1jeune1solution.beta.gouv.fr
```

### Run provisioning from personal computer

Run the following command in your machine:

```
fab refresh
```

cf. files/update.sh and deploy CircleCI workflow in main repository

#### Secret environment variables

The main NodeJS server needs some private variables for production, stored at '/home/main/aides-jeunes/backend/config/production.js'

These variables can be fetched from the current production server with `fab production-config-get`, _--host_ can be specified but default to _mes-aides.1jeune1solution.beta.gouv.fr_. Then the configuration file can be put on another server with `fab production-config-put --host <hostname>`.


#### Continuous deployment

An private key can `ssh` to the host and it will automatically deploy the application latest version.

That private key has been added to CirclecCI (aides-jeunes repository) to allow continuous deployment.


## Development

Development is done using Vagrant and a Debian 10 (buster).

The `vagrant up` command should give you a VM in a similar environment as OVH **clean** instance.
You have to run provisioning commands to set up the server.

**Note: if you use an ARM based computer (for example a Mac with a M1/M2 processor), you need to use Docker as a VM provider and run `vagrant up --provider=docker`**

```
SERVER=192.168.56.200
NAME=testa
ssh root@$SERVER -C date

virtualenv .venv37 --python=python3.7
source .venv37/bin/activate
pip install --requirement requirements.txt --upgrade

cp aides_jeunes_fabric.yml fabric.yml

ssh-add ~/.ssh/id_rsa
fab bootstrap --host $SERVER
fab provision --host $SERVER
```


Currently, it gives you:
- A MongoDB instance with default settings.
- Mes Aides on port 8000 (ExpressJS application).
- OpenFisca on port 2000 (Python via gunicorn).
- A basic monitor server

And via nginx :
- the application as a default server and on 4 host names:
    - (www\.)?(<prefix>\.)?mes-aides.1jeune1solution.beta.gouv.fr,
- OpenFisca on 2 host names:
    - (openfisca.)?(<prefix>\.)?mes-aides.1jeune1solution.beta.gouv.fr,
- the monitor on 2 host names:
    - (monitor.)?(<prefix>\.)?mes-aides.1jeune1solution.beta.gouv.fr,

HTTPS (and associated redirection) is setup if Let's Encrypt certificates are availables (3 set of certificates)

# Monitor

Two different scanning services are used, in order to remove dependency on one specific provider to notify in case of a service failure.
This endpoint is scanned by [UptimeRobot](https://uptimerobot.com) on a 1-minute interval, and will notify the team through Slack and SMS. It is also scanned on a 2-minute interval by [SetCronJob](https://www.setcronjob.com) which will notify the team by email. The SetCronJob instance has to be manually rearmed (i.e. re-enabled after it gets automatically disabled on failure) when it has been triggered.
