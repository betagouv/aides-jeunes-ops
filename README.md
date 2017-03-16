# Mes aides ops

Set up the [Mes Aides](https://mes-aides.gouv.fr) stack.

> Déploie l'infrastructure de Mes Aides.

## Development

Development is done using Vagrant and the Ubuntu version used in production: Ubuntu 14.04 64 bit (trusty).

The ```vagrant up --provider virtualbox``` command should gives you a fully functionning Mes Aides instance.

Currently, it gives you:
- A MongoDB instance with default settings
- Mes-aides on port 8000 (ExpressJS application)
- OpenFisca on port 2000 (Python via gunicorn)
- Mes-aides on port 80 thanks to NGINX proxy

## Limitations

* NodeJS 0.10 installation is **distribution dependant** (because of *0.10.48-1nodesource1~trusty1*)

## Details

Currently, applications are set up and run by *ubuntu* user.

## TODO

- Check relative path possibilities
    + vcsrepo { '/home/ubuntu/mes-aides-ui':
        * /opt alternatives
        * Absolute paths are required in vcsrepo https://github.com/puppetlabs/puppetlabs-vcsrepo/blob/master/lib/puppet/type/vcsrepo.rb#L162
    + exec { 'install node modules for mes-aides-ui':
        * absolute or qualified with path https://docs.puppet.com/puppet/latest/types/exec.html#exec-attribute-command
- Can we use the user running puppet --apply?
    + Yes we can and rely on facts "${facts['identity']['user']}"
    + To prevent explicit user reference
    + exec { 'install node modules for mes-aides-ui':
- Comment current Python setup (python:requirements do not accept --upgrade)
- Surcouche service/upstart
- Move inline shell scripts to files
    + bootstrap.sh
- Create CI deployment script
    + Add in Circle CI in production
- Formal test of CI deployment
- Add Let's Encrypt SSL support (OPT IN for SSL)
    + Rely on mes-aides.gouv.fr certificate
    + Prevent renewal
- Create OpenFisca Puppet module?
- Create Mes-Aides Puppet module (to make feature branch deployment a breeze)?
