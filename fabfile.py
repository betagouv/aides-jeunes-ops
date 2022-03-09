from fabric import task, Connection
from contextlib import contextmanager
from jinja2 import Environment, FileSystemLoader, Template
import os
import requests
import tempfile

USER="root"
WEBROOT_PATH="/var/www"

# ANGULAR_FOLDER="mes-aides-angular"

loader = Environment(loader=FileSystemLoader('.'))


@contextmanager
def write_template(path, ctx):
  fp = tempfile.TemporaryFile(mode='w+', encoding='utf8')
  t = loader.get_template(path)
  t.stream(**ctx).dump(fp)
  fp.seek(0)
  yield fp
  fp.close()


@contextmanager
def write_nginx_config(config0):
  config = {
    **config0,
    'webroot_path': WEBROOT_PATH,
  }
  with write_template('files/nginx_config.template', config) as fp:
    yield fp


# Initial installation from a remote fabfile
@task
def bootstrap(ctx, host):
  c = Connection(host=host, user=USER)
  c.config = ctx.config
  c.run('mkdir --parents /opt/mes-aides')
  c.run('apt-get install --assume-yes htop openssh-client python3-pip rsync vim')
  c.local('rsync -r . %s@%s:/opt/mes-aides/ops --exclude .git --exclude .venv37 --exclude .vagrant -v' % (USER, host))
  c.run('apt-get update')
  if c.run('test -f $HOME/.ssh/id_rsa', warn=True).exited:
    c.run('ssh-keygen -t rsa -q -f "$HOME/.ssh/id_rsa" -m PEM -N "" -C "aides-jeunes@beta.gouv.fr"')
  c.run('cd /opt/mes-aides/ops && pip3 install --requirement requirements.txt')
  ssh_access(c)
  c.run('cd /opt/mes-aides/ops && fab tell-me-your-name --host localhost --identity $HOME/.ssh/id_rsa')


@task
def sync(ctx, host):
  c = Connection(host=host, user=USER)
  c.local('rsync -r . %s@%s:/opt/mes-aides/ops --exclude={.git,.venv,.venv37,.vagrant} -v' % (USER, host))


# Core task for full porivisionning
@task
def provision(ctx, host, name, dns_ok=False):
  if not dns_ok:
    print_dns_records(host, name)
    print_dns_records(host, '')
    return

  c = Connection(host=host, user=USER)
  c.config = ctx.config
  provision_tasks(c, host, name)


# Task for continuous deployment
@task
def refresh(ctx, host, force=False):
  c = Connection(host=host, user=USER)
  c.config = ctx.config
  refresh_tasks(c, force)


# Allow NGINX remote debugging
@task
def nginx(ctx, host):
  c = Connection(host=host, user=USER)
  c.run('service nginx status', warn=True)
  c.run('service nginx restart', warn=True)
  c.run('service nginx status')


# Basic task for connection debugging
@task
def tell_me_your_name(c, host):
  c = Connection(host=host, user=USER)
  c.run('hostname')
  c.run('date')
  c.run('uname -a')
  c.run('lsb_release -a')


# Allow Lets Encrypt challenge redirection to
# move production requests to differente servers
# without downtime
@task
def proxy_challenge(ctx, host, challenge_proxy):
  c = Connection(host=host, user=USER)
  fullname = c.run('hostname').stdout.split()[0]
  nginx_all_sites(c, fullname, challenge_proxy=challenge_proxy)


# Allow
@task
def regenerate_nginx_hosts(ctx, host):
  c = Connection(host=host, user=USER)
  fullname = c.run('hostname').stdout.split()[0]
  nginx_all_sites(c, fullname)


remote_location = '/home/main/aides-jeunes/backend/config/production.js'
local_location = 'production.config.js'
@task
def production_config_get(ctx, host='mes-aides.1jeune1solution.beta.gouv.fr'):
  c = Connection(host=host, user=USER)
  c.get(remote_location, local_location)


@task
def production_config_put(ctx, host):
  c = Connection(host=host, user=USER)
  c.put(local_location, remote_location)
  app_restart(c)


# Live hack task
@task
def fallback(ctx, host, name=None):
  c = Connection(host=host, user=USER)
  nginx_setup(c)
  fullname = c.run('hostname').stdout.split()[0]
  nginx_all_sites(c, fullname)


def curl(c):
  curl_versions = c.run("apt-cache show curl | grep Version | awk -F \" \" '{print $2}'", hide=True).stdout.split()
  for v in curl_versions:
    cmd = c.run("apt-get install --assume-yes --no-remove curl=%s" % v, warn=True)
    if cmd.exited:
      print("****************** Curl installation failed for version %s!" % v)
      print("****************** Fallbacking to next version")
    else:
      return
  raise BaseException("Curl could not be installed")


def provision_tasks(c, host, name):
  fullname = get_fullname(name)

  system(c, fullname)
  nginx_setup(c)
  node(c)
  mongodb(c)

  monitor(c)

  python(c)
  openfisca_setup(c)
  openfisca_config(c)

  app_setup(c)

  letsencrypt(c)
  nginx_all_sites(c, fullname)

  refresh_tasks(c, force=True)


def get_fullname(name):
  return "%s.mes-aides.1jeune1solution.beta.gouv.fr" % name


@task
def add_next(ctx, host):
  c = Connection(host=host, user=USER)
  # app_setup(c, ANGULAR_FOLDER, 'angular')
  # app_refresh(c, ANGULAR_FOLDER)


def print_dns_records(host, name):
  print('DNS records should be updated')
  suffix = '.' if len(name) else ''
  print('\n'.join(['%s 3600 IN A %s' % (item.ljust(25), host) for item in ['%s%s' % (prefix, name) for prefix in ['', 'www%s' % suffix , 'openfisca%s' % suffix, 'monitor%s' % suffix]]])) #, 'v1.']]]))
  print('Once it is done add --dns-ok')


@task
def show_dns(ctx, host, name):
  print_dns_records(host, name)


def refresh_tasks(c, force=False):
  ssh_access(c)
  nginx_reload(c)
  if app_refresh(c, force=force):
    openfisca_refresh(c)
  # app_refresh(c, ANGULAR_FOLDER)


def ssl_setup(c):
  dhparam_path = '/etc/ssl/private/dhparam.pem'
  missing = c.run('test -e %s' % dhparam_path, warn=True).exited
  if missing:
    c.run('/usr/bin/openssl dhparam -out %s 2048' % dhparam_path)

@task
def ssh_reset(ctx, host):
  c = Connection(host=host, user=USER)
  c.local('date')
  c.config = ctx.config
  ssh_access(c)

def ssh_access(c):
  users = c.config.get('github', [])
  assert len(users), "Attention, aucun utilisateur github spécifié, risque d'être bloqué hors du serveur !"
  conf = {
    'root': c.run('cat ~/.ssh/id_rsa.pub', hide=True, warn=True).stdout,
    'users': [{ 'name': u, 'ssh_keys': requests.get("https://github.com/%s.keys" % u).text} for u in users]
  }
  c.put('files/update.sh', '/opt/mes-aides/update.sh')
  with write_template('files/root_authorized_keys.template', conf) as fp:
    c.put(fp, 'authorized_keys')
  c.sudo('mkdir --parents /root/.ssh')
  c.sudo('mv authorized_keys /root/.ssh/authorized_keys')
  c.sudo('chmod 600 /root/.ssh/authorized_keys')
  c.sudo('chown root:root /root/.ssh/authorized_keys')


def nginx_setup(c):
  c.run('apt-get install --assume-yes nginx')
  c.put('files/nginx.ssl_params.conf', '/etc/nginx/snippets/ssl_params.conf')
  c.put('files/nginx.upstreams.conf', '/etc/nginx/conf.d/upstreams.conf')
  c.put('files/nginx_mesaides_static.conf', '/etc/nginx/snippets/mes-aides-static.conf')
  nginx_reload(c)
  c.run('rm -f /etc/nginx/sites-enabled/default')
  c.run('mkdir --parents %s' % WEBROOT_PATH)

  ssl_setup(c)


def nginx_reload(c):
  c.run('nginx -t')
  c.run('service nginx reload')


def letsencrypt(c):
  c.run('apt-get install --assume-yes certbot')
  c.run('certbot register --non-interactive --agree-tos --email aides-jeunes@beta.gouv.fr')


def nginx_site(c, config):
  fullname = config['name']
  add_www_subdomain = config['add_www_subdomain'] if 'add_www_subdomain' in config else False

  ssl_exists = True
  certificate_path = '/etc/letsencrypt/live/%s/fullchain.pem' % fullname
  missing_certificate = c.run('test -e %s' % certificate_path, warn=True).exited
  if missing_certificate:
    with write_nginx_config(config) as fp:
      c.put(fp, '/etc/nginx/sites-enabled/%s.conf' % fullname)
    nginx_reload(c)

    letsencrypt_args = '--cert-name %s -d %s %s --webroot-path %s' % (fullname, fullname, ' --expand -d www.%s' % fullname if add_www_subdomain else '', WEBROOT_PATH)
    letsencrypt_command = 'certbot certonly --webroot --non-interactive %s' % letsencrypt_args
    letsencrypt = c.run(letsencrypt_command, warn=True)
    if letsencrypt.exited:
      print('WARNING Lets encrypt failed')
      print(letsencrypt.stdout)
      print(letsencrypt.stderr)
      print(letsencrypt)
      ssl_exists = False

  with write_nginx_config({'ssl_exists': ssl_exists, **config}) as fp:
    c.put(fp, '/etc/nginx/sites-enabled/%s.conf' % fullname)
  nginx_reload(c)


def nginx_sites(c, fullname, is_default=False, challenge_proxy=None):
  monitor = {
    'name': 'monitor.%s' % fullname,
    'upstream_name' : 'monitor',
    'challenge_proxy': challenge_proxy
  }
  nginx_site(c, monitor)

  main = {
    'name': fullname,
    'add_www_subdomain': True,
    'is_default': is_default,
    'upstream_name' : 'mes_aides',
    'nginx_root': '/home/main/aides-jeunes',
    'challenge_proxy': challenge_proxy,
  }
  nginx_site(c, main)

  # angular_ = {
  #   'name': 'v1.%s' % fullname,
  #   'upstream_name' : 'mes_aides_angular',
  #   'nginx_root': '/home/main/mes-aides-angular',
  #   'challenge_proxy': challenge_proxy,
  # }
  # nginx_site(c, angular_)

  openfisca = {
    'name': 'openfisca.%s' % fullname,
    'upstream_name' : 'openfisca',
    'challenge_proxy': challenge_proxy,
  }
  nginx_site(c, openfisca)

  nginx_reload(c)


def nginx_all_sites(c, fullname, challenge_proxy=None):
  nginx_sites(c, fullname, is_default=False, challenge_proxy=challenge_proxy)
  nginx_sites(c, 'mes-aides.1jeune1solution.beta.gouv.fr', is_default=True, challenge_proxy=challenge_proxy)


def system(c, name=None):
  if name:
    c.run('hostname %s' % name)

  # This source list is required for MongoDB
  # Once added, curl is tricky to install
  c.run('echo "deb http://deb.debian.org/debian/ stretch main" | tee /etc/apt/sources.list.d/debian-stretch.list')
  c.run('apt update')
  c.run('apt-get install --assume-yes libcurl3')

  c.run('apt-get install --assume-yes build-essential git man ntp vim')
  curl(c)

  c.run('apt-get install --assume-yes chromium')
  c.run('sysctl -w kernel.unprivileged_userns_clone=1')

  c.run('ln -fs /usr/share/zoneinfo/Europe/Paris /etc/localtime')
  c.run('dpkg-reconfigure -f noninteractive tzdata')
  usermain(c)


def usermain(c):
  missing = c.run('id -u main', warn=True).exited
  if missing:
    c.run('useradd main --create-home --shell /bin/bash')
    c.run('mkdir --parents /var/log/main')
    c.run('chown main:main -R /var/log/main')


def node(c):
  c.run('curl --silent --location https://deb.nodesource.com/setup_16.x | bash -')
  c.run('apt-get install --assume-yes nodejs')
  pm2(c)


def pm2(c):
  c.run('npm install --global pm2@3.5.1')
  c.run('pm2 startup systemd -u main --hp /home/main')


def python(c):
  c.run('apt-get install --assume-yes python3.7 python3.7-dev python3-venv')


# https://linuxhint.com/install_mongodb_debian_10/
def mongodb(c):
  c.run('apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4')
  c.run('echo "deb http://repo.mongodb.org/apt/debian/dists/stretch/mongodb-org/5.0/ main" | tee /etc/apt/sources.list.d/mongodb-org.list')
  c.run('apt-get update')
  c.run('apt-get install --assume-yes mongodb-org')
  c.run('service mongod start')
  c.run('systemctl enable mongod')


def monitor(c):
  c.run('mkdir --parents /opt/mes-aides')
  c.put('files/monitor/monitor.sh', '/opt/mes-aides/monitor.sh')
  c.put('files/monitor/monitor-server.js', '/opt/mes-aides/monitor-server.js')
  c.put('files/monitor/ma-monitor.service', '/etc/systemd/system/ma-monitor.service')
  c.run('systemctl daemon-reload')
  c.run('service ma-monitor restart')
  c.run('systemctl enable ma-monitor')


def app_setup(c, folder='aides-jeunes', branch='master'):
  c.run('su - main -c "git clone https://github.com/betagouv/aides-jeunes.git %s"' % folder)
  c.run('su - main -c "cd %s && git checkout %s"' % (folder, branch))
  production_path = '/home/main/%s/backend/config/production.js' % folder
  result = c.run('[ -f %s ]' % production_path, warn=True)
  if result.exited:
    c.run('su - main -c "cp /home/main/%s/backend/config/continuous_integration.js %s"' % (folder, production_path))

  test = c.run('su - main -c "crontab -l 2>/dev/null | grep -q \'%s/backend/lib/stats\'"' % folder, warn=True)
  if test.exited:
    c.run('su - main -c \'(crontab -l 2>/dev/null; echo "23 2 * * * /usr/bin/node /home/main/%s/backend/lib/stats") | crontab -\'' % folder)

  test = c.run('su - main -c "crontab -l 2>/dev/null | grep -q \'%s/backend/lib/email\'"' % folder, warn=True)
  if test.exited:
    cmd = "8 4 * * * (NODE_ENV=production /usr/bin/node /home/main/%s/backend/lib/email.js send survey --multiple 1000 >> /var/log/main/emails.log)" % folder
    c.run('su - main -c \'(crontab -l 2>/dev/null; echo "%s") | crontab -\'' % cmd)

  c.run('su - main -c "cd %s && pm2 install pm2-logrotate"' % folder)
  c.run('su - main -c "cd %s && pm2 set pm2-logrotate:max_size 50M"' % folder)
  c.run('su - main -c "cd %s && pm2 set pm2-logrotate:compress true"' % folder)


def app_refresh(c, folder='aides-jeunes', force=False):
  startHash = c.run('su - main -c "cd %s && git rev-parse HEAD"' % folder).stdout
  c.run('su - main -c "cd %s && git pull"' % folder)
  refreshHash = c.run('su - main -c "cd %s && git rev-parse HEAD"' % folder).stdout
  if force or startHash != refreshHash:
    c.run('su - main -c "cd %s && npm ci"' % folder)
    c.run('su - main -c "cd %s && npm run prestart"' % folder)
    app_restart(c, folder)

  return force or startHash != refreshHash


def app_restart(c, folder):
  c.run('su - main -c "cd %s && pm2 startOrReload /home/main/%s/pm2_config.yaml --update-env"' % (folder, folder))
  c.run('su - main -c "cd %s && pm2 save"' % folder)


venv_dir = '/home/main/venv_python3.7'
def openfisca_setup(c):
  c.run('su - main -c "python3.7 -m venv %s"' % venv_dir)


def openfisca_reload(c):
  result = c.run('service openfisca reload', warn=True)
  if result.exited:
    c.run('service openfisca start')


def openfisca_config(c):
  with write_template('files/openfisca.service.template', { 'venv_dir': venv_dir }) as fp:
    c.put(fp, '/etc/systemd/system/openfisca.service')
  c.run('systemctl daemon-reload')
  openfisca_reload(c)
  c.run('systemctl enable openfisca')


def openfisca_refresh(c):
  c.run('su - main -c "%s/bin/pip3 install --upgrade pip"' % venv_dir)
  c.run('su - main -c "cd aides-jeunes && %s/bin/pip3 install --upgrade -r openfisca/requirements.txt"' % venv_dir)
  openfisca_reload(c)
