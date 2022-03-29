from fabric import task, Connection
from contextlib import contextmanager
from jinja2 import Environment, FileSystemLoader, Template
import os
import requests
import tempfile

USER="root"
WEBROOT_PATH="/var/www"
RSYNC_EXCLUDE="--exclude={.git,.venv,.venv37,.vagrant}"
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
  email = c.config.get('email')
  c.run('mkdir --parents /opt/mes-aides')
  c.run('apt-get update')
  c.run('apt-get install --assume-yes htop openssh-client libffi-dev rsync vim')
  python(c)
  c.local('rsync -r . %s@%s:/opt/mes-aides/ops %s -v' % (USER, host, RSYNC_EXCLUDE))
  c.run('apt-get update')
  if c.run('test -f $HOME/.ssh/id_rsa', warn=True).exited:
    c.run('ssh-keygen -t rsa -q -f "$HOME/.ssh/id_rsa" -m PEM -N "" -C "%s"' % email)
  c.run('cd /opt/mes-aides/ops && pip3 install --requirement requirements.txt')
  ssh_access(c)
  c.run('cd /opt/mes-aides/ops && fab tell-me-your-name --host localhost --identity $HOME/.ssh/id_rsa')


@task
def sync(ctx, host):
  c = Connection(host=host, user=USER)
  c.local('rsync -r . %s@%s:/opt/mes-aides/ops %s -v' % (USER, host, RSYNC_EXCLUDE))


# Core task for full provisionning
@task
def provision(ctx, host):
  c = Connection(host=host, user=USER)
  c.config = ctx.config
  provision_tasks(c, host)


# Task for continuous deployment
@task
def refresh(ctx, host, application=None, force=False):
  c = Connection(host=host, user=USER)
  c.config = ctx.config
  refresh_tasks(c, force, application)


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
  c.config = ctx.config
  nginx_setup(c)
  nginx_all_sites(c)


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


def provision_tasks(c, host):
  fullname = c.config.get('fullname')

  system(c, fullname)
  nginx_setup(c)
  node(c)
  mongodb(c)

  # monitor(c) # TODO

  letsencrypt(c)
  nginx_all_sites(c)

  for application in c.config.applications:
    node_setup(c, application)
    openfisca_setup(c, application)
    generate_deploy_key(c, application)

  refresh_tasks(c, force=True)


def print_dns_records(config):
  fullname = config.get('fullname')
  dns_root = config.get('dns_root')
  dns_fullname = fullname[0:len(fullname)-len(dns_root)].strip(".")

  items = [
    dns_fullname,
    'monitor.%s' % dns_fullname
    ]
  for domain in [fullname, *[a.get('domain') for a in config.get('applications')]]:
    name = domain[0:len(domain)-len(dns_root)].strip(".")
    suffix = '.' if len(name) else ''
    for prefix in ['', 'www%s' % suffix , 'openfisca%s' % suffix]:
      items.append('%s%s' % (prefix, name))
  print('\n'.join(['%s 3600 IN A %s' % (
    item.ljust(30), config.get('host')
  ) for item in items]))


@task
def show_dns(ctx):
  print_dns_records(ctx.config)


def refresh_tasks(c, application=None, force=False):
  ssh_access(c)

  nginx_reload(c)
  for app in c.config.applications:
    if application in [None, app.get('name')]:
      if node_refresh(c, app, force=force):
        openfisca_refresh(c, app)


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


def get_application_ssh_data(c, application):
  cmd = c.run('cat %s.pub' % generate_deploy_key(c, application), hide=True, warn=True)
  return {
    'name': application.get('name'),
    'key': None if cmd.exited else cmd.stdout
  }

def ssh_access(c):
  users = c.config.get('github', [])
  assert len(users), "Attention, aucun utilisateur github spécifié, risque d'être bloqué hors du serveur !"
  conf = {
    'root': c.run('cat ~/.ssh/id_rsa.pub', hide=True, warn=True).stdout,
    'applications': [ get_application_ssh_data(c, application) for application in c.config.applications ],
    'users': [{ 'name': u, 'ssh_keys': requests.get("https://github.com/%s.keys" % u).text} for u in users]
  }
  c.put('files/update.sh', '/opt/mes-aides/update.sh')
  with write_template('files/root_authorized_keys.template', conf) as fp:
    c.put(fp, 'authorized_keys')
  c.sudo('mkdir --parents /root/.ssh')
  c.sudo('mv authorized_keys /root/.ssh/authorized_keys')
  c.sudo('chmod 600 /root/.ssh/authorized_keys')
  c.sudo('chown root:root /root/.ssh/authorized_keys')


def get_application_deploy_key_path(application):
  return '%s/id_rsa' % get_application_folder(application)


def generate_deploy_key(c, application):
  key_path = get_application_deploy_key_path(application)
  missing_key = c.run('test -e %s' % key_path, warn=True).exited
  if missing_key:
    c.run('ssh-keygen -t rsa -b 4096 -f %s -q -N ""' % key_path, warn=True)
  return key_path


def nginx_setup(c):
  c.run('apt-get install --assume-yes nginx')
  c.put('files/nginx.ssl_params.conf', '/etc/nginx/snippets/ssl_params.conf')
  with write_template('files/nginx.upstreams.conf.template', c.config) as fp:
    c.put(fp, '/etc/nginx/conf.d/upstreams.conf')
  c.put('files/nginx_mesaides_static.conf', '/etc/nginx/snippets/mes-aides-static.conf')
  nginx_reload(c)
  c.run('rm -f /etc/nginx/sites-enabled/default')
  c.run('mkdir --parents %s' % WEBROOT_PATH)

  ssl_setup(c)


def nginx_reload(c):
  result = c.run('nginx -t', warn=True)
  if not result.exited:
    c.run('service nginx reload')


def letsencrypt(c):
  c.run('apt-get install --assume-yes certbot')
  c.run('certbot register --non-interactive --agree-tos --email %s' % c.config.get('email'))


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


def nginx_application_sites(c, application, additional_domain=None):
  application_name = application.get('name')
  domain = additional_domain if additional_domain else application.get('domain')
  challenge_proxy = application.get('challenge_proxy', None)
  is_default = application.get('default_site', False) if not additional_domain else False

  main = {
    'name': domain,
    'add_www_subdomain': True,
    'is_default': is_default,
    'upstream_name' : '%s_node' % application_name,
    'nginx_root': get_repository_folder(application),
    'challenge_proxy': challenge_proxy,
  }
  nginx_site(c, main)

  openfisca = {
    'name': 'openfisca.%s' % domain,
    'upstream_name' : '%s_openfisca' % application_name,
    'challenge_proxy': challenge_proxy,
  }
  nginx_site(c, openfisca)

  nginx_reload(c)


def nginx_all_sites(c):
  fullname = c.config.get('fullname')

  default_application = [
    *[a for a in c.config.get('applications') if a.get('default_site')],
    *[a for a in c.config.get('applications') if not a.get('default_site')],
    ][0]
  nginx_application_sites(c, default_application, fullname)

  monitor = {
    'name': 'monitor.%s' % fullname,
    'upstream_name' : 'monitor',
  }
  nginx_site(c, monitor)

  for application in c.config.applications:
    nginx_application_sites(c, application)


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

  c.run('su - main -c "pm2 install pm2-logrotate"')
  c.run('su - main -c "pm2 set pm2-logrotate:max_size 50M"')
  c.run('su - main -c "pm2 set pm2-logrotate:compress true"')


def python(c):
  c.run('apt-get install --assume-yes python3.7 python3.7-dev python3-pip python3-venv')


# https://linuxhint.com/install_mongodb_debian_10/
def mongodb(c):
  result = c.run('apt-key list', hide=True)
  if True or 'Mongo' not in result.stdout:
    c.run('apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4')
    c.run('echo "deb http://repo.mongodb.org/apt/debian stretch/mongodb-org/4.0 main" | tee /etc/apt/sources.list.d/mongodb-org.list')
    c.run('apt-get update')
  else:
    print('MongoDB packages already setup')
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


def get_application_folder(application):
  return "/home/main/%s" % application.get('name')


def get_repository_folder(application):
  return "%s/repository" % get_application_folder(application)


def node_setup(c, application):
  app_folder = get_application_folder(application)
  repository = application.get('repository')
  repo_folder = get_repository_folder(application)
  branch = application.get('branch', "master")

  missing = c.run('[ -d %s ]' % repo_folder, warn=True).exited
  if missing:
    c.run('su - main -c "git clone %s %s"' % (repository, repo_folder))
  c.run('su - main -c "cd %s && git checkout %s"' % (repo_folder, branch))
  with write_template('files/pm2_config.yaml.template', { 'application': application }) as fp:
    config_path = '%s/pm2_config.yaml' % app_folder
    c.put(fp, config_path)
    c.run('chown main:main %s' % config_path)

  production_path = '%s/backend/config/production.js' % repo_folder
  result = c.run('[ -f %s ]' % production_path, warn=True)
  if result.exited:
    c.run('su - main -c "cp %s/backend/config/continuous-integration.js %s"' % (repo_folder, production_path))

  varenv_prefix = "NODE_ENV=production MONGODB_URL=mongodb://localhost/db_%s" % application.get('name')
  test = c.run('su - main -c "crontab -l 2>/dev/null | grep -q \'%s/backend/lib/stats\'"' % repo_folder, warn=True)
  if test.exited:
    cmd = "23 2 * * * (%s /usr/bin/node %s/backend/lib/stats)" % (varenv_prefix, repo_folder)
    c.run('su - main -c \'(crontab -l 2>/dev/null; echo "%s") | crontab -\'' % cmd)

  test = c.run('su - main -c "crontab -l 2>/dev/null | grep -q \'%s/backend/lib/email\'"' % repo_folder, warn=True)
  if test.exited:
    cmd = "8 4 * * * (%s /usr/bin/node %s/backend/lib/email.js send survey --multiple 1000 >> /var/log/main/emails.log)" % (varenv_prefix, repo_folder)
    c.run('su - main -c \'(crontab -l 2>/dev/null; echo "%s") | crontab -\'' % cmd)


def node_refresh(c, application, force=False):
  folder = get_repository_folder(application)
  startHash = c.run('su - main -c "cd %s && git rev-parse HEAD"' % folder).stdout
  branch = c.run('su - main -c "cd %s && git rev-parse --abbrev-ref HEAD"' % folder).stdout
  c.run('su - main -c "cd %s && git fetch --all && git reset --hard origin/%s"' % (folder, branch))
  refreshHash = c.run('su - main -c "cd %s && git rev-parse HEAD"' % folder).stdout
  if force or startHash != refreshHash:
    c.run('su - main -c "cd %s && npm ci"' % folder)
    c.run('su - main -c "cd %s && npm run prestart"' % folder)
    node_restart(c, application)

  return force or startHash != refreshHash


def node_restart(c, application):
  app_folder = get_application_folder(application)
  c.run('su - main -c "pm2 startOrReload %s/pm2_config.yaml --update-env"' % app_folder)


def get_venv_path_name(application):
  return "/home/main/%s/venv" % application.get('name')


def get_openfisca_service_name(application):
  return "%s_openfisca" % application.get('name')


def openfisca_reload(c, application):
  service_name = get_openfisca_service_name(application)
  result = c.run('service %s reload' % service_name, warn=True)
  if result.exited:
    c.run('service %s start' % service_name)


def openfisca_setup(c, application):
  venv_dir = get_venv_path_name(application)
  repo_folder = get_repository_folder(application)
  service_name = get_openfisca_service_name(application)
  c.run('su - main -c "python3.7 -m venv %s"' % venv_dir)
  with write_template('files/openfisca.service.template', {
      'application': application,
      'openfisca_worker_number': application.get('openfisca_worker_number', 3),
      'repo_folder': repo_folder,
      'venv_dir': venv_dir
    }) as fp:
    c.put(fp, '/etc/systemd/system/%s.service' % service_name)
  c.run('systemctl daemon-reload')
  openfisca_reload(c, application)
  c.run('systemctl enable %s' % service_name)


def openfisca_refresh(c, application):
  repo_folder = get_repository_folder(application)
  venv_dir = get_venv_path_name(application)
  c.run('su - main -c "%s/bin/pip3 install --upgrade pip"' % venv_dir)
  c.run('su - main -c "cd %s && %s/bin/pip3 install --upgrade -r openfisca/requirements.txt"' % (repo_folder, venv_dir))
  openfisca_reload(c, application)
