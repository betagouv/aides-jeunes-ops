FROM debian:11.6
ENV container docker

RUN apt-get update -y && apt-get dist-upgrade -y
RUN apt-get install -y --no-install-recommends ssh sudo wget curl cron software-properties-common build-essential libffi-dev systemd openssh-client net-tools

#RUN apt-get -y install puppet

# Add vagrant user and key for SSH
RUN useradd --create-home -s /bin/bash vagrant
RUN echo -n 'vagrant:vagrant' | chpasswd
RUN echo 'vagrant ALL = NOPASSWD: ALL' > /etc/sudoers.d/vagrant
RUN chmod 440 /etc/sudoers.d/vagrant
RUN mkdir -p /home/vagrant/.ssh
RUN chmod 700 /home/vagrant/.ssh
RUN curl https://raw.githubusercontent.com/hashicorp/vagrant/5b501a3fb05ed0ab16cf10991b3df9d231edb5cf/keys/vagrant.pub >> /home/vagrant/.ssh/authorized_keys
RUN chmod 600 /home/vagrant/.ssh/authorized_keys
RUN chown -R vagrant:vagrant /home/vagrant/.ssh
RUN sed -i -e 's/Defaults.*requiretty/#&/' /etc/sudoers
RUN sed -i -e 's/\(UsePAM \)yes/\1 no/' /etc/ssh/sshd_config

# Start SSH
RUN mkdir /var/run/sshd
EXPOSE 22
RUN /usr/sbin/sshd

# Start Systemd (systemctl)
#CMD ["/lib/systemd/systemd"]
CMD ["/usr/sbin/sshd", "-D"]
