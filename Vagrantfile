# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/buster64"

  # Guest have 500MB of RAM by default
  # That is not enough to `npm ci`
  # Upgrading to 3GB
  config.vm.provider :virtualbox do |vb|
    vb.memory = 3072
  end

  # Faster startup
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # Allow development on various version relatively simply
  suffix = "vagrant"
  current_private_ip = "192.168.56.200"

  puts "This instance will be reachable at #{current_private_ip}"
  config.vm.define "mes_aides_#{suffix}"
  config.vm.network "private_network", ip: current_private_ip

  # Replicate OVH initial provisioning
  ssh_pub_key = File.read("#{ENV['HOME']}/.ssh/id_rsa.pub").split("\n")[0]
  config.vm.provision "shell", inline: "sudo su -c \"mkdir --parents /root/.ssh && echo #{ssh_pub_key}-for-vagrant > /root/.ssh/authorized_keys\""
end
