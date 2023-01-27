# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
	# image for virtualbox on a x64 machine
  config.vm.box = "debian/buster64"
	# image for parallels (arm64 machine)
  #config.vm.box = "bento/debian-11.2-arm64"
	#config.vm.box_version = "202112.19.0"
	#
	# image for vmware (arm64 machine)
	#config.vm.box = "bytesguy/debian-11-arm64"
	config.vm.box_version = "1.0.0"
  # Guest have 500MB of RAM by default
	# That is not enough to `npm ci`
  # Upgrading to 4GB
  config.vm.provider :virtualbox do |vb|
    vb.memory = 4000
  end
	config.vm.provider :vmware_desktop do |vmware|
		vmware.memory = 4000
		# gui is required on vmware on mac M1/M2
		vmware.gui = true
		#vmware.vmx["ethernet0.pcislotnumber"] = "33"
		vmware.vmx["memsize"] = "1024"
		vmware.vmx["numvcpus"] = "1"
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
  ssh_pub_key = File.read("#{ENV['HOME']}/.ssh/github_auth.pub").split("\n")[0]
  config.vm.provision "shell", inline: "sudo su -c \"mkdir --parents /root/.ssh && echo {ssh_pub_key}-for-vagrant > /root/.ssh/authorized_keys\""
end
