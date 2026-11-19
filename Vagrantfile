# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2004"
  config.vm.hostname = "cis-hardened"

  config.vm.provider :libvirt do |lv|
    lv.memory = "2048"
    lv.cpus = 2
    lv.title = "cis-hardened"
  end
end