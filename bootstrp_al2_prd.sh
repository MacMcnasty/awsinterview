#!/bin/bash
SW_SERVER="us09stgmgta1"
SW_ACT_KEY="504103a6558043ee229bdb4591f8bc01"
yum update -y
yum install -y usermod python-ethtool m2crypto pyOpenSSL python-hwdata python-dmidecode python-gudev
if [[ -f /etc/pki/ca-trust/source/anchors/ca.crt ]]; then
    :
else
    curl -o ca.crt http://crl.vmwarefedstg.com/crl/ca.crt
    update-ca-trust force-enable
    mv -f ca.crt /etc/pki/ca-trust/source/anchors
    update-ca-trust extract
fi
rpm --import http://packages.wazuh.com/key/GPG-KEY-WAZUH
rpm -Uvh https://copr-be.cloud.fedoraproject.org/results/@spacewalkproject/spacewalk-2.8-client/epel-7-x86_64/00742644-spacewalk-repo/spacewalk-client-repo-2.8-11.el7.centos.noarch.rpm
rpm -Uvh http://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum -y install rhn-client-tools rhn-check rhn-setup rhnsd m2crypto yum-rhn-plugin rhncfg* osad
sed -i "s@^serverURL\=https\:\/\/.*\/XMLRPC@serverURL\=https\:\/\/$SW_SERVER\/XMLRPC@" /etc/sysconfig/rhn/up2date
rhnreg_ks --serverUrl=https://us09stgmgta1/XMLRPC --sslCACert=/etc/pki/ca-trust/source/anchors/ca.crt --activationkey=1-504103a6558043ee229bdb4591f8bc01 --force
rpm -e spacewalk-client-repo
rpm -e epel-release
systemctl enable osad
systemctl start osad
rhn-actions-control --enable-all
printf "[main]\nenabled=1\nverbose=0\nalways_print_best_host = true\nsocket_timeout=3\nhostfilepath=timedhosts.txt\nmaxhostfileage=10\nmaxthreads=15" > /etc/yum/pluginconf.d/fastestmirror.conf
systemctl enable wazuh-agent
systemctl start wazuh-agent
/var/ossec/bin/agent-auth -m us10stgloga2 -p 55000
rhncfg-client get
sleep 10
systemctl restart wazuh-agent
service auditd restart
tar -zcvf /opt/repos_back.tgz /etc/yum.repos.d
rm -rf /etc/yum.repos.d/*
systemctl restart osad
