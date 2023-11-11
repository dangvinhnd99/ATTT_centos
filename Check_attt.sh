echo "_________   ___ ______________________  ____  __.    ____________________________________    _____     _________"
echo "\_   ___ \ /   |   \_   _____\_   ___ \|    |/ _|   /  _  \__    ___\__    ___\__    ___/   /      \  /   _____/"
echo "/    \  \//    ~    |    __)_/    \  \/|      <    /  /_\  \|    |    |    |    |    |     /   ()   \ \_____  \ "
echo "\     \___\    Y    |        \     \___|    |  \  /    |    |    |    |    |    |    |    /          \/        \ "
echo " \______  /\___|_  /_______  /\______  |____|__ \ \____|__  |____|    |____|    |____|    \__________/_______  /"
echo "        \/       \/        \/        \/        \/         \/                                                 \/"
echo ""

echo "================================================================================"
echo "----------------------------- CHECK KERNEL -------------------------------------"
echo "================================================================================"
echo ""

check=`uname -msr`
echo -e "Current Kernel is: \n$check"
echo ""

echo "================================================================================"
echo "------------------------- CHECK APPLICATION's DRIVE ----------------------------"
echo "================================================================================"
echo ""

check=`cat /etc/fstab | grep -vw "#\|/\|/var\|/dev/shm\|/home\|/usr\|/proc\|/sys\|/dev/pts\|/opt\|swap\|/boot\|/boot/efi"`
if [[ -z $check ]]
    then 
        echo "Not found applcation's drive (/u01...) in /etc/fstab ==> WARNING"
    else
        echo "Found applcation's drive (/u01...) in /etc/fstab ==> OK"
fi
echo ""

echo "================================================================================"
echo "----------------------------- CHECK SUDO ACCOUNTS ------------------------------"
echo "================================================================================"
echo ""

standard=`echo -e "%wheel\tALL=(ALL)\tALL"`
check1=`cat /etc/sudoers | grep -v ^# | grep "$standard"`
if [[ -z $check1 ]]
    then 
        echo "In /etc/sudoers is not exist: $standard ==> OK"
    else 
        echo -e "In /etc/sudoers is exist: $check1  ==> WARNING"
fi

standard=`echo -e "ALL=(ALL)\tALL"`
list=`cat /etc/passwd |grep /*sh$  | grep -v ^# | grep -v nfsnobody | awk -F: '($3>=400) {print $1}'`
for i in $list
    do 
        check2=`cat /etc/sudoers | grep -v ^# | grep -w "$i" | grep "$standard"`
        if [[ -z $check2 ]]
            then 
                echo -e "In /etc/sudoers is not exist: $i\t$standard ==> OK"
            else 
                echo -e "In /etc/sudoers is exist: $check2  ==> WARNING"
    fi
done
echo ""

list=`cat /etc/passwd |grep /*sh$  | grep -v ^# | grep -v nfsnobody | awk -F: '($3>=500) {print $1}'`
for user in $list
    do 
        check3=`sudo -l -U $user| cut -f 4,5 -d ' '`
            if [[ $check3 == "not allowed" ]]
                then 
                    echo "$user does not have any sudo privilege  ==> OK"
                else 
                    echo "$user has some sudo privilege ==> WARNING"
            fi
done
echo ""

dir="/etc/pam.d/su"
check4=`cat $dir | grep -v ^# | grep -w auth | grep -w required | grep -w "pam_wheel.so"`
if [[ -z $check4 ]]
    then 
        echo "Not configured only group wheel can su root  ==> WARNING"
    else
        echo "Configured only group wheel can su root ==> OK"
fi
echo ""

echo "================================================================================"
echo "----------------------- CHECK SERVICES RUNNING AS ROOT--------------------------"
echo "================================================================================"
echo ""

check=`ps -ef | grep ^root | grep "java\|tomcat\|jre\|jdk" | grep -v grep`
if [[ -z $check ]]
    then
        echo "Do not have services (java|tomcat|jre|jdk) running as root ==> OK"
    else 
        echo -e "Services (java|tomcat|jre|jdk) running as root\n $check \n==> WARNING"
fi
echo ""

echo "================================================================================"
echo "--------------------------- CHECK PASSWORD POLICIES-----------------------------"
echo "================================================================================"
echo ""

check1=`cat /etc/login.defs | grep -v ^# | grep PASS_MAX_DAYS | awk '{print$2}'`
if [[ $check1 -gt "90" ]]
    then 
        echo "PASS_MAX_DAYS 90 is not configured  ==> WARNING"
    else 
        echo "PASS_MAX_DAYS 90 is configured ==> OK"
fi
echo ""

list=`cat /etc/passwd |grep /*sh$  | grep -v ^# | grep -v nfsnobody | grep -v vt_admin | grep -v monitor | awk -F: '($3>=500) {print $1}'`
for user in $list
    do 
        check2=`chage -l $user | grep "Password expires" |  awk '{print $4}'`
        if [[ $check2 = "never" ]]
            then 
                echo "$user: Password expires: $check2 ==> WARNING"
            else 
                echo "$user: Password expires: $check2 ==> OK"
        fi
done
echo ""

check3=`cat /etc/pam.d/system-auth 2>/dev/null | grep -v ^# | grep -w password | grep -w "retry=3" | grep -w "minlen=8" | grep -w "dcredit=-1" | grep -w "ucredit=-1" | grep -w "ocredit=-1" | grep -w "lcredit=-1"`
check4=`cat /etc/pam.d/common-password 2>/dev/null | grep -v ^# | grep -w password | grep -w "retry=3" | grep -w "minlen=8" | grep -w "dcredit=-1" | grep -w "ucredit=-1" | grep -w "ocredit=-1" | grep -w "lcredit=-1"`
if [[ -z $check3 ]] && [[ -z $check4 ]]
    then
        echo "Strong password polices is not configured (requirement: minlen 8,dcredit=-1,ucredit=-1,lcredit=-1,ocredit=-1 ) ==> WARNING"
    else 
        echo -e "Strong password polices is configured ==> OK"
fi
echo ""

check5=`cat /etc/pam.d/system-auth 2>/dev/null | grep -v ^# | grep -w password | grep -w sha512 | grep -w "remember=5"`
check6=`cat /etc/pam.d/common-password 2>/dev/null | grep -v ^# | grep -w password | grep -w "remember=5"`
if [[ -z $check5 ]] && [[ -z $check6 ]]
    then 
        echo "Enforce Pasword History is not configured (requirement: remember=5) ==> WARNING"
    else 
        echo -e "Enforce Pasword History is configured ==> OK"
fi
echo ""

check7=`cat /etc/login.defs |  grep -v ^# | grep ENCRYPT_METHOD | grep  SHA512 | awk '{print$2}'`
if [[ -z $check7 ]]
    then 
        echo "Password hashing algorithm is not configured sha512 ==> WARNING"
    else 
        echo -e "Password hashing algorithm is configured sha512 ==> OK"
fi
echo ""

echo "================================================================================"
echo "------------------------- CHECK UNECESSARIES SERVICES---------------------------"
echo "================================================================================"
echo ""

check1=`systemctl status bluetooth 2>/dev/null | grep "running"`
if [[ -z $check1 ]]
    then 
        echo "Bluetooth service is not running ==> OK"
    else 
        echo -e "Bluetooth service is running ==> WARNING"
fi

check2=`systemctl status cups 2>/dev/null | grep "running"`
if [[ -z $check2 ]]
    then 
        echo "Cups service is not running ==> OK"
    else 
        echo -e "Cups service is running ==> WARNING"
fi
echo ""

echo "================================================================================"
echo "---------------------------- CHECK SSH CONFIGURATIONS---------------------------"
echo "================================================================================"
echo ""

check1=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w "Protocol 2"`
if [[ -z $check1 ]]
    then 
        echo "Protocol 2 is not configured ==> WARNING"
    else 
        echo -e "Protocol 2 is configured ==> OK"
fi
echo ""

check2=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w "PermitRootLogin no"`
if [[ -z $check2 ]]
    then 
        echo "PermitRootLogin no is not configured ==> WARNING"
    else 
        echo -e "PermitRootLogin no is configured==> OK"
fi
echo ""

check3=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w AllowUsers`
if [[ -z $check3 ]]
    then 
        echo "AllowUsers is not configured ==> WARNING"
    else 
        echo "$check3 is configured to ssh ==> OK"
fi
echo ""

check4=`cat /etc/profile | grep -v ^# | grep -w "TMOUT=300" -A 2 | grep -w "readonly TMOUT" -A 1 | grep -w "export TMOUT"`
if [[ -z $check4 ]]
    then 
        echo -e "TMOUT in /etc/profile is not configured: \nTMOUT=300 \nreadonly TMOUT \nexport TMOUT  ==> WARNING"
    else 
        echo -e "TMOUT in /etc/profile is configured: \nTMOUT=300 \nreadonly TMOUT \nexport TMOUT ==> OK"
fi
echo ""

echo "================================================================================"
echo "-------------------------- CHECK USER SH/BASH PRIVILIEGE------------------------"
echo "================================================================================"
echo ""

# list=`cat /etc/passwd |grep /*sh$  | grep -v ^# | grep -v nfsnobody | awk -F: '($3>=500) {print $1}'`
# for user in $list
# do check=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w AllowUsers | grep -w $user`
# if [[ $check == *$user* ]]
# then echo "$user ==> OK"
# else echo "$user ==>WARNING"
# fi
# done
# echo ""
cat /etc/passwd |grep /*sh$  | grep -v ^# | grep -v nfsnobody 
echo ""

variable="/etc/profile"
check1=`cat $variable | grep -v ^# | grep -wi "umask" | grep "022"`
if [[ -z $check1 ]]
    then 
        echo "$variable is not configured umask 022 ==> WARNING"
    else 
        echo "$variable: $check1 ==> OK"
fi
echo ""

check2=`cat /etc/bashrc 2>/dev/null | grep -v ^# | grep -wi "umask" | grep "022"`
check3=`cat /etc/bash.bashrc 2>/dev/null | grep -v ^# | grep -wi "umask" | grep "022"`
if [[ -z $check2 ]] || [[ -z $check3 ]]
    then 
        echo "/etc/bashrc or /etc/bash.bashrc is not configured umask 022 ==> WARNING"
    else 
        echo "/etc/bashrc or /etc/bash.bashrc: $check2 ==> OK"
fi
echo ""
#---------------------------------
# echo -e "\nResult:"
# list=`ls /etc/profile.d`
# for i in $list
# do check=`cat /etc/profile.d/$i | grep -v ^# | grep -wi "umask" | grep "022"`
# if [[ -z $check ]]
# then echo "$i ==> WARNING"
# else echo "$i: $check ==> OK"
# fi
# done
# echo ""

echo "================================================================================"
echo "------------------------------- CHECK UNOWNER FILE------------------------------"
echo "================================================================================"
echo ""

check=`find / -xdev \( -nouser -o -nogroup \) -print`
if [[ -z $check ]]
    then 
        echo "Do not exist unowner file ==> OK"
    else 
        echo -e "Exist unowner file ==> WARNING \n$check"
fi
echo ""

echo "================================================================================"
echo "------------------------------ CHECK DANGEROUS PATH ----------------------------"
echo "================================================================================"
echo ""

check=`echo $PATH | grep "\./\|::\|/tmp"`
if [[ -z $check ]]
    then 
        echo -e "Do not exist dangerous \$PATH : \n$PATH ==> OK"
    else 
        echo -e "Exist dangerous \$PATH nguy hiem (./  ::  /tmp):\n$PATH ==> WARNING"
fi
echo ""

echo "================================================================================"
echo "---------------------------- CHECK CRON CONFIGURATIONS -------------------------"
echo "================================================================================"
echo ""

check1=`ls /etc/ | grep cron.deny`
if [[ -z $check1 ]]
    then 
        echo "/etc/cron.deny is removed ==> OK"
    else 
        echo "/etc/cron.deny is not removed ==> WARNING"
fi
echo ""

check2=`ls /etc/ | grep cron.allow`
if [[ -z $check2 ]]
    then 
        echo "/etc/cron.allow is not created ==> WARNING"
    else 
        echo "/etc/cron.allow is created  ==> OK"
fi
echo ""

array=("/etc/crontab" "/etc/cron.allow" "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.weekly")
for i in "${array[@]}"
    do 
        check3=`stat -c '%a' "$i" 2>/dev/null`
        if [[ $check3 -eq 600 ]] || [[ $check3 -eq 700 ]]
            then 
                echo "Da phan quyen dung cho: $i ==> OK "
            else
                echo "Chua phan quyen dung cho: $i ==> WARNING" 
        fi
done

check4=`crontab -l | grep -v ^# | grep -v ntpdate| grep -v sd_agent | grep -v backup`
check5=`crontab -l`
if [[ -z $check4 ]]
    then 
        echo "Minimum crontab is configured ==> OK"
    else 
        echo -e "Minimum crontab is not configured: ==> WARNING \n$check5"
fi
echo ""

echo "================================================================================"
echo "----------------------------- CHECK LOG CONFIGURATIONS -------------------------"
echo "================================================================================"
echo ""

array=("*.info;mail.none;authpriv.none;cron.none" "authpriv.*" "mail.*" "cron.*" "uucp,news.crit" "local7.*" "local6.*" "kern.debug" )
for i in "${array[@]}"
    do 
        check1=`cat /etc/rsyslog.conf | grep -v ^# | grep -v ^$ | grep "$i"`
        if [[ -z $check1 ]]
            then
                 echo "/etc/rsyslog.conf is not configured $i ==> WARNING"
            else 
                echo "/etc/rsyslog.conf is configured $i ==> OK"
        fi
done
echo "" 

check2=`cat /etc/bashrc 2>/dev/null | grep -v ^# |grep local6.debug`
check3=`cat /etc/bash.bashrc 2>/dev/null | grep -v ^# |grep local6.debug`
check4=`ls -la /var/log | grep cmdlog`
if [[ -z $check2 && -z $check4 ]] || [[ -z $check3 && -z $check4 ]]
    then 
        echo "Cmdlog is not configured ==> WARNING"
    else 
        echo "Cmdlog is configured ==> OK"
fi
echo ""

check5=`cat /etc/logrotate.conf | grep -w rotate | awk '($2 > 3){print$2}'`
check6=`head -2 /etc/logrotate.conf`
if [[ $check5 -eq "12" ]]
    then
        echo "/etc/logrotate.conf is configured ==> OK"
    else 
        echo -e "/etc/logrotate.conf is not configured ==> WARINING \n$check6"
fi
echo ""

echo "Check /etc/logrotate.d/syslog"
array=("/var/log/cron" "/var/log/maillog" "/var/log/messages" "/var/log/secure" "/var/log/spooler" "{" "compress" "sharedscripts" "postrotate" "/bin/kill -HUP \`cat /var/run/syslogd.pid 2> /dev/null\` 2> /dev/null || true"  "endscript" "}")
for i in "${array[@]}"
    do 
        check7=`cat /etc/logrotate.d/syslog | grep -v ^# | grep -w "$i"`
        if [[ $check7 == *$i* ]]
            then
                echo "$i ==> OK"
            else 
                echo "$i ==> WARNING"
        fi
done
echo ""

echo "================================================================================"
echo "---------------------------- CHECK VIETTEL NTP SERVER --------------------------"
echo "================================================================================"
echo ""

check1=`systemctl status ntpd 2>/dev/null | grep "running"`
if [[ -z $check1 ]]
    then echo "NTP service is not running ==> WARNING"
    else echo -e "NTP service is running ==> OK"
fi
echo ""

array=("server 192.168.181.50")
for i in "${array[@]}"
    do 
        check2=`cat /etc/ntp.conf 2>/dev/null | grep -v ^# | grep -w "$i"`
        if [[ $check2 == *$i* ]]
            then 
                echo "Viettel NTP Server is configured: ==> OK"
            else 
                echo "Viettel NTP Server is not configured: ==> WARNING"
        fi
done
echo ""

check3=`date +"%Z %z" | grep -w 0700`
if [[ $check3 == *0700* ]]
    then 
        echo "Timezone is configured +7 ==> OK"
    else 
        echo "Timezone is configured $check (requirement: +7)==> WARNING"
fi
echo ""

echo "================================================================================"
echo "------------------------------ CHECK SIRC VIETTEL -------------------------------"
echo "================================================================================"
echo ""

check=`/opt/se/salt-call vsm.status 2>/dev/null| grep 2017`
if [[ -z $check ]]
    then 
        echo "SIRC is not installed or running ==> WARNING"
    else 
        echo "SIRC is running ==> OK"
fi
echo ""

echo "================================================================================"
echo "-------------------------------- CHECK IPTABLES --------------------------------"
echo "================================================================================"
echo ""

check1=`service iptables status | grep "iptables is not running"`
if [[ -z $check1 ]]
    then 
        echo "Iptables services is running ==> OK"
    else 
        echo -e "Iptables services is not running ==> WARNING"
fi
echo ""

check2=`iptables-save | grep 'j LOG'`
check3=`ls /var/log/iptables/ 2>/dev/null | grep "iptables.log" `
if [[ -z $check2 ]] || [[ -z $check3 ]]
    then 
        echo "Iptables services does not have "-j LOG" rules ==> WARNING"
    else 
        echo "Iptables services has "-j LOG" rules ==> OK"
fi
echo ""

check4=`iptables-save | grep 'INPUT -j DROP\| INPUT -j REJECT'`
check5=`iptables-save | grep 'OUTPUT -j DROP\| OUTPUT -j REJECT'`
if [[ -z $check4 ]] || [[ -z $check5 ]]
    then 
        echo "Iptables services does not have "drop or reject all" rules ==> WARNING"
    else 
        echo "Iptables services has "drop or reject all" rules ==> OK"
fi

echo ""
echo "================================================================================"
echo "-------------------------------- CHECK DOCKER ----------------------------------"
echo "================================================================================"
echo ""

echo "Check Docker version"
check0=`docker -v 2>/dev/null`
if [[ -z $check0 ]]
    then
        echo -e "Docker is not installed\n"
    else
        echo -e "$check0\n"

        echo "Check users in group Docker"
        getent group docker
        echo ""

        echo "Check Docker daemon.json"
        check1=`cat /etc/docker/daemon.json 2>/dev/null`
        if [[ -z $check1 ]]
            then
                echo -e "/etc/docker/daemon.json is not exist !\n"
            else
                echo -e "$check1\n"
        fi
        echo ""

        echo "Check Dockerfile"
        check2=`find / -iname '*Dockerfile*' -type f 2>/dev/null`
        if [[ -z $check2 ]]
            then   
                echo -e "Dockerfile is not exist !\n"
            else
                echo "$check2"
        fi
        echo ""

        echo "Check running containers"
        check3=$(docker ps --format "{{.Names}}" 2>/dev/null | wc -l)
        check4=`docker ps --no-trunc`
        if [ $check3 -eq 0 ]
            then
                echo -e "Container is not running !\n" 
            else
                echo -e "$check4\n"
        fi
        echo ""

        echo "List all docker networks"
        docker network ls --quiet | xargs docker network inspect --format '{{ .Name}}: {{ .Options }}'
        echo ""

        echo "Check docker network: Inter Container Connectivity"
        check5=`docker network ls --quiet | xargs docker network inspect --format '{{ .Name}}: {{ .Options }}' | grep -w "com.docker.network.bridge.enable_icc:true"`
        if [[ -z $check5 ]]
            then
                echo "icc configuration of default bridge network configuration is false ==> OK\n"
            else
                echo "icc configuration of default bridge network configuration is true ==> WARNING"
                echo -e "Suggest: Use user-defined network\n"
        fi
        echo ""

        echo "Check docker host network" 
        check6=`docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}' | grep "NetworkMode=host"`
        if [[ -z $check6 ]]
            then
                echo -e "Do not have Docker host network ==> OK\n"
            else
                echo "$check5 ==> WARNING"
                echo -e "Suggest: Don't use docker host network for production environment !\n"
        fi
        echo ""

        echo "Check --device option mount" 
        check7=`docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}:Devices={{ .HostConfig.Devices }}'`
        echo "Sure that all output have Devices=[]"
        echo -e "$check7\n"
        # if [[ -z $check7 ]]
        #     then
        #         echo "Do not have containers that are run with --device option mount ==> OK"
        #     else
        #         echo "$check6 ==> WARNING"
        #         echo "Suggest: Don't use --device option mount !"
        # fi
fi

echo ""
echo "================================================================================"
echo "------------------------- CHECK VULNERABILITIES --------------------------------"
echo "================================================================================"
echo ""

#CVE-2021-4034 --> Check bang cach xem last modify cua packages :v
echo "Check CVE-2021-4034 (pkexec - polkit) !"
if [ `command -v pkexec` ] && stat -c '%a' $(which pkexec) | grep -q 4755 && [ "$(stat -c '%Y' $(which pkexec))" -lt "1642035600" ]
    then
        echo "Vulnerable to CVE-2021-4034 ==> WARINING"
        echo "Solution: run chmod u-s $(which pkexec) or upgrage polkit package !"
    else
        echo "Not Vulnerable ==> OK"
fi
echo ""

#sudo token Privilege Escalation
echo "Check sudo token Privilege Escalation !"
ptrace_scope="$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)"
is_gdb="$(command -v gdb 2>/dev/null)"
if [ "$ptrace_scope" ] && [ "$ptrace_scope" -eq 0 ] && [ "$is_gdb" ]
    then
        for pid in $(pgrep '^(ash|ksh|csh|dash|bash|zsh|tcsh|sh)$' -u "$(id -u)" 2>/dev/null | grep -v "^$$\$")
            do
                # echo "Injecting process $pid -> "$(cat "/proc/$pid/comm" 2>/dev/null)
                echo 'call system("echo | sudo -S touch /tmp/shrndom32r2r >/dev/null 2>&1 && echo | sudo -S chmod 777 /tmp/shrndom32r2r >/dev/null 2>&1")' | gdb -q -n -p "$pid" >/dev/null 2>&1
            if [ -f "/tmp/shrndom32r2r" ]
                then
                    echo "Sudo token reuse exploit worked with pid:$pid, Vulnerable ==> WARINING !"
                    echo "Solution: run sysctl kernel.yama.ptrace_scope=1 "
                    break
            fi
        done
        if [ -f "/tmp/shrndom32r2r" ]
            then
                rm -f /tmp/shrndom32r2r 2>/dev/null
            else 
                echo "Not Vulnerable ==> OK"
        fi
    else
        echo  "Not Vulnerable ==> OK"
fi
echo ""

#CVE-2021-3156 - sudo Privilege Escalation ( heap-based buffer overflow)
echo "Check CVE-2021-3156 (sudo buffer overflow) !"
check=`/usr/bin/sudoedit -s / 2>&1  | grep "not a regular file"`
if [[ -z $check ]]
    then
        echo "Not Vulnerable ==> OK"
    else
        echo "Vulnerable to CVE-2021-3156 ==> WARINING"
        echo "Solution: upgrade sudo packages !"
fi
echo ""

#USBCreator
echo "Check CVE-2015-3643 (USBCreator) !"
if (busctl list 2>/dev/null | grep -q com.ubuntu.USBCreator)
    then
        pc_version=$(dpkg -l 2>/dev/null | grep policykit-desktop-privileges | grep -oP "[0-9][0-9a-zA-Z\.]+")
        if [ -z "$pc_version" ]
            then
                pc_version=$(apt-cache policy policykit-desktop-privileges 2>/dev/null | grep -oP "\*\*\*.*" | cut -d" " -f2)
        fi
        if [ -n "$pc_version" ]
            then
            pc_length=${#pc_version}
            pc_major=$(echo "$pc_version" | cut -d. -f1)
            pc_minor=$(echo "$pc_version" | cut -d. -f2)
            if [ "$pc_length" -eq 4 ] && [ "$pc_major" -eq 0 ] && [ "$pc_minor"  -lt 21 ]
                then
                    echo "Vulnerable to CVE-2015-3643 ==> WARINING"
                    echo "Solution: upgrade policykit-desktop-privileges packages !"
                else
                    echo "Not Vulnerable ==> OK"
            fi
        fi
    else
        echo "USBCreator is not installed ==> OK"
fi
echo ""

echo "================================================================================"
echo "-------------------------------- CHECK OTHERS ----------------------------------"
echo "================================================================================"
echo ""

echo "CHECK OPENSSL VERSION" 
check=`openssl version`
echo -e "Current Version: $check"
array=("1.0.2k-19")
variable="WARNING"
for i in "${array[@]}"
    do 
        check=`openssl version -a | grep "$i"`
        if [[ ! -z $check ]]
        then 
            echo "$check ==> OK"
            variable="OK"
            break
        fi
done
if [[ $variable == WARNING ]]
    then 
        echo "Version OpenSSL is not in whitelist ($array) ==> $variable"
fi
echo ""

echo "================================================================================"
echo "------------------------------- IPTABLES RULES ---------------------------------"
echo "================================================================================"
echo ""
iptables-save