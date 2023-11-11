echo "___________._______  ___    ______________________________________    _____    _________"
echo "\_   _____/|   \   \/  /   /  _  \__    ___/\__    ___/\__    ___/   /     \  /   _____/ "
echo " |    __)  |   |\     /   /  /_\  \|    |     |    |     |    |     /   ()  \ \_____  \ "
echo " |     \   |   |/     \  /    |    \    |     |    |     |    |    /         \/        \ "
echo " \___  /   |___/___/\  \ \____|__  /____|     |____|     |____|    \_________/_______  / "
echo "     \/              \_/         \/                                                  \/ "
echo "                                                                -- Fix ATTT CentOS --- "

echo ""
echo "================================================================================"
echo "----------------------------- CHECK KERNEL -------------------------------------"
echo "================================================================================"
echo "" 



echo ""
echo "================================================================================"
echo "----------------------------- CREATE USER ADMIN --------------------------------"
echo "================================================================================"
echo "" 
useradd vt_admin
echo -e 'Vts@2023\nVts@2023' | passwd vt_admin




echo "Please manually fix CentOS's kernel version !"

echo ""
echo "================================================================================"
echo "---------------------------- REMOVE SUDO PRIVILLEGE ----------------------------"
echo "================================================================================"
echo ""


#  xóa dấu # ở phần giới hạn quyền chỉ có user trong group wheel mới có quyền su root. cấu hình ở trong file "/etc/pam.d/su"    bỏ thăng dòng này: auth    required     pam_wheel.so use_uid 

if grep -q '^#auth\s\+required\s\+pam_wheel.so\s\+use_uid' /etc/pam.d/su; then
  sed -i '/^#auth\s\+required\s\+pam_wheel.so\s\+use_uid/s/^#//' /etc/pam.d/su
  echo "Configuration updated."
else
  echo "Configuration is already set."
fi

# xóa dấu # ở phần wheel (allows people in group wheel to run all command), 
# sau đó thêm rule no password vào để có quyền sudo trace




# new_rule="%wheel  ALL=(root) NOPASSWD: /usr/bin/tcptraceroute, /bin/traceroute, /usr/sbin/iotop"


# new_command="your_command_here"


# sudoers_file="/etc/sudoers"


# if grep -q "$new_rule" "$sudoers_file"; then
#     echo "Quy tắc đã tồn tại. Nothing to do."
# else
#     echo "$new_command" | sudo tee -a "$sudoers_file" > /dev/null
#     echo "$new_rule" | sudo tee -a "$sudoers_file" > /dev/null
#     echo "da add them rule"
# fi





standard=`echo -e "%wheel\tALL=(ALL)\tALL"`
check1=`cat /etc/sudoers | grep -v ^# | grep "$standard"`
if [[ -z $check1 ]]
    then echo "Nothing to do !"
    else 
    sed -i "s/$check/#$check/g" /etc/sudoers
    echo "Users in group Wheel are removed sudo privillege !"
fi

standard=`echo -e "%wheel\tALL=(ALL)\tNOPASSWD: ALL"`
check2=`cat /etc/sudoers | grep -v ^# | grep "$standard"`
if [[ -z $check2 ]]
    then echo "Nothing to do !"
    else 
    sed -i "s/$check/#$check/g" /etc/sudoers
    echo "Users in group Wheel are removed sudo privillege !"
fi

standard=`echo -e "ALL=(ALL)\tALL"`
list=`cat /etc/passwd |grep /bin/bash  | grep -v ^# | grep -v nfsnobody | awk -F: '($3>=400) {print $1}'`
for i in $list
    do check3=`cat /etc/sudoers | grep -v ^# | grep -w "$i" | grep "$standard"`
        if [[ -z $check3 ]]
            then 
                echo "Nothing to do !"
            else 
                sed -i "s/$check3/#$check3/g" /etc/sudoers
                echo "User $i are removed sudo privillege !"
        fi
done

list=`cat /etc/passwd |grep /bin/bash  | grep -v ^# | grep -v nfsnobody | awk -F: '($3>=400) {print $1}'`
for i in $list
    do check4=`cat /etc/sudoers | grep -v ^# | grep -w "$i" | grep "NOPASSWD: ALL"`
    usermod -aG wheel $i
        if [[ -z $check4 ]]
            then 
                echo "Nothing to do !"
            else 
                sed -i "s/$i/#$i/g" /etc/sudoers
                echo "User $i are removed sudo privillege !"
        fi
done

# dir="/etc/pam.d/su"
# check5=`cat $dir | grep -v ^# | grep -w auth | grep -w required | grep -w "pam_wheel.so"`
# if [[ -z $check5 ]]
#     then 
#         echo -e "auth\trequired\tpam_wheel.so\tuse_uid" >>  $dir
#         echo "Configured user of group Wheel can su root!"
#     else
#         echo "Nothing to do !"
# fi

echo ""
echo "================================================================================"
echo "--------------------------- CONFIG STRONG PASSWORD -----------------------------"
echo "================================================================================"
echo ""

dir="/etc/pam.d/system-auth"
check1=`cat $dir | grep -v ^# | grep -w "pam_pwquality.so" | grep -w "retry=3" | grep -w "minlen=8" | grep -w "dcredit=-1" | grep -w "ucredit=-1" | grep -w "ocredit=-1" | grep -w "lcredit=-1"`
check2=`cat $dir | grep -v ^# | grep -w "pam_pwquality.so"`
if [[ -z $check1 ]]
    then  
        if [[ -z $check2 ]]
            then
                echo -e "password\trequisite\tpam_pwquality.so\ttry_first_pass\tlocal_users_only\tretry=3\tminlen=8\tdcredit=-1\tucredit=-1\tocredit=-1\tlcredit=-1\tauthtok_type=" >> $dir
            else
                sed -i "s/pam_pwquality.so try_first_pass local_users_only retry=3/pam_pwquality.so try_first_pass local_users_only retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/g" $dir
                echo "Configured strong password (retry=3 minlen=8 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1) !"
        fi 
    else 
        echo -e "Nothing to do !"
fi

check3=`cat $dir | grep -v ^# | grep ^password | grep -w sufficient | grep -w pam_unix.so | grep remember`
check4=`cat $dir | grep -v ^# | grep ^password | grep -w sufficient | grep -w pam_unix.so`
if [[ -z $check3 ]]
    then  
        if [[ -z $check4 ]]
            then
                echo -e "password\tsufficient\tpam_unix.so\tsha512\tshadow\tnullok\ttry_first_pass\tuse_authtok\tremember=5" >> $dir
            else
                sed -i "s/use_authtok/use_authtok remember=5/g" $dir
                echo "Configured remember=5 !"
        fi 
    else 
        echo -e "Nothing to do !"
fi

list=`cat /etc/passwd |grep /bin/bash  | grep -v ^# | grep -v nfsnobody | grep -v monitor| grep -v vt_admin | awk -F: '($3>=400) {print $1}'`
for i in $list
    do check5=`chage -l $i | grep "Maximum" | awk '{print$9}'`
    if [[ $check5 -gt 90  ]]
        then 
            chage -M 90 $i 
            echo "PASS_MAX_DAYS of user $i is set maximum 90 days !"
        else
            echo "Nothing to do !"
    fi
done

check6=`cat /etc/login.defs |grep -v ^#|  grep PASS_MAX_DAYS | awk '{print$2}' `
if [[ -z $check6 ]]
    then  
        echo -e "PASS_MAX_DAYS\t90" >> /etc/login.defs
        echo "Configured PASS_MAX_DAYS 90"
fi
if [[ $check6 -gt 90 ]]
    then
        sed -i "s/PASS_MAX_DAYS/#PASS_MAX_DAYS/g" /etc/login.defs
        echo -e "PASS_MAX_DAYS\t90" >> /etc/login.defs
        echo "Configured PASS_MAX_DAYS 90"
fi 

check7=`authconfig --test | grep hashing | grep sha512`
if [[ -z $check7 ]]
    then 
        authconfig --passalgo=sha512 --update
        echo "Configured password hashing algorithm that is sha512 !"
    else
        echo "Nothing to do !"
fi

echo ""
echo "================================================================================"
echo "-------------------- STOP AND DISABLE DEFAULT UNECESSARIES SERVICES ------------"
echo "================================================================================"
echo ""

check1=`systemctl status bluetooth 2>/dev/null | grep "running"`
if [[ -z $check1 ]]
    then 
        echo "Nothing to do !"
    else 
        systemctl stop bluetooth
        systemctl disable bluetooth
        echo "Stopped bluetooth !"
fi

check2=`systemctl status cups 2>/dev/null | grep "running"`
if [[ -z $check2 ]]
    then 
        echo "Nothing to do !"
    else 
        systemctl stop cups
        systemctl disable cups
        echo "Stopped cups !"
fi

echo ""
echo "================================================================================"
echo "----------------------------- SSH CONFIGURATIONS -------------------------------"
echo "================================================================================"
echo ""

check1=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w "Protocol"`
if [[ -z $check1 ]]
    then 
        echo "Protocol 2" >> /etc/ssh/sshd_config
    else
        echo "Nothing to do !"
fi

check2=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w "PermitRootLogin"`
check3=`cat /etc/ssh/sshd_config  |grep -v ^# |  grep PermitRootLogin | awk '{print$2}'`
if [[ -z $check2 ]]
    then 
        echo "PermitRootLogin no" >> /etc/ssh/sshd_config

elif [[ $check3 == "yes" ]]
    then
        sed -i "/s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
    else
        echo "Nothing to do !"
fi

check4=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w AllowUsers`
check5=`cat /etc/ssh/sshd_config | grep -v ^# | grep -w AllowUsers | grep -v ChrootDirectory | grep root `
check6=`cat /etc/ssh/sshd_config | grep -v ^#  | grep ChDirectory `
if [[ -z $check4 ]]
    then 
        list=`cat /etc/passwd |grep /bin/bash  | grep -v ^# | grep -v nfsnobody | grep /*sh$ |awk -F: '($3>=400) {print $1}'`
        for i in $list
            do 
                echo "AllowUsers $i" >> /etc/ssh/sshd_config
                echo "User $i is allowed to ssh"
        done
elif [[ -z $check5 ]]
    then
        echo "Nothing to do !"
    else
        sed -ie "s/root//g" /etc/ssh/sshd_config
fi

if [[ -z $check6 ]]
    then 
        echo ""
    else
        sed -i "s/ChDirectory/ChrootDirectory/g" /etc/ssh/sshd_config 
fi

echo ""
echo "================================================================================"
echo "----------------------------- TIMEOUT CONFIGURATIONS ---------------------------"
echo "================================================================================"
echo ""

dir="/etc/profile"
check1=`cat $dir | grep -v ^# | grep "TMOUT="`
check2=`cat $dir | grep -v ^# | grep "TMOUT=" | awk -F= '{print$2}'`
if [[ -z $check1 ]]
    then
        echo "TMOUT=300" >> $dir
    elif [[ $check2 -gt 300 ]]
        then
            sed -i "s/TMOUT=/#TMOUT=/g" $dir
            sed -i "s/readonly/#readonly/g" $dir
            sed -i "s/export/#export/g" $dir
            echo "TMOUT=300" >> $dir
            echo "readonly TMOUT" >> $dir
            echo "export TMOUT" >> $dir
            echo "Configured TMOUT=300 !"
        else
            echo "Nothing to do !"
fi

check3=`cat $dir | grep -v ^# | grep "readonly TMOUT"`
if [[ -z $check3 ]]
    then
        echo "readonly TMOUT" >> $dir
        echo "Configured "readonly TMOUT" !"
    else
        echo "Nothing to do !"
fi

check4=`cat $dir | grep -v ^# | grep "export TMOUT"`
if [[ -z $check4 ]]
    then
        echo "export TMOUT" >> $dir
        echo "Configured "export TMOUT" !"
    else
        echo "Nothing to do !"
fi

echo ""
echo "================================================================================"
echo "------------------------------- CRON CONFIGURATIONS ----------------------------"
echo "================================================================================"
echo ""

check1=`ls /etc/ | grep cron.deny`
if [[ -z $check1 ]]
    then 
        echo "Nothing to do !"
    else 
        rm -rf /etc/cron.deny
        echo "/etc/cron.deny is removed !"
fi

check2=`ls /etc/ | grep cron.allow`
if [[ -z $check2 ]]
    then 
        touch /etc/cron.allow
        echo "/etc/cron.allow is created !"
    else 
        echo "Nothing to do !"
fi

chown -R root:root /etc/cron*
chmod 600 /etc/crontab
chmod -R go-rwx /etc/cron*

echo ""
echo "================================================================================"
echo "-------------------------------- LOG CONFIGURATIONS ----------------------------"
echo "================================================================================"
echo ""

check1=`cat /etc/bashrc | grep -v ^# | grep "local6.debug"`
PROMPT_COMMAND='RETRN_VAL=$?;logger -p local6.debug "[cmdlog] $(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//" ) [$RETRN_VAL] [$(echo $SSH_CLIENT | cut -d" " -f1)]"'
if [[ -z $check1 ]]
    then
        echo "export PROMPT_COMMAND='"$PROMPT_COMMAND"'" >> /etc/bashrc
        echo "exported PROMPT_COMMAND to /etc/bashrc ! "
    else
        echo "Nothing to do !"
fi

dir="/etc/rsyslog.conf"
check2=`cat $dir | grep -v ^# |grep "*.info;mail.none;authpriv.none;cron.none" `
if [[ -z $check2 ]]
    then
        echo -e "*.info;mail.none;authpriv.none;cron.none\t/var/log/messages" >>  $dir
    else
        echo "Nothing to do !"
fi

check3=`cat $dir | grep -v ^# |grep "authpriv.*" | grep secure `
if [[ -z $check3 ]]
    then
        echo -e "authpriv.*\t/var/log/secure" >>  $dir
    else
        echo "Nothing to do !"
fi

check4=`cat $dir | grep -v ^# |grep "mail.*" | grep maillog `
if [[ -z $check4 ]]
    then
        echo -e "mail.*\t/var/log/maillog" >>  $dir
    else
        echo "Nothing to do !"
fi

check5=`cat $dir | grep -v ^# |grep "cron.*" | grep "/var/log/cron" `
if [[ -z $check5 ]]
    then
        echo -e "cron.*\t/var/log/cron" >>  $dir
    else
        echo "Nothing to do !"
fi

check6=`cat $dir | grep -v ^# |grep "*.emerg" `
if [[ -z $check6 ]]
    then
        echo -e "*.emerg\t:omusrmsg:*" >>  $dir
    else
        echo "Nothing to do !"
fi

check7=`cat $dir | grep -v ^# |grep "uucp,news.crit" | grep "spooler" `
if [[ -z $check7 ]]
    then
        echo -e "uucp,news.crit\t/var/log/spooler" >>  $dir
    else
        echo "Nothing to do !"
fi

check8=`cat $dir | grep -v ^# |grep "local7.*" | grep "boot.log" `
if [[ -z $check8 ]]
    then
        echo -e "local7.*\t/var/log/boot.log" >>  $dir
    else
        echo "Nothing to do !"
fi

check9=`cat $dir | grep -v ^# |grep "local6.*" | grep "cmdlog.log" `
if [[ -z $check9 ]]
    then
        echo -e "local6.*\t/var/log/cmdlog.log" >>  $dir
    else
        echo "Nothing to do !"
fi

check10=`cat $dir | grep -v ^# |grep "kern.debug" | grep "iptables.log" `
if [[ -z $check10 ]]
    then
        echo -e "kern.debug\t/var/log/iptables/iptables.log" >>  $dir
    else
        echo "Nothing to do !"
fi

cat >>./check_logrotate_config<<EOF
weekly
rotate 12
create
dateext
include /etc/logrotate.d
/var/log/wtmp {
    monthly
    create 0664 root utmp
    minisize 1M
    rotate 3
}
/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    minisize 1M
    rotate 3
}
EOF

check11=`diff check_logrotate_config /etc/logrotate.conf`
if [[ -z check11 ]]
    then
        rm -rf check_logrotate_config
        echo "Nothing to do !"
    else
       mv check_logrotate_config /etc/logrotate.conf -f
fi

systemctl restart rsyslog

echo ""
echo "================================================================================"
echo "---------------------------- CHECK VIETTEL NTP SERVER --------------------------"
echo "================================================================================"
echo ""

check1=`systemctl status ntpd 2>/dev/null| grep running`
if [[ -z $check1 ]]
    then
        systemctl start ntpd 2>/dev/null
        echo "Started ntpd.service !" 
    else
        echo "Nothing to do !"
fi

check2=`cat /etc/ntp.conf 2>/dev/null| grep -v ^# | grep "restrict -6 default"`
check3=`cat /etc/ntp.conf 2>/dev/null| grep -v ^# | grep "restrict -6 ::1"`
check4=`cat /etc/ntp.conf 2>/dev/null| grep -v ^# | grep "192.168.181.50"`
if [[ -e /etc/ntp.conf ]]
    then
        if [[ -z check2 ]]
            then
                echo "restrict -6 default nomodify notrap nopeer noquery" >> /etc/ntp.conf
                echo "Configured "restrict -6 default nomodify notrap nopeer noquery" in /etc/ntp.conf !"
            else
                echo "Nothing to do !"
        fi
        if [[ -z check3 ]]
            then
                sed -i "s/restrict ::1/restrict -6 ::1/g" /etc/ntp.conf
                echo "restrict -6 ::1" >> /etc/ntp.conf
                echo "Configured "restrict -6 ::1" in /etc/ntp.conf !"
            else
                echo "Nothing to do !"
        fi
        if [[ -z $check4 ]]
            then
                echo "server 192.168.181.50" >> /etc/ntp.conf
                echo "Configured "server 192.168.181.50" in /etc/ntp.conf !"
            else
                echo "Nothing to do !"
        fi
    else
        echo "To fix NTP configuration, please install ntp service first !"
fi

check5=`timedatectl | grep "Time zone" | awk '{print$3}'`
if [[ $check5 != "Asia/Ho_Chi_Minh" ]]
    then 
        timedatectl set-timezone Asia/Ho_Chi_Minh
        echo "Timezone is configured Asia/Ho_Chi_Minh (+7) !"
    else echo "Nothing to do !"
fi

echo ""
echo "================================================================================"
echo "------------------------------ CHECK SIRC VIETTEL ------------------------------"
echo "================================================================================"
echo ""

check=`/opt/se/salt-call vsm.status 2>/dev/null | grep 2017`
if [[ -z $check ]]
    then 
        echo "SIRC isn't installed. Please contact ATTT for help !"
    else 
        echo "Nothing to do !"
fi

echo ""
echo "================================================================================"
echo "-------------------------------- CHECK IPTABLES --------------------------------"
echo "================================================================================"
echo ""

echo "Please manually fix all of iptables's rules !"

echo ""
echo "================================================================================"
echo "---------------------------------- THE END -------------------------------------"
echo "================================================================================"
echo ""
