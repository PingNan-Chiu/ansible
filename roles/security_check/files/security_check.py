#!/usr/bin/env python3
import os
import getpass
import subprocess
from pathlib import Path


def is_rhel8():
    """Is RHEL8

    Returns:
        bool: True if RHEL8
    """
    return 'el8' in os.uname().release


def is_rhel7():
    """Is RHEL7

    Returns:
        bool: True if RHEL7
    """
    return 'el7' in os.uname().release


def is_rhel6():
    """Is RHEL6

    Returns:
        bool: True if RHEL6
    """
    return 'el6' in os.uname().release


def header():
    print("************\n*******  Server $HOSTNAME Linux Security Check Level3 @ $DATE\n************\n\n")
    print("Section 0 : Execute Envirnoment Check ...")

    me = getpass.getuser()
    print(f"******\n******\nRuning By {me} \n******\n******\n")


def section1():
    ETC_MOTD = Path('/etc/motd')
    fail_count = 0
    print("\nSection 1 : Remove system information from login screen")
    print("\t1/1: Login info check.. (/etc/motd) ")

    if ETC_MOTD.exists():
        with ETC_MOTD.open('rt') as fin:
            content = fin.read()
    else:
        content = ''

    if 'Unauthorized use of this system is prohibited' not in content:
        fail_count = fail_count + 1
        print("\033[1;31m\t\t/etc/motd file policy check failed!!\033[0m")
    else:
        print("\033[1;36m\t\t/etc/motd file policy Checked and Pass.\033[0m")

    if fail_count >0:
        print("\n\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\t\t\t!!!!!!!!  Section 1 check failed!!  !!!!!!!\n\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m")
    # FAILED="$FAILED Section 1 ,"  
    return fail_count


def section2_1():
    fail_count = 0
    print("\nSection 2 : User security management")
    print("\n\t1/10. Password policy check.. (/etc/login.defs)")
    print("\t\tTITLE\t\tVALUE\t(POLICY VALUE)\tCheck")

    ETC_LOGIN_DEFS = Path('/etc/login.defs')
    VALID_PARAMETERS = {
        'PASS_MAX_DAYS': 90,
        'PASS_MIN_DAYS': 1,
        'PASS_MIN_LEN': 8,
        'PASS_WARN_AGE': 15,
    }
    current_parameters = {}
    if ETC_LOGIN_DEFS.exists():
        with ETC_LOGIN_DEFS.open('rt') as fin:
            for line in fin:
                line = line.strip()
                if line.startswith('#') or len(line.strip()) == 0:
                    continue
                tokens = line.split()
                if tokens[0] in VALID_PARAMETERS.keys():
                    current_parameters[tokens[0]] = int(tokens[1])
        for param in VALID_PARAMETERS.keys():
            result = 'X!!!'
            expected = VALID_PARAMETERS[param]
            if param in current_parameters.keys():
                current = f"{current_parameters[param]}"
                if VALID_PARAMETERS[param] == current_parameters[param]:
                    result = 'V'
            else:
                current = ''
            if result != 'V':
                fail_count = fail_count + 1
            print(f"\t\t{param:15s} {current:7s} {expected:-15d} {result:5s}")
    else:
        print(f"{ETC_LOGIN_DEFS} not found")

    return fail_count

def section2_2():
    print("\n\t2/10. root account check..")
    print("\t\tList of user who uid = 0")
    print("\t\t------------------------")
    ETC_PASSWD = Path('/etc/passwd')
    with ETC_PASSWD.open('rt') as fin:
        for line in fin:
            line = line.strip()
            tokens = line.split(':')
            if tokens[2] == '0':
                print(f"\t\t{tokens[0]}: {tokens[2]}:{tokens[3]}")
    print("\t\t------------End  of list")
    return 0


def section2_3():
    fail_count = 0
    ETC_PASSWD = Path('/etc/passwd')
    found = False
    print("\n\t3/10. guest account check..")
    with ETC_PASSWD.open('rt') as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('guest'):
                found = True
    if found:
        print("\t\t$GUEST")
        fail_count = fail_count + 1
    else:
        print("\033[1;36m\t\tNO GUEST account found\033[0m")

    return fail_count


def section2_4():
    print("\n\t4/10. User UMASK setting check.. (/etc/login.defs)")
    print("\t\tTITLE\t\tVALUE\t(POLICY VALUE)\tCheck")
    is_valid = False
    fail_count = 0
    current_value = ''
    ETC_LOGIN_DEFS = Path('/etc/login.defs')
    with ETC_LOGIN_DEFS.open("rt") as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('UMASK'):
                tokens = line.split()
                current_value = tokens[1]
                if current_value == "027":
                    is_valid = True
                break
    if is_valid:
        result = "V"
    else:
        result = "X!!!"
        fail_count = fail_count + 1
    print(f"\t\tUMASK\t\t{current_value}\t(027)\t\t{result}")
    return fail_count


def section2_5():
    print("\n\t5/10 & 6/10 & 7/10 User password style policy Check.. (/etc/pam.d/system-auth)")
"""

echo -e "\n\t5/10 & 6/10 & 7/10 User password style policy Check.. (/etc/pam.d/system-auth)"| tee -a $OUTPUT
  PW=("retry=3" "minlen=8" "dcredit=-1" "lcredit=-1" "remember=3")
  LK=`uname -r`
  [[ $LK == *el6* ]] && LINE=`grep pam_cracklib.so /etc/pam.d/system-auth`
  [[ $LK == *el7* ]] && LINE=`grep pam_pwquality.so /etc/pam.d/system-auth`
  LINE2=`grep pam_unix.so /etc/pam.d/system-auth`
  echo -e "\t\tTITLE\tVALUE\t(POLICY VALUE)\tCheck"| tee -a $OUTPUT
  for S in ${PW[@]}; do 
    S1=`echo $S|awk 'BEGIN {FS="="};{print $1}'`
    S2=`echo $S|awk 'BEGIN {FS="="};{print $2}'`
    if [ ${S1} == "remember" ] ;then
      LINE=${LINE2[@]}
    fi
    T2='NAN'
    for T in ${LINE[@]}; do
      T1=`echo "$T" | grep $S1`
      test $T1 && T2=`echo $T1 | awk 'BEGIN {FS="="};{print $2}'`
    done

    if [ "${S2}" == "${T2}" ];then 
     CK="V" 
    else 
     CK="X!!!" 
     fail_2=$((fail_2+1))
    fi

    printf "\t\t%-8s %5s\t%6s\t\t%-5s\n" $S1 $T2 $S2 $CK| tee -a $OUTPUT
  done 
#read -p "----------Press enter to continue......."
"""

def section2_9():
    fail_count = 0
    print("\n\t8/10 Session timeout setting check.. (/etc/profile)")
    print("\t\t{0:18s}  {1:18s}       {2:5s}".format(
        "SETTINGS_NOW",
        "(POLICY_SETTING)",
        "Check",
    ))

    ETC_PROFILE = Path('/etc/profile')
    with ETC_PROFILE.open("rt") as fin:
        nothing_found = True
        for line_no, line in enumerate(fin):
            passed = False
            title = "------"
            expected = ""
            line = line.strip()
            if 'TMOUT' not in line:
                continue
            if line.startswith('TMOUT='):
                expected = "TMOUT=900"
                tokens = line.split('=')
                try:
                    tmout_value = int(tokens[1])
                except ValueError:
                    tmout_value = -1
                if tmout_value == 900:
                    passed = True
            elif line.startswith('export'):
                expected = "export TMOUT"
                passed = True
            elif line.startswith('readonly'):
                expected = "readonly TMOUT"
                passed = True
            if passed:
                result = 'V'
            else:
                result = 'X!!'
            print(f"\t\t{title:18s}  {expected:18s}       {result:5s}")
            nothing_found = True
        if nothing_found:
            fail_count = fail_count + 1
            print("\033[1;31m\t\tNO TimeOUT setting!!\033[0m")
    return fail_count


def is_telnetd_enabled_and_activated():
    return False


def section2_10():
    fail_count = 0
    print("\n\t10/11 Admin login via ssh setting check.. (/etc/ssh/sshd_config)")
    print("\n\t\t Check telnet status in current time..")

    if is_telnetd_enabled_and_activated():
        fail_count = fail_count + 1
        print("\t\t TELNET SERVICE ACTIVE!! Please SHUT DOWN SERVICE and check again!!")
    else:
        print("\t\t Telnet service status CHECK.")

    print("\n\t\t Check Root Login setting..")
    # Find 'PermitRootLogin'
    ETC_SSH_SSHD_CONFIG = Path('/etc/ssh/sshd_config')
    with ETC_SSH_SSHD_CONFIG.open('rt') as fin:
        found = False
        found_text = ""
        for line in fin:
            line = line.strip()
            if line.startswith('PermitRootLogin'):
                found = True
                found_text = line
                break
    if found:
        print("\t\t -------------------------------")
        print(f"\t\t {found_text}")
        print("\t\t -------------------------------")
    if 'yes' in found_text.lower():
        print("\033[1;31m\t\t Root ssh Login setting Check Faild!!\033[0m")
        fail_count = fail_count + 1
    else:
        print("\033[1;36m\t\t Root ssh Login setting Checked and Pass.\033[0m")

    print("\n\t\t Check Admin Login setting..")
    # Find 'DenyUsers'
    # TODO: need sudo to read
    with ETC_SSH_SSHD_CONFIG.open('rt') as fin:
        found = False
        found_text = ""
        for line in fin:
            line = line.strip()
            if line.startswith('DenyUsers'):
                found = True
                found_text = line
                break
    is_valid = False
    default_deny_users = ("wasadmin", "jboss", "wasusr", "antdeploy") 
    if found:
        print("\t\t -------------------------------")
        print(f"\t\t {found_text}")
        print("\t\t -------------------------------")

        deny_users = found_text.split()
        if len(set(default_deny_users) & set(deny_users)) == len(deny_users):
            is_valid = True

    if is_valid:
        print("\t\t -------------------------------")
        print(f"\t\t Default_DenyUsers \033[1;33m{','.join(default_deny_users)}\033[0m")
        print("\t\t -------------------------------")
        print("\033[1;36m\t\t Default Admin Login setting Checked and Pass.\033[0m")
    else:
        print("\033[1;31m\t\t Admin Login setting Check FAILD!!!!!!!!!!!\033[0m")
        print(f"\033[1;31m\t\t User: \"{','.join(default_deny_users)}\" has NOT been set for denyuser for ssh login!!!!\033[0m")
        fail_count = fail_count + 1

    return fail_count
    

def find_current_active_ftp_daemon():
    try:
        output = subprocess.check_output([
            'lsof', '-n', '-i', ':21'
        ], shell=True)
        output = output.decode('utf-8')
        for line in output.split('\n'):
            if 'LISTEN' not in line:
                continue
            columns = line.strip().split()
            return columns[0]
    except subprocess.CalledProcessError:
        return ''

    return ''


def section2_11():
    print("\n\t11/11 Root login via FTP setting check.. ")

    fail_count = 0
    current_ftp_daemon = find_current_active_ftp_daemon()
    if current_ftp_daemon == 'vsftpd':
        ETC_VSFTPD_FTPUSERS = Path('/etc/vsftpd/ftpusers')
        with ETC_VSFTPD_FTPUSERS.open('rt') as fin:
            found = False
            for line in fin:
                line = line.strip()
                if 'root' in line:
                    found = True
                    break
            if found:
                print("\033[1;36m\t\t Root ftp Login setting Checked and Pass\033[0m")
            else:
                print("\033[1;31m\t\t Root ftp Login setting Check Faild!!\033[0m")
                fail_count = fail_count + 1
    elif current_ftp_daemon == 'proftpd':
        print("\t\t Proftpd has been decided disable from server, Please remove proftpd and install vsftpd instead.")
        fail_count = fail_count + 1
    else:
        print("\t\t No FTP configuration file exist.")
    return fail_count


def section2():
    fail_count = 0
    fail_count = fail_count + section2_1()
    fail_count = fail_count + section2_2()
    fail_count = fail_count + section2_3()
    fail_count = fail_count + section2_4()
    fail_count = fail_count + section2_9()
    fail_count = fail_count + section2_10()
    fail_count = fail_count + section2_11()
    if fail_count:
        print("\n\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("\t\t\t!!!!!!!!  Section 2 check failed!!  !!!!!!!")
        print("\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m")
        # FAILED="$FAILED Section 2 ,"  


def section3():
    print("\nSection 3 : Files, folder, programs management")
    fail_count = 0
    expected_permission_and_owner_file_list = [
        # path, expected mode, expected owner
        (Path('/etc/passwd'), 0o100644, 0),
        (Path('/etc/group'), 0o100644, 0),
        (Path('/etc/hosts'), 0o100644, 0),
        (Path('/etc/inetd.conf'), 0o100644, 0),
        (Path('/etc/named.conf'), 0o100644, 0),
        (Path('/etc/resolv.conf'), 0o100644, 0),
        (Path('/usr/bin/ftp'), 0o100755, 0),
        (Path('/bin/netstat'), 0o100755, 0),
        (Path('/sbin/ifconfig'), 0o100755, 0),
    ]
    total = len(expected_permission_and_owner_file_list)
    print("\t{0:16s} {1:10s}  {2:19s}   {3:6s}   {4:6s}   {5:6s}".format(
        "FILE", "PERMISSION", "(PERMISSION_POLICY)", "PER_CK", "OWNER", "OWN_CK"
    ))
    for no, item in enumerate(expected_permission_and_owner_file_list, start=1):
        path, expected_perm, expected_owner = item
        if path.exists():
            stat = path.stat()
            is_perm_valid = False
            is_owner_valid = False
            if stat.st_mode == expected_perm:
                is_perm_valid = True
            if stat.st_uid == expected_owner:
                is_owner_valid = True

            if is_perm_valid:
                perm_chk_result = 'V'
            else:
                fail_count = fail_count + 1
                perm_chk_result = 'X!!'
            if is_owner_valid:
                owner_chk_result = 'V'
            else:
                fail_count = fail_count + 1
                owner_chk_result = 'X!!'
            print(f"({no}/{total})\t{str(path):16s} {expected_perm:10o}  {stat.st_mode:19o}    {perm_chk_result:6s}  {stat.st_uid:6d}    {owner_chk_result:6s}")
        else:
            print(f"({no}/{total})\t{str(path):16s} \t\tFile not found!")
    if fail_count:
        print("\n\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("\t\t\t!!!!!!!!  Section 3 check failed!!  !!!!!!!")
        print("\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m")
        #FAILED="$FAILED Section 3 ,"  


def is_syslog_daemon_in_memory():
    found = False
    output = subprocess.check_output(['ps', 'aux'])
    output = output.decode('utf-8')
    for line in output.split('\n'):
        line = line.strip()
        if 'rsyslogd' in line:
            found = True
            break
    return found


def section4():
    fail_count = 0
    print("Section 4 : System funtion check")
    print("\n\t4.1 Syslog funtion check..")

    if is_syslog_daemon_in_memory():
        print("\t\tSyslog daemon Found:")
        print("\t\t\033[1;36mSyslog Daemon Checked and Pass.\033[0m")
    else:
        print("\t\t\033[1;31mNO Systemlog daemon found!!\033[0m")
        fail_count = fail_count + 1

    ETC_RSYSLOG_CONF = Path('/etc/rsyslog.conf')
    found = False
    with ETC_RSYSLOG_CONF.open('rt') as fin:
        for line in fin:
            line = line.strip()
            if 'authpriv' in line and '514' in line:
                found = True
                break
    if found:
        print("\t\tSyslog daemon Configuration Setting Found:")
        print("\t\t\033[1;36mSyslog Conf Checked and Pass.\033[0m")
    else:
        print("\t\t\033[1;31mNO Systemlog daemon Configuration Setting found!!\033[0m")
        fail_count = fail_count + 1

    # RHEL7/8 already use systemd instead of SysV, so use systemctl to check
    try:
        output = subprocess.check_output([
            'systemctl',
            'is-active',
            'rsyslog',
        ], stderr=Path('/dev/null').open('wt'))
        output = output.strip()
    except subprocess.CalledProcessError:
        output = ''

    if output == 'active':
        print("\t\tSyslog daemon service is \033[1;36menabled and Pass.\033[0m")
    else:
        print("\t\t\033[1;31mSyslog daemon service is diabled!!\033[0m")
        fail_count = fail_count + 1

    if fail_count:
        print("")
        print("\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("\t\t\t!!!!!!!!  Section 4 check failed!!  !!!!!!!")
        print("\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m")
        # FAILED="$FAILED Section 4 ,"  


def is_ntp_service_active():
    try:
        output = subprocess.check_output(
            ['timedatectl', 'status'],
            stderr=Path('/dev/null').open('wt'),
        )
        output = output.decode('utf-8')
    except subprocess.CalledProcessError:
        output = ''

    if not output:
        return False

    for line in output.split('\n'):
        line = line.strip()
        if not line.startswith('NTP service:'):
            tokens = line.split(':')
            if tokens[1] == 'active':
                return True
    return False


def section5():
    fail_count = 0
    print("Section 5 : System and Network security management")
    print("\n\t5.1 NTPD funtion check..")

    if is_ntp_service_active():
        print("\t\tNetwork time Correction Daemon found:")
        print("\t\t\033[1;36mNTPD Checked and Pass\033[0m")
    else:
        print("\t\t\033[1;31mNO NTP daemon found!!\033[0m")
        fail_count = fail_count + 1

    return fail_count


def summary():
    pass


def main():
    header()
    section1()
    section2()
    section3()
    section4()
    section5()
    summary()


if __name__ == "__main__":
    main()