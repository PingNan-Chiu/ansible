#!/bin/bash

######
## UPDATE NOTE: 2019.09.06
##    V2: 
##        1. Remove check-step-stop
##        2. First Run case
##        3. DenyUsers ssh login confirm by manualy input
##        4. Defalut DenyUsers (antdeploy,wasusr)
##        5. Remove Proftp check
##        6. vim security leak check
##	  7. NTP config check
##        8. Result FTP to MRTG Server
####
GROUP=$3
LK=`uname -r`
DATE=`date +%Y-%m-%d-%H-%M`
DATEs=`date +%Y-%m-%d`
HOSTNAME=`hostname`
CK_HOME='/var/SP_management/security_ck'
CK_RECORD='/var/SP_management/security_ck/record'
OUTPUT="/tmp/SYSTEM_Security_Check_$HOSTNAME.tmp"
OUTPUT_F="/tmp/SYSTEM_Security_Check_$HOSTNAME"
CRON=$1
# FIRST_RUN=1
FIRST_RUN=0

if [ -e $OUTPUT ]; then
  rm -f $OUTPUT
else
  touch $OUTPUT
fi
chmod 0777 $OUTPUT

# Detect distro version
if grep -q -i "release 6" /etc/redhat-release ; then
  rhel6=1
elif grep -q -i "release 7" /etc/redhat-release ; then
  rhel7=1
elif grep -q -i "release 8" /etc/redhat-release ; then
  rhel8=1
else
  echo "Only support RHEL6.x RHEL7.x RHEL8.x"
fi


echo -e "************\n*******  Server $HOSTNAME Linux Security Check Level3 @ $DATE\n************\n\n" | tee -a $OUTPUT
echo -e "\nSection 0 : Execute Envirnoment Check ..."

ME=`/usr/bin/whoami`
echo -e "******\n******\nRuning By ${ME} \n******\n******\n" | tee -a $OUTPUT
# echo $4 |sudo -S "ls"
# -d file: True if file exists and is a directory
if [ ! -d "${CK_RECORD}" ] ; then
  echo "No previous check record found: Setup envirnoment at Frist time...."
  `sudo -S mkdir -p  "${CK_RECORD}"`
  `sudo cp /tmp/security_ck.sh ${CK_HOME}`
  `sudo chmod 755 ${CK_HOME}/security_ck.sh`
  FIRST_RUN=1
  if [ "${ME}" == "root" ] || [ "`/usr/bin/sudo -v || echo 1`" == "1" ]; then 
    echo -e "\n"
    echo -e "\033[1;31mPermission ERROR: Please run as normal user with sudo permission at firt time\033[0m\n"
    exit 1 
  fi
fi

if [ "${CRON}" == "cron" ] && [ "${ME}" == "root" ];then 
  # DO_FTP=1
  echo -e "******\n" | tee -a $OUTPUT
  echo -e "******\n" | tee -a $OUTPUT
  echo -e "Crontab execute at ${DATE} \n" | tee -a $OUTPUT
  echo -e "******\n" | tee -a $OUTPUT
  echo -e "******\n" | tee -a $OUTPUT
  rm ${CK_HOME}/SYSTEM_Security_Check_${HOSTNAME}.*.txt
fi

############################################################
## Section 1 : Remove system information from login screen ##
############################################################
echo -e "\nSection 1 : Remove system information from login screen"| tee -a $OUTPUT
echo -e "\t1/1: Login info check.. (/etc/motd) "| tee -a $OUTPUT
fail_1=0

MESG=`grep 'Unauthorized use of this system is prohibited' "/etc/motd"`
if [ -z "$MESG" ];then 
  echo -e "\033[1;31m\t\t/etc/motd file policy check failed!!\033[0m"| tee -a $OUTPUT
  fail_1=$((fail_1+1))
else
  echo -e "\033[1;36m\t\t/etc/motd file policy Checked and Pass.\033[0m"| tee -a $OUTPUT
fi

if [ $fail_1 != 0 ] ;then 
  echo -e "" | tee -a $OUTPUT
  echo -e "\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" | tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!  Section 1 check failed!!  !!!!!!!" | tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m" | tee -a $OUTPUT
  FAILED="$FAILED Section 1 ,"
fi

#read -p "----------Press enter to continue......."
######################
## End of section 1 ##
######################

##########################################
## Section 2 : User security management ##
##########################################

fail_2=0
echo -e "\nSection 2 : User security management"| tee -a $OUTPUT
echo -e "\n\t1/11. Password policy check.. (/etc/login.defs)"| tee -a $OUTPUT
PLY=("PASS_MAX_DAYS=90" "PASS_MIN_LEN=8" "PASS_WARN_AGE=15")
echo -e "\t\tTITLE\t\tVALUE\t(POLICY VALUE)\tCheck"| tee -a $OUTPUT
for X in ${PLY[@]};do
  Y=`echo $X|awk 'BEGIN {FS="="};{print $1}'`
  Z=`echo $X|awk 'BEGIN {FS="="};{print $2}'`
  VALUE=`cat /etc/login.defs | grep $Y | grep -v \# | awk 'BEGIN {FS=" "};{print $2}'`
  if [ $Z == $VALUE ];then 
   CK="V" 
  else 
   CK="X!!!" 
  fail_2=$((fail_2+1))
  fi
  printf "\t\t%-15s %-7d %-15s %-5s\n" $Y $VALUE \($Z\) $CK| tee -a $OUTPUT
done

#read -p "----------Press enter to continue......."
echo -e "\n\t2/11. root account check.."| tee -a $OUTPUT
echo -e "\t\tList of user who uid = 0" | tee -a $OUTPUT
echo -e "\t\t------------------------" | tee -a $OUTPUT
awk -F: '{printf "\t\t%s: %s:%s\n",$1,$3,$4}' /etc/passwd | grep ' 0:'| tee -a $OUTPUT
echo -e "\t\t------------End  of list" | tee -a $OUTPUT
echo ""; echo -e "\n\t3/11. guest account check.."| tee -a $OUTPUT

GUEST=`grep '^guest' /etc/passwd`
test ! -z "$GUEST" && echo -e "\t\t$GUEST" | tee -a $OUTPUT && fail_2=$((fail_2+1))
test -z "$GUEST" && echo -e "\033[1;36m\t\tNO GUEST account found\033[0m"| tee -a $OUTPUT

echo ""; echo -e "\n\t4/11. User UMASK setting check.. (/etc/login.defs)" | tee -a $OUTPUT
echo -e "\t\tTITLE\t\tVALUE\t(POLICY VALUE)\tCheck"| tee -a $OUTPUT
MSK=`cat /etc/login.defs | awk 'BEGIN {FS=" "};/^UMASK/{print $2}'`
if [ "$MSK" == '027' ];then
  CK="V"
else
  CK="X!!!"
  fail_2=$((fail_2+1))    
fi
echo -e "\t\tUMASK\t\t$MSK\t(027)\t\t$CK"| tee -a $OUTPUT

# 5/11 is same with 6/11
echo -e "\n\t5/11 & 6/11 User password style policy Check.. (/etc/pam.d/system-auth)"| tee -a $OUTPUT
PW=("retry=3" "minlen=8" "dcredit=-1" "lcredit=-1")
[[ $LK == *el6* ]] && LINE=`grep pam_cracklib.so /etc/pam.d/system-auth`
[[ $LK == *el7* || $LK == *el8* ]] && LINE=`grep pam_pwquality.so /etc/pam.d/system-auth`
echo -e "\t\tTITLE\tVALUE\t(POLICY VALUE)\tCheck"| tee -a $OUTPUT

# echo "LINE=$LINE"
IFS=' ' read -ra line_array <<< "$LINE"
if [ ! -z "$LINE" -a "$LINE" != " " ]; then
  for S in ${PW[@]}; do 
    S1=`echo $S|awk 'BEGIN {FS="="};{print $1}'`
    S2=`echo $S|awk 'BEGIN {FS="="};{print $2}'`
    T2='NAN'
    # Iterate the line we found, for example:
    # "password    requisite     pam_cracklib.so try_first_pass retry=3 type="
    # T will be "password", "requisite" ...
    for T in ${line_array[@]}; do
      # echo "T=$T"
      T1=`echo "$T" | grep $S1`
      # T1 is "retry", "minlen", "dcredit", "lcredit"
      # if found T1 in T, then get the value
      if [ $T1 ]; then
        T2=`echo $T1 | awk 'BEGIN {FS="="};{print $2}'`
      fi
      # echo "T1=$T1 T2=$T2"
    done

    # S2 is expected value, T2 is the found value
    # if they are the same, the variable "CK" will be marked as 'V'
    if [ "${S2}" == "${T2}" ];then 
      CK="V" 
    else 
      CK="X!!!" 
      fail_2=$((fail_2+1))
    fi

    # Display
    printf "\t\t%-8s %5s\t%6s\t\t%-5s\n" $S1 $T2 $S2 $CK| tee -a $OUTPUT
  done 
else
  for S in ${PW[@]}; do 
    S1=`echo $S|awk 'BEGIN {FS="="};{print $1}'`
    S2=`echo $S|awk 'BEGIN {FS="="};{print $2}'`
    T2='NAN'
    CK="X!!!" 
    fail_2=$((fail_2+1))
    printf "\t\t%-8s %5s\t%6s\t\t%-5s\n" $S1 $T2 $S2 $CK| tee -a $OUTPUT
  done 
fi

# 7/11
# Follow the above check rule, but change PW and the filename
# Check pam_unix.so
# In RHEL6/7:
# password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok
# In RHEL8:
# password    sufficient                                   pam_unix.so sha512 shadow nullok try_first_pass use_authtok
echo -e "\n\t7/11 pam_unix.so setting check.. (/etc/pam.d/system-auth)"| tee -a $OUTPUT
PW=("remember=3")
LINE=`grep "pam_unix.so" /etc/pam.d/system-auth | grep "password" | grep "sufficient"`
IFS=' ' read -ra line_array <<< "$LINE"
if [ ! -z "$LINE" -a "$LINE" != " " ]; then
  for S in ${PW[@]}; do 
    S1=`echo $S|awk 'BEGIN {FS="="};{print $1}'`
    S2=`echo $S|awk 'BEGIN {FS="="};{print $2}'`
    T2='NAN'
    for T in ${line_array[@]}; do
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
else
  for S in ${PW[@]}; do 
    S1=`echo $S|awk 'BEGIN {FS="="};{print $1}'`
    S2=`echo $S|awk 'BEGIN {FS="="};{print $2}'`
    T2='NAN'
    CK="X!!!" 
    fail_2=$((fail_2+1))
    printf "\t\t%-8s %5s\t%6s\t\t%-5s\n" $S1 $T2 $S2 $CK| tee -a $OUTPUT
  done 
fi

echo -e "\n\t8/11 pam_tally2 / pam_faillock setting check.. (/etc/pam.d/password-auth)"| tee -a $OUTPUT
PW=("unlock_time=1800")
[[ $LK == *el6* || $LK == *el7* ]] && LINE=`grep pam_tally2.so /etc/pam.d/password-auth`
[[ $LK == *el8* ]] && LINE=`grep pam_faillock.so /etc/pam.d/password-auth`

IFS=' ' read -ra line_array <<< "$LINE"
if [ ! -z "$LINE" -a "$LINE" != " " ]; then
  for S in ${PW[@]}; do 
    S1=`echo $S|awk 'BEGIN {FS="="};{print $1}'`
    S2=`echo $S|awk 'BEGIN {FS="="};{print $2}'`
    T2='NAN'
    for T in ${line_array[@]}; do
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
else
  for S in ${PW[@]}; do 
    S1=`echo $S|awk 'BEGIN {FS="="};{print $1}'`
    S2=`echo $S|awk 'BEGIN {FS="="};{print $2}'`
    T2='NAN'
    CK="X!!!" 
    fail_2=$((fail_2+1))
    printf "\t\t%-8s %5s\t%6s\t\t%-5s\n" $S1 $T2 $S2 $CK| tee -a $OUTPUT
  done 
fi

echo -e "\n\t9/11 Session timeout setting check.. (/etc/profile)"| tee -a $OUTPUT
printf "\t\t%-18s  %-18s       %-5s\n" SETTING_NOW \(POLICY_SETTING\) Check| tee -a $OUTPUT
TO=(= readonly export)
for ((U=1;U<=3;U=U+1));do
  TOA=`grep TMOUT /etc/profile|sed -n $U\p|grep "${TO[$U - 1]}" | grep -v "#"`
  if [ ${TO[$U - 1]} == "=" ];then 
    TOB="TMOUT=900" 
  elif [ ${TO[$U - 1]} == "readonly" ];then
    TOB="readonly TMOUT"
  elif [ ${TO[$U - 1]} == "export" ];then
    TOB="export TMOUT"
  fi
  test "$TOA" && CK="V" && printf "\t\t%-18s  %-18s       %-5s\n" "$TOA" "($TOB)" "$CK"| tee -a $OUTPUT
  test -z "$TOA" && CK="X!!" && printf "\t\t%-18s  %-18s       %-5s\n" "------" "($TOB)" "$CK"| tee -a $OUTPUT
done
test -z "$TOA" && echo -e "\033[1;31m\tNO TimeOUT setting!!\033[0m" | tee -a $OUTPUT&& fail_2=$((fail_2+1))

echo -e "\n\t10/11 Admin login via ssh setting check.. (/etc/ssh/sshd_config)"| tee -a $OUTPUT
echo -e "\n\t\t Check telnet status in current time.."| tee -a $OUTPUT
unset TELNET_FIND
TELNET_FIND=`sudo netstat -tl | grep telnet`
if [ -n "${TELNET_FIND}" ];then
  echo -e "\t\t TELNET SERVICE ACTIVE!! Please SHUT DOWN SERVICE and redo security_ck.sh !! ${TELNET_FIND}"| tee -a $OUTPUT
  fail_2=$((fail_2+1))
else
  echo -e "\t\t Telnet service status CHECK."| tee -a $OUTPUT
fi

echo -e "\n\t\t Check Root Login setting.."| tee -a $OUTPUT
root_login=`sudo cat /etc/ssh/sshd_config | grep PermitRootLogin|grep -v "#"`
ro_inck=`echo ${root_login}| awk 'BEGIN {FS=" "};{print $2}'`
echo -e "\t\t -------------------------------"| tee -a $OUTPUT
echo -e "\t\t ${root_login}"| tee -a $OUTPUT
echo -e "\t\t -------------------------------"| tee -a $OUTPUT
if [[ ${ro_inck} == 'no' ]];then
 echo -e "\033[1;36m\t\t Root ssh Login setting Checked and Pass.\033[0m"| tee -a $OUTPUT
else
 echo -e "\033[1;31m\t\t Root ssh Login setting Check Faild!!\033[0m"| tee -a $OUTPUT
 fail_2=$((fail_2+1))
fi

################################################
############### DenyUsers ######################
################################################
function CheckDenyUsers() {
echo -e "\n\t\t Check Admin Login setting.."| tee -a $OUTPUT
deny_user=`sudo cat /etc/ssh/sshd_config | grep -v "#" |grep DenyUsers`
if [ "$FIRST_RUN" != "1"  ] ;then # Deal with history sec_ck log
  shopt -s nullglob
  sckllog=`sudo ls -rt ${CK_RECORD}/SYSTEM_Security_Check*.SCUESS.*.txt | tail -1`
  his_deny_user=`sudo cat ${sckllog} | grep " DenyUsers "| sed 's/\t//g'`
  IFS=' ' read -r -a hisduser_ary <<< "$his_deny_user";IFS=$'\n' hdu_sorted=($(sort <<<"${hisduser_ary[*]}")); unset IFS
  varh=$( IFS=','; echo "${hdu_sorted[*]}" )
  his_input=`sudo cat ${sckllog} | grep USER| grep input`
fi

echo -e "\n\t\t Check default admin user Login setting....."
default_duser=("wasadmin" "jboss" "wasusr" "antdeploy") 
for T_duser in ${default_duser[@]}; do
  tuser_ck=0
  tuser_f=`sudo cat /etc/passwd | grep ${T_duser} | awk 'BEGIN {FS=":"};{print $1}' | grep ${T_duser}`
  tuser_index=`sudo cat /etc/passwd | grep ${T_duser} | awk 'BEGIN {FS=":"};{print $7}'|grep nologin`
  
  if [ -n "${tuser_f}" ] && [ -z "${tuser_index}" ] ;then
    tduser="${tduser},${tuser_f}"
    duser_ck=`echo \"${deny_user}\" | grep ${tuser_f} `
    test "${duser_ck}" && P_duser="${P_duser},${tuser_f}"
    test -z "${duser_ck}" && F_duser="${F_duser},${tuser_f}"
  elif [ -n "${tuser_f}" ] && [ -n "${tuser_index}" ] ;then
    P_duser="${P_duser},${tuser_f}"
  fi
done

IFS=',' read -r -a Fduser <<< "$F_duser";IFS=$'\n' fdur=($(sort <<<"${Fduser[*]}")); unset IFS
var00=$( IFS=','; echo "${fdur[*]}" )

if [ -n "${F_duser}" ];then
  echo -e "\033[1;31m\t\t Admin Login setting Check FAILD!!!!!!!!!!!\033[0m"| tee -a $OUTPUT
  echo -e "\033[1;31m\t\t User: \"${var00}\" has NOT been set for denyuser for ssh login!!!!\033[0m"| tee -a $OUTPUT
  fail_2=$((fail_2+1))
fi

if [ -n "${P_duser}" ];then
  IFS=',' read -r -a Pduser <<< "$P_duser";IFS=$'\n' pdur=($(sort <<<"${Pduser[*]}")); unset IFS
  var0=$( IFS=','; echo "${pdur[*]}" )
  echo -e "\t\t -------------------------------"| tee -a $OUTPUT
  echo -e "\t\t Default_DenyUsers \033[1;33m${var0}\033[0m"| tee -a $OUTPUT
  echo -e "\t\t -------------------------------"
  echo -e "\033[1;36m\t\t Default Admin Login setting Checked and Pass.\033[0m"| tee -a $OUTPUT
fi
if [ -n "${deny_user}" ] ;then

  IFS=' ' read -r -a duser_ary <<< "$deny_user";IFS=$'\n' du_sorted=($(sort <<<"${duser_ary[*]}")); unset IFS
  vara=$( IFS=','; echo "${du_sorted[*]}" )
  echo -e "\t\t Additional denyUsers has been set,"| tee -a $OUTPUT
  echo -e "\t\t -------------------------------"| tee -a $OUTPUT

  if [ "$FIRST_RUN" == "1" ];then
    echo -e "\t\t Please input the admin account (EX: accountA,accountB,accountC):"
      # read USERIN
    USERIN=$2
    echo -e "\t\t USER \033[1;32m${ME}\033[0m confirm input : \" $USERIN \" at ${DATE}"| tee -a $OUTPUT
    USERIN="DenyUsers,$USERIN"
    IFS=',' read -r -a Inuser_ary <<< "$USERIN";IFS=$'\n' iu_sorted=($(sort <<<"${Inuser_ary[*]}")); unset IFS
    varb=$( IFS=','; echo "${iu_sorted[*]}" )
    if [ "$vara" != "$varb" ];then echo -e "\033[1;31m\t\t!! Setting of System is not Consistent with User Input. !!\n\n\t\t Admin Login setting Check FAILD!!!!!!!!!!!\033[0m"| tee -a $OUTPUT;fail_2=$((fail_2+1))
    else
      for ((DU=1;DU<=${#duser_ary[@]};DU=DU+1));do
          DUL="$DUL ${duser_ary[$DU]}"
      done
    fi

  elif [ "$FIRST_RUN" != "1" ] && [ "$vara" != "$varh" ];then
    echo -e "\t\t History confirm Record:" | tee -a $OUTPUT
    echo -e "${his_input}" | tee -a $OUTPUT
    echo -e "\t\t -------------------------------"
    if [ "${CRON}" != "cron" ];then
      echo -e "\t\t Please input the admin account (EX: accountA,accountB,accountC):"
      read USERIN
      echo -e "\t\t USER \033[1;32m${ME}\033[0m confirm input : \" $USERIN \" at ${DATE}"
    fi 
    USERINA="$USERIN";  USERIN="DenyUsers,$USERIN"
    IFS=',' read -r -a Inuser_ary <<< "$USERIN";IFS=$'\n' iu_sorted=($(sort <<<"${Inuser_ary[*]}")); unset IFS
    varb=$( IFS=','; echo "${iu_sorted[*]}" )
    if [ "$vara" != "$varb" ];then 
      echo -e "\033[1;31m\t\t!! Setting of System is not Consistent with User Input/Record. !!\n\n\t\t Admin Login setting Check FAILD!!!!!!!!!!!\033[0m" |tee -a $OUTPUT
      fail_2=$((fail_2+1))
    else
      echo -e "\t\t USER \033[1;32m${ME}\033[0m confirm input : \" $USERINA \" at ${DATE}"| tee -a $OUTPUT
      for ((DU=1;DU<=${#duser_ary[@]};DU=DU+1));do
        DUL="$DUL ${duser_ary[$DU]}"
      done
      
    fi
    echo -e "\t\t -------------------------------"| tee -a $OUTPUT
  else
   echo -e "\t\t ${deny_user}"
    for ((DU=1;DU<=${#duser_ary[@]};DU=DU+1));do
      DUL="$DUL ${duser_ary[$DU]}"
    done
  fi 
  echo -e "\t\t DenyUsers \033[1;33m${DUL}\033[0m"| tee -a $OUTPUT
  echo -e "\t\t -------------------------------"| tee -a $OUTPUT
  test "${DUL}" && echo -e "\033[1;36m\t\t DenyUsers_Login_Setting Checked and Pass.\033[0m"| tee -a $OUTPUT
   echo -e "\t\t Please make sure setting above contain the AP admin user....."| tee -a $OUTPUT
else
  httpd=`ps -ef | grep httpd | grep -v "#" | grep -v grep | wc -l`
  if [ ${httpd} != 0 ];then 
    echo -e "\t\tApache Daemon Found, Web service server can have NO_Denyuser\n\033[1;36m\t\t DenyUsers_Login_Setting Checked and Pass.\033[0m" | tee -a $OUTPUT
  else
    echo -e "\033[1;31m\t\t!!Admin Login setting Check FAILD!!!!!!!!!!!\n\t\tNo Denyuser_setting be found!!\033[0m"| tee -a $OUTPUT
    fail_2=$((fail_2+1))
  fi
fi 
}

#read -p "----------Press enter to continue......."
echo -e "\n\t11/11 Root login via FTP setting check.. "| tee -a $OUTPUT
  
ftp_now=`sudo lsof -n -i :21 | grep LISTEN | awk 'BEGIN {FS=" "};{print $1}'`

echo -e "\t\t Current Active FTP Daemon : ${ftp_now} "| tee -a $OUTPUT

if [ "${ftp_now}" == "vsftpd"  ];then
  echo -e "\t\t Check setting file : \"\033[1;32m/etc/vsftpd/ftpusers\033[0m\" ...."| tee -a $OUTPUT
  ftpusr=`sudo cat /etc/vsftpd/ftpusers|grep root`
  if [ ${ftpusr} == 'root' ];then
    echo -e "\033[1;36m\t\t Root ftp Login setting Checked and Pass\033[0m"| tee -a $OUTPUT
  else
    echo -e "\033[1;31m\t\t Root ftp Login setting Check Faild!!\033[0m"| tee -a $OUTPUT
    fail_2=$((fail_2+1))
  fi
elif [ "${ftp_now}" == "proftpd" ];then
  echo -e "\t\t Proftpd has been decided disable from server, Please remove proftpd and install vsftpd instead.\n"| tee -a $OUTPUT
  fail_2=$((fail_2+1))
else
 echo -e "\t\t No FTP configuration file exist."| tee -a $OUTPUT
fi

if [ $fail_2 != 0 ] ;then 
  echo -e "\n\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!  Section 2 check failed!!  !!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m"| tee -a $OUTPUT
  FAILED="$FAILED Section 2 ,"  
fi

######################
## End of Section 2 ##
######################

####################################################
## Section 3 : Files, folder, programs management ##
####################################################
fail_3=0
echo -e "Section 3 : Files, folder, programs management"| tee -a $OUTPUT
  FILES=(\/etc\/passwd \/etc\/group \/etc\/hosts \/etc\/inetd.conf \/etc\/named.conf \/etc\/resolv.conf \/usr\/bin\/ftp \/bin\/netstat \/sbin\/ifconfig)
  PERMN=(644 644 664 644 644 664 755 755 755)
echo -e "\n\t3. Flies premission check.."| tee -a $OUTPUT
printf "\t%-16s %10s  %19s   %-6s   %-6s   %-6s\n" "FILE" "PERMISSION" "(PERMISSION_POLICY)" "PER_CK" "OWNER" "OWN_CK"| tee -a $OUTPUT
for ((P=0;P<=8;P=P+1));do
  if [ -e ${FILES[$P]} ];then
    PER_STR=`stat -c \%a ${FILES[$P]} | tr -d '\n'`
    OWN_STR=`stat -c \%U ${FILES[$P]}`
    if [ $PER_STR = ${PERMN[$P]} ];then
      PRCK="V"
    else
      PRCK="X!!"
      fail_3=$((fail_3+1))
    fi
    if [ $OWN_STR = "root" ];then
      OWCK="V"
    elif [ $OWN_STR = "bin" ] && [ ${FILES[$P]} = "/sbin/ifconfig" ];then
      OWCK="V"
    else
      OWCK="X!!"
      fail_3=$((fail_3+1))
    fi
    PP=$(($P + 1))
    printf "(%d/9)\t%-16s %10s  %19s   %-6s   %-6s   %-6s\n" $PP ${FILES[$P]} $PER_STR \(${PERMN[$P]}\) $PRCK $OWN_STR $OWCK| tee -a $OUTPUT
  else
    PP=$(($P + 1))
    printf "(%d/9)\t%-16s \t\tFile not found!\n" $PP ${FILES[$P]}| tee -a $OUTPUT
  fi
done
if [ $fail_3 != 0 ] ;then 
  echo -e "\n\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!  Section 3 check failed!!  !!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m"| tee -a $OUTPUT
  FAILED="$FAILED Section 3 ,"  
fi

######################
## End of Section 3 ##
######################

######################################
## Section 4 : System funtion check ##
######################################
fail_4=0
echo -e "Section 4 : System funtion check"| tee -a $OUTPUT
echo -e "\n\t4.1 Syslog funtion check.."| tee -a $OUTPUT

# Check rsyslog daemon
if [[ $LK == *el6* ]]; then
  SYSLOG=`ps aux | grep rsyslog | grep -v grep`
  if [ -z "$SYSLOG" ]; then
    echo -e "\033[1;31mNO Systemlog daemon found!!\033[0m" | tee -a $OUTPUT
    fail_4=$((fail_4+1))
  else
    echo -e "\tSyslog daemon Found:"| tee -a $OUTPUT
    echo -e "$SYSLOG"| tee -a $OUTPUT
    echo -e "\033[1;36mSyslog Daemon Checked and Pass.\033[0m\n"| tee -a $OUTPUT
  fi
else
  # RHEL7/8 already use systemd instead of SysV, so use systemctl to check
  SYSLOG_CHKCONFIG=`systemctl list-unit-files | awk -F' ' '/rsyslog/{print $2}'`
  if [ "$SYSLOG_CHKCONFIG" == "enabled" ]; then
    echo -e "\tSyslog daemon service is \033[1;36menabled and Pass.\033[0m\n"| tee -a $OUTPUT
  else
    echo -e "\033[1;31mSyslog daemon service is diabled!!\033[0m"| tee -a $OUTPUT && fail_4=$((fail_4+1))
  fi
fi
# Check rsyslog configuration
SYSLOG_CONF=`cat /etc/rsyslog.conf | grep authpriv | grep 514`
if [ -z "$SYSLOG_CONF" ]; then
  echo -e "\033[1;31mNO Systemlog daemon Configuration Setting found!!\033[0m" | tee -a $OUTPUT && fail_4=$((fail_4+1))
else
  echo -e "\tSyslog daemon Configuration Setting Found:"| tee -a $OUTPUT
  echo -e "$SYSLOG"| tee -a $OUTPUT
  echo -e "\033[1;36mSyslog Conf Checked and Pass.\033[0m\n"| tee -a $OUTPUT
fi

if [ $fail_4 != 0 ] ;then 
  echo -e "\n\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!  Section 4 check failed!!  !!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m"| tee -a $OUTPUT
  FAILED="$FAILED Section 4 ,"  
fi

######################
## End of Section 4 ##
######################

########################################################
## Section 5 : System and Network security management ##
########################################################
fail_5=0
echo -e "Section 5 : System and Network security management"| tee -a $OUTPUT
echo -e "\n\t5.1 NTPD funtion check.."| tee -a $OUTPUT

# Check ntp by distribution
NTPD=""
DTL=""
TL_conf=""
if [[ $LK == *el6* ]]; then
  # RHEL6, check ntpd
  NT=`ps -ef | grep ntpd | grep -v grep`
  if [ "$NT" ]; then
    NTPD="ntpd"
    DTL="ntp"
  fi
else
  # RHEL7 / RHEL8, use timedatectl to check NTP service
  # Default NTP daemon in RHEL7 / RHEL8 is chrony
  NT=`timedatectl status | awk -F: '/NTP service/{print $2}'`
  if [ "$NT" == " active" ]; then
    NTPD="chrony"
    DTL="chrony"
  fi
fi

# Check whether 'cathaygtsm' is in NTP config.
test "${DTL}" && TL_conf=`cat /etc/"${DTL}.conf" | grep -v '#' | grep cathaygtsm`
if [ "$NTPD" ]; then
  echo -e "\tNetwork time Correction Daemon found:"| tee -a $OUTPUT
  echo -e "$NTPD"| tee -a $OUTPUT
  echo -e "\033[1;36mNTPD Checked and Pass\033[0m"| tee -a $OUTPUT
fi
test -z "$TL_conf" && echo -e "\033[1;31mNO NTP Configuration found!!\033[0m" | tee -a $OUTPUT && fail_5=$((fail_5+1))
test -z "$NTPD" && echo -e "\033[1;31mNO NTP daemon found!!\033[0m"| tee -a $OUTPUT && fail_5=$((fail_5+1))

if [ $fail_5 != 0 ] ;then 
  echo -e "\n"| tee -a $OUTPUT
  echo -e "\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!  Section 5 check failed!!  !!!!!!!"| tee -a $OUTPUT
  echo -e "\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m"| tee -a $OUTPUT
  FAILED="$FAILED Section 5 ,"  
fi

#read -p "----------Press enter to continue......."
######################
## End of Section 5 ##
######################

if [ "${CRON}" != "cron" ] ;then
  #read -p "End of Security Check. Press enter to exit......."
  echo "End of Security Check. Press enter to exit......."
  sleep 1
fi

echo -e "\nSECURITY CHECK RESULT:\n"| tee -a $OUTPUT
result=`expr $fail_1 + $fail_2 + $fail_3 + $fail_4 + $fail_5`
if [ $result != 0 ];then
  echo -e "\033[1;31m\t!!!!!!!!!!!!!!!!\n\t!!!  FAILED  !!!\n\t!!!!!!!!!!!!!!!!\033[0m\n"| tee -a $OUTPUT
  echo -e "\033[1;31mFAILED on: $FAILED\033[0m\n"| tee -a $OUTPUT
  sed -i 's/\x1b\[[0-9;]*m//g' $OUTPUT
  result_P="FAILED"
#  `sudo mv ${OUTPUT} "${OUTPUT}.faild"`
  if [ "${FIRST_RUN}" == "1" ];then
    `sudo rm -rf ${CK_HOME}`
    echo -e "\033[1;31m\tFirst Run FAILD. Please Correct system setting then try again.\033[0m"
#  else
#    `sudo mv "${OUTPUT}.faild" "${OUTPUT}.faild.${DATE}.txt"`
#    OPFN=`basename "${OUTPUT}.faild.${DATE}.txt"`
#    `sudo mv "${OUTPUT}.faild.${DATE}.txt" ${CK_RECORD}`
#    report="${CK_RECORD}/${OPFN}"
  fi
else
  echo -e "\033[1;36m\t*****************\n\t***  SUCCESS  ***\n\t*****************\033[0m\n"| tee -a $OUTPUT
  sed -i 's/\x1b\[[0-9;]*m//g' $OUTPUT
  result_P="SCUESS"
  if [ "${FIRST_RUN}" == "1" ];then
  echo -e "\t\tPlease setup this script into root's crontab.\nExample:\n05 01 5 10 * ${CK_HOME}/security_ck.sh cron > /dev/null 2>&1\n"
  fi
  # DO_FTP=1
fi

`sudo mv ${OUTPUT} "${OUTPUT_F}.${result_P}"`
sudo mkdir -p "${OUTPUT_F}"
report="${OUTPUT_F}.${result_P}"

if [ "${FIRST_RUN}" != "1" ] || [ "${DO_FTP}" == "1" ];then
#  echo "${FIRST_RUN}, ${DO_FTP}"
  OPFN=`basename "${OUTPUT_F}.${result_P}"`
  N_OPFN_R="${OPFN}.${DATEs}.txt"
  N_OPFN_C="${OPFN}.txt"
  `sudo cp "/tmp/${OPFN}" "${CK_HOME}/${N_OPFN_C}"`

  `sudo mv "/tmp/${OPFN}" "${CK_RECORD}/${N_OPFN_R}"`
  report="${CK_RECORD}/${N_OPFN_R}"
fi

echo -e "\nSECURITY CHECK REPORT GENERATED:  ${report} \n"


if [ "${DO_FTP}" == "1" ];then
  FTPHOST=192.168.102.95
  FTP_ID=securitycheck
  FTP_PW="1qaz#EDC"
  FTP_PATH_C="${GROUP}"
  FTP_PATH_R="${GROUP}/1st_Run_Record"
ftp -n << EOF
  open ${FTPHOST}
  user ${FTP_ID} ${FTP_PW}
  lcd ${CK_HOME}
  mkdir ${FTP_PATH_C}
  cd ${FTP_PATH_C}
  asc
  prompt
  mdel "SYSTEM_Security_Check_${HOSTNAME}.*.txt"
  put ${N_OPFN_C}
EOF

  if [ "$FIRST_RUN" == "1"  ];then
ftp -n << EOF
  open ${FTPHOST}
  user ${FTP_ID} ${FTP_PW}
  lcd ${CK_RECORD}
  mkdir ${FTP_PATH_R}
  cd ${FTP_PATH_R}
  asc
  prompt
  put ${N_OPFN_R}
EOF
  fi
fi

exit 0