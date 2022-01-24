##################################################
## Section 6 : Additional Security Poilcy Check ##
##################################################
fail_6=0
echo -e "Section 6 : Additional Security Poilcy Check "| tee -a $OUTPUT
echo -e "\n\t6.1 VIM Security Check ( /etc/vimrc ; CVE-2019-12735)"| tee -a $OUTPUT
  vim_version=`vim --version|head -1 | awk 'BEGIN{FS=" "};{print $5}'`
  if [ -z ${vim_version} ] ; then
  echo -e " No installed VIM package be found on this server."
  echo -e "\033[1;36m\tVIM Security Checked and Pass.\033[0m"
  else
    version_tr=$(awk '{print $1*$2}' <<<"${vim_version} 10")
    require_ver=81
    echo -e "\tVIM version: $vim_version"| tee -a $OUTPUT
    if [ ${version_tr} -lt ${require_ver} ]; then
      vim_ckv=`vim -es -c 'set modeline?' -c 'quit'`
      vim_keyw=`cat /etc/vimrc | grep set | grep nomodeline`
      if [ ${vim_ckv} == 'nomodeline' ];then
        echo -e "\033[1;36m\tVIM Security Checked and Pass.\033[0m"
      else
        test "$vim_keyw" && echo -e "\t/etc/vimrc nomodeline setting inclued.\n \n\033[1;36mVIMRC FILE Checked and Pass\033[0m\n"| tee -a $OUTPUT
        test -z "$vim_keyw" && echo -e "\033[1;31mCan't find nomodeline setting!!\033[0m" | tee -a $OUTPUT&& fail_6=$((fail_6+1))
      fi
    else
      echo -e "\t\033[1;36mVersion of VIM package Updated and Check Pass.\033[0m\n"| tee -a $OUTPUT
   
    fi
  fi


if [ $fail_6 != 0 ] ;then 
  echo -e "\n\033[1;31m\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\t\t\t!!!!!!!!  Section 6 check failed!!  !!!!!!!\n\t\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\033[0m"| tee -a $OUTPUT
  FAILED="$FAILED Section 6 ,"  
fi

######################
## End of Section 6 ##
######################