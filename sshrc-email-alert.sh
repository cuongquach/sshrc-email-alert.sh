#!/bin/bash
## Author : Quach Chi Cuong
## Last updated : 09/2016
## Description :
## - This script is used by service ssh to run a script after user login to system successfully. The main purpose in this
## script is to send email 
## Path : /etc/ssh/sshrc
## Location of log authentication
#### Centos : /var/log/secure
#### Debian : /var/log/auth.log


## Variable zone for editting ##
DOMAIN="9am.vn"
EMAIL_ADMIN="cuongqc@vinahost.vn"



################################
###### Progress variable #######
USER_LOGIN=`echo ${LOGNAME}`
IP_LOGIN=`echo ${SSH_CONNECTION} | awk '{print $1}'`
TIME_LOGIN=`/usr/bin/last -i ${USER_LOGIN} | head -1 | awk '{print $7}'`
METHOD_LOGIN="non-defined"
RD_STRING=`date +%s | sha256sum | base64 | head -c 12 ; echo`
REPORT=/tmp/ssh_login_report.${RD_STRING}.txt
HOSTNAME=`echo ${HOSTNAME}`

## Determine the method login ##
if [ -f /var/log/secure ];then
    if [[ $(tail -n 100 /var/log/secure | grep "${USER_LOGIN}" | grep "${IP_LOGIN}" | grep "${TIME_LOGIN}" | grep -o "publickey") ]];then
        METHOD_LOGIN="private/public-key auth"
    elif [[ $(tail -n 100 /var/log/secure | grep "${USER_LOGIN}" | grep "${IP_LOGIN}" | grep "${TIME_LOGIN}" | grep -o "password") ]];then
        METHOD_LOGIN="password auth"
    fi
elif [ -f /var/log/auth.log ];then
    if [[ $(tail -n 100 /var/log/auth.log | grep "${USER_LOGIN}" | grep "${IP_LOGIN}" | grep "${TIME_LOGIN}" | grep -o "publickey") ]];then
        METHOD_LOGIN="private/public-key auth"
    elif [[ $(tail -n 100 /var/log/auth.log | grep "${USER_LOGIN}" | grep "${IP_LOGIN}" | grep "${TIME_LOGIN}" | grep -o "password") ]];then
        METHOD_LOGIN="password auth"
    fi
fi

create_report()
{
    if [[ -f ${REPORT} ]];then
        rm -f ${REPORT}
    fi

cat << EOF > ${REPORT}
REPORT USER LOGIN TO SERVER ${HOSTNAME}
=======================================
User : ${USER_LOGIN}
IP from : ${IP_LOGIN}
Time login : ${TIME_LOGIN}
Method login : ${METHOD_LOGIN}
EOF

}

send_mail()
{
    if [ -z ${DOMAIN} ];then
        DOMAIN=${HOSTNAME}
    fi

    ## Check variable email with simple method, valid character '@'
    ## Check postition 1 and second after '@' is not null
    if [[ $(echo ${EMAIL_ADMIN} | grep "\@") ]];then
        POS1=$(echo ${EMAIL_ADMIN} | sed 's/\@/ /g' | awk '{print $1}')
        POS2=$(echo ${EMAIL_ADMIN} | sed 's/\@/ /g' | awk '{print $2}')
        if [[ ! -z ${POS1} && ! -z ${POS2} ]];then
            mail -r "(Admin ${DOMAIN}) admin@${DOMAIN}" -s "[QMTC] ${USER_LOGIN} from ${IP_LOGIN} ssh logged-in to ${HOSTNAME} " ${EMAIL_ADMIN} < ${REPORT} || echo "- Fail to send email to ${EMAIL_ADMIN}"
        fi
    fi
    
}

end_script()
{
    if [[ -f ${REPORT} ]];then
        sleep 1
        rm -f ${REPORT}
    fi
}

## Main functions  ###
create_report
send_mail
end_script

exit 0