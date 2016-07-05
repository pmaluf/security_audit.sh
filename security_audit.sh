#!/bin/bash
#
# security_audit.sh - Realiza verificacoes de seguranca no banco de dados
# Created: Paulo Victor Maluf - 06/2014
#
# Parameters:
#
#   security_audit.sh --help
#
#    Parameter           Short Description                                                        Default
#    ------------------- ----- ------------------------------------------------------------------ --------------
#    --hostname             -H [REQUIRED] Hostname will be audited                                localhost
#    --port                 -P [OPTIONAL] Port to connect to database
#    --username             -u [OPTIONAL] DB username
#    --password             -p [OPTIONAL] DB password
#    --db-type              -t [REQUIRED] Database type: MYSQL or ORACLE
#    --help                 -h [OPTIONAL] help
#
#   Ex.: security_audit.sh --hostname <HOST> --username <DBUSER> --password <DBPASS> --db-type <DBTYPE>
#        security_audit.sh --hostname mysql-teste-2.dev.infra --username root --password xpto --db-type MYSQL
#
# Changelog:
#
# Date       Author               Description
# ---------- ------------------- ----------------------------------------------------
#====================================================================================

# Carrega a lib de monitoracao
. /u00/scripts/.lib $0

# Global Variables
HOST="localhost"

# Functions
f_help(){
 head -28 $0 | tail -27
 exit 0
}

log(){
 MSG=$1
 COLOR=$2
 if [ "${COLOR}." == "blue." ]
  then
     echo -ne "\e[34;1m${MSG}\e[m" | tee -a ${LOG}
  elif [ "${COLOR}." == "yellow." ]
    then
      echo -ne "\e[33;1m${MSG}\e[m" | tee -a ${LOG}
  elif [ "${COLOR}." == "green." ]
    then
      echo -ne "\e[32;1m${MSG}\e[m" | tee -a ${LOG}
  elif [ "${COLOR}." == "red." ]
    then
      echo -ne "\e[31;1m${MSG}\e[m" | tee -a ${LOG}
      #sendmail ${MSG}
  else
    echo -ne "${MSG}" | tee -a ${LOG}
 fi
}

# MYSQL FUNCTIONS
check_mysql_conn(){
 log "Checking MySQL connection: " blue
 ${MYSQL} -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "exit" > /dev/null 2>&1
 [ "$?." != "0." ] && { log " [Critical] " red ; log "Can't connect to MySQL! Please check your username and password.\n" ;  exit 1 ;} || log "[ OK ]\n" green
}

check_mysql_version(){
 log "MySQL version: " blue
 ${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select @@version;" 2> /dev/null
 [ "$?." != "0." ] && { log " [Critical] " red ; log "Can't get MySQL version.\n" red ; }
}

check_mysql_db_test(){
 log "Checking 'test' database: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select count(1) from information_schema.schemata where schema_name = 'test';" 2> /dev/null`
 [ "${CHK}." !=  "0." ] && { log " [Warning]\n" yellow ; log "  Database test found! Please remove it.\n" ; } ||  log "[ OK ]\n" green
}

check_mysql_root(){
 log "Checking root user: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select count(1) from mysql.user where user = 'root';" 2> /dev/null`
 [ "${CHK}." !=  "0." ] && { log " [Warning]\n" yellow ; log "  User 'root' found! Consider change it.\n" ; } || log "[ OK ]\n" green
}

check_mysql_hash(){
 log "Checking weak password hashes: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select distinct concat(user,'@',host) from mysql.user where length(password) < 41 AND length(password) > 0;" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red ; log "  The following users were found having weak password hashes: `echo ${CHK}|xargs` .\n" ; }  || log "[ OK ]\n" green
}

check_mysql_wildcard(){
 log "Checking users with '%' in hostname: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select distinct concat(user,'@',host) from mysql.user where host = '%';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red ; log "  The following users were found with '%' in hostname: " ; log "`echo ${CHK}|xargs`.\n" ; }  || log "[ OK ]\n" green
}

check_mysql_blank_pass(){
 log "Checking users with blank passwords: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select distinct concat(user,'@',host) from mysql.user where length(password) = 0 or password is null;" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users were found with blank passwords: " ; log "`echo ${CHK}|xargs`.\n" ; }  || log "[ OK ]\n" green
}

check_mysql_anon(){
 log "Checking anonymous accounts: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select count(1) from mysql.user where user ='';" 2> /dev/null`
 [ "${CHK}." !=  "0." ] && { log " [Critical]\n" red  ; log "  Anonymous account found! Please run mysql_secure_installation to remove it. ASAP! " ; log "`echo ${CHK}|xargs`.\n" ; }  || log "[ OK ]\n" green
}

check_mysql_database_access(){
 log "Checking users with access on 'mysql' database: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host)
                                                                           from mysql.db
                                                                          where db = 'mysql' and ((Select_priv = 'Y')
                                                                             or (Insert_priv = 'Y') or (Update_priv = 'Y')
                                                                             or (Delete_priv = 'Y') or (Create_priv = 'Y') or (Drop_priv = 'Y'))" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have access to the MySQL database: " ; log "`echo ${CHK}|xargs`.\n" ; }  || log "[ OK ]\n" green
}

check_mysql_drop_grant(){
 log "Checking users with CREATE or DROP grants: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host)
                                                                           from mysql.user
                                                                          where user not in ('root') and ((Create_priv = 'Y') or (Drop_priv = 'Y'));" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Warning]\n" yellow  ; log "  The following users have CREATE or DROP grants: " ; log "`echo ${CHK}|xargs`.\n" ; }  || log "[ OK ]\n" green
}

check_mysql_file_grant(){
 log "Checking users with FILE grant: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host) from mysql.user where user not in ('root') and File_priv = 'Y';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have FILE grant: " ; log "`echo ${CHK}|xargs`.\n" ; log "  *** Do not grant FILE privileges to non Admin users ***\n" red ; }  || log "[ OK ]\n" green
}

check_mysql_process_grant(){
 log "Checking users with PROCESS grant: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host) from mysql.user where user not in ('root','nagios','zabbixmonitor','backup') and Process_priv = 'Y';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have PROCESS grant: " ; log "`echo ${CHK}|xargs`.\n" ; log "  *** Do not grant PROCESS privileges to non Admin users ***\n" red ; }  || log "[ OK ]\n" green
}

check_mysql_super_grant(){
 log "Checking users with SUPER grant: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host) from mysql.user where user not in ('root','backup','nagios','zabbixmonitor') and Super_priv = 'Y';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have SUPER grant: " ; log "`echo ${CHK}|xargs`.\n" ; log "  *** Do not grant SUPER privileges to non Admin users ***\n" red ; }  || log "[ OK ]\n" green
}

check_mysql_shutdown_grant(){
 log "Checking users with SHUTDOWN grant: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host) from mysql.user where user not in ('root') and Shutdown_priv = 'Y';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have SHUTDOWN grant: " ; log "`echo ${CHK}|xargs`.\n" ; log "  *** Do not grant SHUTDOWN privileges to non Admin users ***\n" red ; }  || log "[ OK ]\n" green
}

check_mysql_create_user_grant(){
 log "Checking users with CREATE USER grant: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host) from mysql.user where user not in ('root') and Create_user_priv = 'Y';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have CREATE USER grant: " ; log "`echo ${CHK}|xargs`.\n" ; log "  *** Do not grant CREATE USER privileges to non Admin users ***\n" red ; }  || log "[ OK ]\n" green
}

check_mysql_reload_grant(){
 log "Checking users with RELOAD grant: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host) from mysql.user where user not in ('root') and Reload_priv = 'Y';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have RELOAD grant: " ; log "`echo ${CHK}|xargs`.\n" ; log "  *** Do not grant RELOAD privileges to non Admin users ***\n" red ; }  || log "[ OK ]\n" green
}

check_mysql_grant_grant(){
 log "Checking users with GRANT grant: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "select concat(user,'@',host) from mysql.user where user not in ('root') and Grant_priv = 'Y';" 2> /dev/null`
 [ "${CHK}." !=  "." ] && { log " [Critical]\n" red  ; log "  The following users have GRANT grant: " ; log "`echo ${CHK}|xargs`.\n" ; log "  *** Do not grant GRANT privileges to non Admin users ***\n" red ; }  || log "[ OK ]\n" green
}

check_mysql_local_infile(){
 log "Checking if local_infile variable is ON: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "show global variables like 'local_infile'" 2> /dev/null | awk '{print $2}'`
 [ "${CHK}." !=  "OFF." ] && { log " [Critical]\n" red  ; log "  The local_infile variable is ON, please disable it.\n " ; }  || log "[ OK ]\n" green
}

check_mysql_old_pass(){
 log "Checking if old_passwords variable is OFF: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "show global variables like 'old_passwords'" 2> /dev/null | awk '{print $2}'`
 [ "${CHK}." !=  "OFF." ] && { log " [Critical]\n" red  ; log "  The old_passwords variable is ON, please disable it.\n " ; }  || log "[ OK ]\n" green
}

check_mysql_safe_show(){
 log "Checking if secure_auth variable is ON: " blue
 CHK=`${MYSQL} -s -N -u${USER} -p${PASS} -h ${HOST} -P ${PORT:-3306} -e "show global variables like 'secure_auth'" 2> /dev/null | awk '{print $2}'`
 [ "${CHK}." !=  "ON." ] && { log " [Critical]\n" red  ; log "  The secure_auth variable is OFF, please enable it.\n " ; }  || log "[ OK ]\n" green
}

# Parameters
for arg
do
    delim=""
    case "$arg" in
    #translate --gnu-long-options to -g (short options)
      --hostname)        args="${args}-H ";;
      --port)            args="${args}-P ";;
      --username)        args="${args}-u ";;
      --password)        args="${args}-p ";;
      --db-type)         args="${args}-t ";;
      --list)            args="${args}-l ";;
      --help)            args="${args}-h ";;
      #pass through anything else
      *) [[ "${arg:0:1}" == "-" ]] || delim="\""
         args="${args}${delim}${arg}${delim} ";;
    esac
done

eval set -- $args

while getopts ":hH:P:p:u:t:lh:" PARAMETRO
do
    case $PARAMETRO in
        h) f_help;;
        H) HOST=${OPTARG[@]};;
        P) PORT=${OPTARG[@]};;
        u) USER=${OPTARG[@]};;
        p) PASS=${OPTARG[@]};;
        t) DB_TYPE=${OPTARG[@]};;
        l) list ;;
        :) echo "Option -$OPTARG requires an argument."; exit 1;;
        *) echo $OPTARG is an unrecognized option ; echo $USAGE; exit 1;;
    esac
done

[ "$1" ] || f_help

#########################
# Main                  #
#########################
if [ "${DB_TYPE}." == "MYSQL." ]
 then
   MYSQL=`which mysql`
   check_mysql_conn
   check_mysql_version
   check_mysql_db_test
   check_mysql_root
   check_mysql_hash
   check_mysql_wildcard
   check_mysql_blank_pass
   check_mysql_anon
   check_mysql_database_access
   check_mysql_drop_grant
   check_mysql_file_grant
   check_mysql_process_grant
   check_mysql_super_grant
   check_mysql_shutdown_grant
   check_mysql_create_user_grant
   check_mysql_reload_grant
   check_mysql_grant_grant
   check_mysql_local_infile
   check_mysql_old_pass
   check_mysql_safe_show
elif [ "${DB_TYPE}." == "ORACLE." ]
 then
  log "Sorry, Oracle isn't supported yet.\n"
else
 f_help
fi
