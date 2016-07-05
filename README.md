# security_audit.sh

Script to check several vulnerabilities in MySQL

## Notice

This script was tested in:

* Linux
  * OS Distribution: CentOS release 6.5 (Final)

## Prerequisities

* MySQL client 

## How to use it

```
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
```

Example:
```
./security_audit.sh --hostname mysql-teste-2.dev.infra --username root --password xpto --db-type MYSQL
```

## License

This project is licensed under the MIT License - see the [License.md](License.md) file for details
