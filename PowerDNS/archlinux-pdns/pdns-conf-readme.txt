

mysql -u pdnsadmin -p kifarunixdemopdns < /usr/share/pdns-backend-mysql/schema/schema.mysql.sql

Configure PowerDNS Database Connection Details

cat > /etc/powerdns/pdns.d/pdns.local.gmysql.conf << 'EOL'
# MySQL Configuration
#
# Launch gmysql backend
launch+=gmysql

# gmysql parameters
gmysql-host=127.0.0.1
gmysql-port=3306
gmysql-dbname=kifarunixdemopdns
gmysql-user=pdnsadmin
gmysql-password=PdnSPassW0rd
gmysql-dnssec=yes
# gmysql-socket=
EOL

chown pdns: /etc/powerdns/pdns.d/pdns.local.gmysql.conf
chmod 640 /etc/powerdns/pdns.d/pdns.local.gmysql.conf

systemctl restart pdns

















