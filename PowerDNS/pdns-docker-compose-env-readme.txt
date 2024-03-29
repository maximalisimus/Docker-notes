

pdns-master:
docker-compose.yml

version: '3.1'
services:

  mariadb:
    image: mariadb:latest
    container_name: mariadb
    restart: unless-stopped
    # hostname: mariadb
    ports: # expose
      - 3306:3306
    environment:
      MYSQL_ROOT_PASSWORD: 'powerdns'
      MYSQL_DATABASE: 'powerdns'
      MYSQL_USER: 'powerdns'
      MYSQL_PASSWORD: 'powerdns'
    volumes:
      - ./mysql-master:/var/lib/mysql

  adminer:
    image: adminer
    restart: always
    ports:
      - 8080:8080

  pdnsmaster:
    image: pschiffe/pdns-mysql
    container_name: pdnsmaster
    restart: unless-stopped
    hostname ns1.debian.local
    ports:
      - 53:53
      - 53:53/udp
    link:
      - mariadb:mysql
    environment:
      - PDNS_master=yes
      - PDNS_api=yes
      - PDNS_api_key=secret # jdnAJHwFflX2 A8DAhUMgL3Kv slave
      # openssl rand -base64 12 | sed 's/[^0-9.a-zA-Z]*//g'
      - PDNS_webserver=yes
      - PDNS_webserver_address=0.0.0.0
      - PDNS_webserver_password=secret2
      - PDNS_version_string=anonymous
      - PDNS_default_ttl=1500
      - PDNS_soa_minimum_ttl=1200
      - PDNS_default_soa_name=ns1.debian.local
      - PDNS_default_soa_mail=hostmaster.debian.local
      # PDNS_allow_axfr_ips=192.168.100.45
      # PDNS_only_notify=192.168.100.45
      # PDNS_webserver_allow_from=172.5.0.0/16 # example configuration for PowerDNS 4.x
      # PowerDNS server, for example 4.0.1
      - PDNS_API_URL="http://192.168.0.120:8081/"
      - PDNS_VERSION="4.1.1"
      - PDNS_gmysql_host=mariadb
      - PDNS_gmysql_port=3306
      - PDNS_gmysql_user='powerdns'
      - PDNS_gmysql_password='powerdns'
      - PDNS_gmysql_dbname='powerdns'

  pdnsuwsgi:
    image: pschiffe/pdns-admin-uwsgi:ngoduykhanh
    container_name: pdnsuwsgi
    restart: unless-stopped
    environment:
      - PDNS_ADMIN_SQLA_DB_HOST='mariadb'
      - PDNS_ADMIN_SQLA_DB_PORT='3306'
      - PDNS_ADMIN_SQLA_DB_USER='powerdns'
      - PDNS_ADMIN_SQLA_DB_PASSWORD='powerdns'
      - PDNS_ADMIN_SQLA_DB_NAME='powerdns'
    volumes:
      - ./pdns-admin-upload:/opt/powerdns-admin/upload
    link:
      - mariadb:mysql
      - pdnsmaster:pdns

  pdnsstatic:
    image: pschiffe/pdns-admin-static:ngoduykhanh
    container_name: pdnsstatic
    restart: unless-stopped
    ports:
      - 8585:80
    link:
      - pdnsuwsgi:pdns-admin-uwsgi








pdns-slave:
docker-compose.yml

version: '3.1'
services:

  mariadb:
    image: mariadb:latest
    container_name: mariadb
    restart: unless-stopped
    # hostname: mariadb
    # ports:
      # 3306:3306
    expose: '3306'
    environment:
      MYSQL_ROOT_PASSWORD: 'powerdnsslave'
      MYSQL_DATABASE: 'powerdnsslave'
      MYSQL_USER: 'powerdnsslave'
      MYSQL_PASSWORD: 'powerdnsslave'
    volumes:
      - ./mysql:/var/lib/mysql

  adminer:
    image: adminer
    restart: always
    ports:
      - 8080:8080

  pdnsslave:
    image: pschiffe/pdns-mysql
    container_name: pdnsslave
    restart: unless-stopped
    hostname: ns2.debian.local
    ports:
      - 53:53
      - 53:53/udp
    link: 
      - mariadb:mysql
    environment:
      - PDNS_gmysql_host=mariadb
      - PDNS_gmysql_port=3306
      - PDNS_gmysql_user=powerdnsslave
      - PDNS_gmysql_password=powerdnsslave
      - PDNS_gmysql_dbname=powerdnsslave
      - PDNS_slave=yes
      - PDNS_version_string=anonymous
      - PDNS_disable_axfr=yes
      # PDNS_allow_notify_from=192.168.100.160
      # SUPERMASTER_IPS=192.168.100.160







pdns-recursor:
docker-compose.yml

version: '3.1'
services:

  pdns-recursor:
    image: pschiffe/pdns-recursor
    container_name: dns-recursor
    restart: unless-stopped
    ports:
      - 53:53
      - 53:53/udp
    environment:
      - PDNS_api_key=secret
      - PDNS_webserver=yes
      - PDNS_webserver_address=0.0.0.0
      - PDNS_webserver_password=secret2
      
















