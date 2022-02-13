

https://brainycp.com/download

Минимальные системные требования:
ОС: CentOS 7 64bit, CentOS 8 64bit
RAM: min 1GB
SWAP: min 1GB
Диск: 2GB на корневом разделе /
Процессор: от 266mhz
Рекомендуемые системные требования:
ОС: CentOS 7 64bit, CentOS 8 64bit
RAM: 2GB
SWAP: 2GB
Диск: 10GB на корневом разделе /
Процессор: от 266mhz


yum clean all && yum install -y wget && wget -O install.sh http://core.brainycp.com/install.sh && bash ./install.sh


yum clean all && yum install -y wget && wget -O install.sh http://core.brainycp.com/install.sh && bash ./install.sh \
--package=apache2.4,nginx,php52w,php53w,php54w,php55w,php56w,php70w,php71w,php72w,php73w,php74w,php80w,bindserver,memcached,\
ffmpeg,imagemagick,httpry,certbot,megacli,iotop,atop,iftop,logrotate,git,shellinabox,MariaDB10.5,phpMyAdmin-4.9.4,exim,\
spamassassin,clamav,proftpd,csf






wget http://core.brainycp.ru/install.sh

sh install.sh

firewall-cmd --permanent --zone=public --add-port=8002/tcp
firewall-cmd --reload

reboot

Подключение
После перезагрузки вы можете подключиться к панели BrainyCP из браузера по следующему адресу:
http://<Ваш_IP-адрес>:8002

Например:
http://111.111.111.111:8002

В открывшемся окне введите логин и пароль пользователя сервера.


