

Firewalld.

Archlinux:
sudo pacman -S firewalld --noconfirm

Debian:
# echo 'deb http://ftp.de.debian.org/debian sid main' > /etc/apt/sources.list.d/ftp.de.debian.org.list
sudo apt install firewalld -y


sudo systemctl enable firewalld.service
sudo systemctl start firewalld.service

Зоны.

drop - блокировать все входящие пакеты, разрешить только исходящие
block - в отличие от предыдущего варианта отправителю пакета будет отправлено сообщение по блокировке его пакета;
public - поддерживаются входящие соединения только для ssh и dhclient;
external - поддерживает NAT для скрытия внутренней сети;
internal - разрешены сервисы ssh, samba, mdns и dhcp;
dmz - используется для изолированных сервров, у которых нет доступа к сети. Разрешено только подключение по SSH;
work - разрешенны сервисы ssh и dhcp;
home - аналогично internal;
trusted - всё разрешено.

Конфигурации.

runtime - действительна только до перезагрузки, все изменения, в которых явно не указано другое, применяются к этой конфигурации;
permanent - постоянные настройки, которые будут работать и после перезагрузки.

Синтиксис.

firewall-cmd опции

Управление зонами.

firewall-cmd --конфигурация --zone=зона опции

В качестве конфигурации нужно указать опцию --permanent, чтобы сохранить изменения после перезагрузки 
или ничего не указывать, тогда изменения будут действительны только до перезагрузки. 
В качестве зоны используйте имя нужной зоны.

--state - вывести состояние брандмауэра;
--reload - перезагрузить правила из постоянной конфигурации;
--complete-reload - жёсткая перезагрузка правил с разрывом всех соединений;
--runtime-to-permanent - перенести настройки конфигурации runtime в постоянную конфигурацию;
--permanent - использовать постоянную конфигурацию;
--get-default-zone - отобразить зону, используемую по умолчанию;
--set-default-zone - установить зону по умолчанию;
--get-active-zones - отобразить активные зоны;
--get-zones - отобразить все доступные зоны;
--get-services - вывести предопределенные сервисы;
--list-all-zones - вывести конфигурацию всех зон;
--new-zone - создать новую зону;
--delete-zone - удалить зону;
--list-all - вывести всё, что добавлено, из выбранной зоны;
--list-services - вывести все сервисы, добавленные к зоне;
--add-service - добавить сервис к зоне;
--remove-service - удалить сервис из зоны;
--list-ports - отобразить порты, добавленные к зоне;
--add-port - добавить порт к зоне;
--remove-port - удалить порт из зоны;
--query-port - показать, добавлен ли порт к зоне;
--list-protocols - вывести протоколы, добавленные к зоне;
--add-protocol - добавить протокол к зоне;
--remove-protocol - удалить протокол из зоны;
--list-source-ports - вывести порты источника, добавленные к зоне;
--add-source-port - добавить порт-источник к зоне;
--remove-source-port - удалить порт-источник из зоны;
--list-icmp-blocks - вывести список блокировок icmp;
--add-icmp-block - добавить блокировку icmp;
--add-icmp-block - удалить блокировку icmp;
--add-forward-port - добавить порт для перенаправления в NAT;
--remove-forward-port - удалить порт для перенаправления в NAT;
--add-masquerade - включить NAT;
--remove-masquerade - удалить NAT.

Simple.

$ sudo firewall-cmd --state
# посмотреть зону по умолчанию
$ sudo firewall-cmd --get-default-zone
# изменить текущую зону с помощью опции --set-default-zone
$ sudo firewall-cmd --set-default-zone=public
# какие зоны используются для всех сетевых интерфейсов
$ sudo firewall-cmd --get-active-zones
# для зоны public
$ sudo firewall-cmd --zone=public --list-all
# посмотреть все предопределенные сервисы
$ sudo firewall-cmd --get-services
# Например, добавить к зоне к зоне, чтобы его разрешить. Подключение к http.
$ sudo firewall-cmd --zone=public --add-service=http --permanent
# чтобы удалить этот сервис
$ sudo firewall-cmd --zone=public --remove-service=http --permanent
# После изменений нужно обновить правила
$ sudo firewall-cmd --reload
$ sudo firewall-cmd --zone=public --list-all

КАК ОТКРЫТЬ ПОРТ В FIREWALLD

# Если для нужной вам программы нет сервиса, просто добавьте нужный порт к зоне вручную.
$ sudo firewall-cmd --zone=public --add-port=8083/tcp --permanent
# Чтобы удалить этот порт из зоны.
$ sudo firewall-cmd --zone=public --remove-port=8083/tcp --permanent

ПРОБРОС ПОРТОВ FIREWALLD

# Проборс портов в Firewalld настраивается намного проще, чем в iptables.
# Если вам нужно, например, перенаправить трафик с порта 2223 на порт 22, достаточно добавить к зоне перенаправление.
$ sudo firewall-cmd --zone=public --add-forward-port=port=2223:proto=tcp:toport=22

# Здесь перенаправление выполняется только на текущей машине. Если вы хотите настроить сеть NAT 
# и пробрасывать порт на другую машину, то вам нужно сначала включить поддержку masquerade.
$ sudo firewall-cmd --zone=public --add-masquerade
# Затем уже можно добавить порт
$ sudo firewall-cmd --zone=publiс --add-forward-port=port=2223:proto=tcp:toport=22:toaddr=192.168.56.4 --permanent

РАСШИРЕННЫЕ ПРАВИЛА

rule family="семейтво" source значение destination значение log audit действие

В качестве семейства протоколов можно указать ipv4 или ipv6 или ничего не указывать, тогда правило будет применяться к обоим протоколам;
source и destination - это отправитель и получатель пакета. 
		В качестве этих параметров может быть использован IP-адрес (address), сервис (service name), порт (port), протокол (protocol) и так далее;
log - позволяет логгировать прохождение пакетов, например в syslog. 
		В этой настройке вы можете указать префикс строчки лога и уровень подробности логгирования;
audit - это альтернативный способ логгирования, когда сообщения будут отправляться в службу auditd.
Действие - это действие, которое необходимо выполнить с совпавшим пакетом. Доступны: accept, drop, reject, mark.

Example.

# Нам необходимо заблокировать доступ к серверу для пользователя с IP 135.152.53.5.
$ sudo firewall-cmd --zone=public --add-rich-rule 'rule family="ipv4" source address=135.152.53.5 reject'

# Или нам нужно запретить для этого же пользователя только доступ к порту 22.
$ sudo firewall-cmd --zone=public --add-rich-rule 'rule family="ipv4" source address=135.152.53.5 port port=22 protocol=tcp reject'

# Посмотреть все расширенные правила можно командой
$ sudo firewall-cmd --list-rich-rules



Example cockpit and forwarding 80 to 5000.

sudo firewall-cmd --add-service=cockpit
sudo firewall-cmd --add-service=cockpit --permanent
sudo firewall-cmd --add-forward-port=port=80:proto=tcp:toport=5000 --permanent
sudo firewall-cmd --reload
















