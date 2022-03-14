

---
version: '2'
services:
	dokuwiki:
		image: docker.io/bitnami/dokuwiki:latest
		restart: always
		ports:
			- '8888:8080'
			- '9999:8443'
		volumes:
			- /app/dokuwii/dokuwiki-persistence:/bitnami
		environment:
			- DOKUWIKI_USERNAME=User
			- DOKUWIKI_PASSWORD=123456
			- DOKUWIKI_WIKI_NAME=BazaZnaniy


---
version: "2.1"
services:
  dokuwiki:
    image: lscr.io/linuxserver/dokuwiki
    container_name: dokuwiki
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/London
    volumes:
      - /path/to/appdata/config:/config
    ports:
      - 80:80
      - 443:443 #optional
    restart: unless-stopped



---
version: '2'
services:
  dokuwiki:
    image: docker.io/bitnami/dokuwiki:20200729
    ports:
      - '80:8080'
      - '443:8443'
    volumes:
      - 'dokuwiki_data:/bitnami/dokuwiki'
volumes:
  dokuwiki_data:
    driver: local
    


Переходим Управление → Управление дополнениями
	В «Установленные плагины» устанавливаем плагин Indexmenu Plugin
	В «Установленные шаблоны» устанавливаем шаблон Bootstrap3 Template Giuseppe Di Terlizzi
Создаем в корне dokuwiki страничку с именем sidebar.txt (в файловой системе он лежит в папке data/pages) и следующим содержимым:

{{indexmenu>..#1|js#thread navbar nsort tsort}}

~~NOCACHE~~

Расшифровка магии:
{{indexmenu>..:#1}} - Отображать пространство имен родителя и текущий уровень, не разворачивать ноды
js#thread - использовать JS, тема "thread"
navbar - Разворачивать дерево текущего неймспейса
nsort tsort - сортировка страниц в алфавитном порядке
Если нужно скрывать всплывающее меню - используйте nomenu
Все параметры тут: https://www.dokuwiki.org/plugin:indexmenu#full_syntax

Переходим Управление → Настройки вики
	В разделе «Параметры «ДокуВики»» устанавливаем:
		template / Шаблон: bootstrap3
		sidebar / Боковая панель, пустое поле отключает боковую панель: sidebar
	В разделе «Параметры плагинов» → Indexmenu устанавливаем скрываемые страницы:
		plugin»indexmenu»skip_file / Список страниц для пропуска: /^sidebar$/
	В разделе «Параметры шаблонов» → Bootstrap3 ставим галочки по желанию для изменения внешнего вида, подключения тем, включения/отключения функций на панели навигации и т.д. Из функционального:
		tpl»bootstrap3»showCookieLawBanner / Display the Cookie Law banner on footer: выкл
		tpl»bootstrap3»fixedTopNavbar / Зафиксировать панель навигации сверху: вкл
		tpl»bootstrap3»fluidContainer / Разрешить плавающий контейнер(страница во весь экран): вкл
		tpl»bootstrap3»fluidContainerBtn / Display a button in navbar to expand container: вкл
		tpl»bootstrap3»pageOnPanel / Включить рамку вокруг страницы: вкл
		tpl»bootstrap3»tableFullWidth / Разрешить таблицы в 100% ширину: вкл

Настройки

Параметры «Докувики» / Параметры отображения / Первый заголовок вместо имени страницы (useheading) - Только в навигации
Indexmenu / Скрывать заглавные страницы (hide_headpage) - Отключено

Изменяем тему sidebar

Если стандартная тема сайдбара не нравится, изменяем ее легко и просто: в строке

{{indexmenu>..#1|js#thread navbar nsort tsort}}

Изменяем цвет sidebar
По умолчанию sidebar зеленого цвета. 
Чтобы изменить цвет на ваш любимый открываем Управление → Настройка стилей шаблона и меняем existing на #337ab7 (синий цвет), 
и нажимаем «Сохранить изменения»

Меняем лого и favicon

	Заходим в «Управление медиафайлами»
	Выбираем каталог «wiki»
	Загружаем по очереди файлы logo.png и favicon.ico - это и будет замена стандартным изображениям

Как добавить сайдбар справа (по аналогии с левым)
	Устанавливаем тему Bootstrap3 как описано выше, проверяем настройки в разделе Боковая панель (они уже должны быть по умолчанию):
		tpl»bootstrap3»rightSidebar: rightsidebar
		tpl»bootstrap3»rightSidebarGrid: col-sm-3 col-md-2
	Создаем страницу rightsidebar.txt в корне вики со следующим содержимым:
		~~NOCACHE~~
	В разделе «Параметры плагинов» → Indexmenu устанавливаем скрываемые страницы:
		plugin»indexmenu»skip_file / Список страниц для пропуска: /^sidebar$|^rightsidebar$/



https://php-ru.info/editor.html
https://pandoc.org/try/?text&from=html&to=dokuwiki

<code>

</code>












