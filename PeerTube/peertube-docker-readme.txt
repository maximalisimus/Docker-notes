

curl https://raw.githubusercontent.com/chocobozzz/PeerTube/master/support/docker/production/docker-compose.yml > docker-compose.yml

curl https://raw.githubusercontent.com/Chocobozzz/PeerTube/master/support/docker/production/.env > .env

mkdir -p docker-volume/nginx
curl https://raw.githubusercontent.com/Chocobozzz/PeerTube/master/support/nginx/peertube > docker-volume/nginx/peertube

mkdir -p docker-volume/certbot
docker run -it --rm --name certbot -p 80:80 -v "$(pwd)/docker-volume/certbot/conf:/etc/letsencrypt" certbot/certbot certonly --standalone



$ mv env .env

$EDITOR ./docker-compose.yml

$EDITOR ./.env

In the downloaded example .env, you must replace:

<MY POSTGRES USERNAME>
<MY POSTGRES PASSWORD>
<MY DOMAIN> without 'https://'
<MY EMAIL ADDRESS>




docker run -it --rm --name certbot -p 80:80 -v "$(pwd)/docker-volume/certbot/conf:/etc/letsencrypt" certbot/certbot certonly --standalone

docker-compose up -d



docker-compose logs peertube | grep -A1 root



Obtaining Your Automatically Generated DKIM DNS TXT Record

DKIM signature sending and RSA keys generation are enabled by the default Postfix image mwader/postfix-relay with OpenDKIM.

Run cat ./docker-volume/opendkim/keys/*/*.txt to display your DKIM DNS TXT Record containing the public key to configure to your domain :

$ cat ./docker-volume/opendkim/keys/*/*.txt

peertube._domainkey.mydomain.tld.	IN	TXT	( "v=DKIM1; h=sha256; k=rsa; "
	  "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Dx7wLGPFVaxVQ4TGym/eF89aQ8oMxS9v5BCc26Hij91t2Ci8Fl12DHNVqZoIPGm+9tTIoDVDFEFrlPhMOZl8i4jU9pcFjjaIISaV2+qTa8uV1j3MyByogG8pu4o5Ill7zaySYFsYB++cHJ9pjbFSC42dddCYMfuVgrBsLNrvEi3dLDMjJF5l92Uu8YeswFe26PuHX3Avr261n"
	  "j5joTnYwat4387VEUyGUnZ0aZxCERi+ndXv2/wMJ0tizq+a9+EgqIb+7lkUc2XciQPNuTujM25GhrQBEKznvHyPA6fHsFheymOuB763QpkmnQQLCxyLygAY9mE/5RY+5Q6J9oDOQIDAQAB" )  ; ----- DKIM key peertube for mydomain.tld
	  




  volumes:
      - /home/docker/services/web/peertube/avatars:/PeerTube/avatars
      - /home/docker/services/web/peertube/certs:/PeerTube/certs
      - /home/docker/services/web/peertube/videos:/PeerTube/videos
      - /home/docker/services/web/peertube/logs:/PeerTube/logs
      - /home/docker/services/web/peertube/previews:/PeerTube/previews
      - /home/docker/services/web/peertube/thumbnails:/PeerTube/thumbnails
      - /home/docker/services/web/peertube/torrents:/PeerTube/torrents

	 
  volumes: # chocobozzz/peertube:production-bullseye
      - ./config:/config
	  - ./data:/data

chocobozzz/peertube-webserver:latest










