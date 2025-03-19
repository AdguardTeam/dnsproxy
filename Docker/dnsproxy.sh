#!/bin/bash

COMMAND="dnsproxy"
LISTENADDR=$LISTEN
SRVPORT=$SRVPORT
CERTPATH=/etc/letsencrypt/live/$DOMAIN/fullchain.pem
KEYPATH=/etc/letsencrypt/live/$DOMAIN/privkey.pem
UPSTREAM=$UPSTREAM_ADDR
RATELIMIT=$RATELIMIT
EDNSFLAG=$EDNS
EDNSIP=$EDNSIP
PORT=$LOCALPORT
PROTOCOL=$PROTO

case $PROTOCOL in
	"quic") SWITCHPORT="-q $SRVPORT --tls-crt=$CERTPATH --tls-key=$KEYPATH";;
	"tls") SWITCHPORT="-t $SRVPORT --tls-crt=$CERTPATH --tls-key=$KEYPATH";;
	"https") SWITCHPORT="--https-port $SRVPORT --tls-crt=$CERTPATH --tls-key=$KEYPATH";;
	"dnscrypt") SWITCHPORT="-y $SRVPORT --tls-crt=$CERTPATH --tls-key=$KEYPATH";;
esac

case $MODE in
	"server") LISTENSWITCH="-l $LISTENADDR";
		  if [[ ! -f $CERTPATH ]]
		  then
			  echo "Waiting for letsencrypt cert to be created"
			  sleep 8;
		  fi;;

	"client") LISTENSWITCH=" ";
		  SWITCHPORT=" ";;
esac

if [[ $EDNSFLAG == "" ]]
then
	$COMMAND $LISTENSWITCH $SWITCHPORT -u $UPSTREAM -r $RATELIMIT -p $PORT
else
	$COMMAND $LISTENSWITCH $SWITCHPORT -u $UPSTREAM -r $RATELIMIT --edns -p $PORT
fi

#dnsproxy -l 0.0.0.0 -q 785 --tls-crt=/etc/letsencrypt/live/$DOMAIN/fullchain.pem --tls-key=/etc/letsencrypt/live/$DOMAIN/privkey.pem -u 192.168.2.1:53 -r 100 --edns -p $PORT
