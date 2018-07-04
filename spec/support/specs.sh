#!/usr/bin/env bash

function start {
  docker pull honeyryderchuck/snmp-server-emulator:latest
  docker run -d -p :1161/udp --name test-snmp -v $(pwd)/spec/support/snmpsim:/home/snmp_server/.snmpsim honeyryderchuck/snmp-server-emulator \
  --v3-engine-id=000000000000000000000002 \
  --agent-udpv4-endpoint=0.0.0.0:1161 --agent-udpv6-endpoint='[::0]:1161' \
  --v3-user=simulator --v3-auth-key=auctoritas --v3-priv-key=privatus \
  --v3-user=authmd5 --v3-auth-key=maplesyrup --v3-auth-proto=MD5 --v3-priv-proto=NONE \
  --v3-user=authsha --v3-auth-key=maplesyrup --v3-auth-proto=SHA --v3-priv-proto=NONE \
  --v3-user=authprivshaaes --v3-auth-key=maplesyrup --v3-auth-proto=SHA \
                           --v3-priv-key=maplesyrup --v3-priv-proto=AES \
  --v3-user=authprivmd5aes --v3-auth-key=maplesyrup --v3-auth-proto=MD5 \
                           --v3-priv-key=maplesyrup --v3-priv-proto=AES \
  --v3-user=authprivshades --v3-auth-key=maplesyrup --v3-auth-proto=SHA \
                           --v3-priv-key=maplesyrup --v3-priv-proto=DES \
  --v3-user=authprivmd5des --v3-auth-key=maplesyrup --v3-auth-proto=MD5 \
                           --v3-priv-key=maplesyrup --v3-priv-proto=DES \
  --v3-user=unsafe --v3-auth-proto=NONE --v3-priv-proto=NONE

}

function run {
  sleep 20 # give some time for the simulator to boot
  
  port="$(docker port test-snmp 1161/udp)"
  export SNMP_PORT=$(echo $port | cut -d':' -f2)
  
  bundle exec rake spec:ci
}

function finish {
  docker stop test-snmp
  docker rm test-snmp
}

trap finish EXIT

case "$1" in
  start)
    start
    docker logs -f test-snmp
    ;;
  run)
    start
    run
    ;;
  *)
    echo $"Usage: $0 {start|run}"
    exit 1
esac
