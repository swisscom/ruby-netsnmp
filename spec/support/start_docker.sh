sudo docker build --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -t snmp-server-emulator -f spec/support/Dockerfile .
sudo docker run -d -p :1161/udp --name test-snmp-emulator snmp-server-emulator \
  --agent-udpv4-endpoint=0.0.0.0:1161 --agent-udpv6-endpoint='[::0]:1161' \
  --v3-user=simulator --v3-auth-key=auctoritas --v3-priv-key=privatus \
  --v3-user=author --v3-auth-key=maplesyrup --v3-priv-proto=NONE \
  --v3-user=unsafe --v3-auth-proto=NONE --v3-priv-proto=NONE
sleep 20 # give some time for the simulator to boot


