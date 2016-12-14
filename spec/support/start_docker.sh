sudo docker build --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy -t snmp-server-emulator -f spec/support/Dockerfile .
sudo docker run -d -p :1161/udp --name test-snmp-emulator snmp-server-emulator \
  --agent-udpv4-endpoint=0.0.0.0:1161 --agent-udpv6-endpoint='[::0]:1161' \
  --v3-user=simulator --v3-auth-key=auctoritas --v3-priv-key=privatus \
  --v3-user=authmd5 --v3-auth-key=maplesyrup --v3-auth-proto=MD5 --v3-priv-proto=NONE \
  --v3-user=authsha --v3-auth-key=maplesyrup --v3-auth-proto=SHA --v3-priv-proto=NONE \
  --v3-user=authprivshades --v3-auth-key=maplesyrup --v3-auth-proto=SHA \
                           --v3-priv-key=maplesyrup --v3-priv-proto=DES \
  --v3-user=authprivmd5des --v3-auth-key=maplesyrup --v3-auth-proto=MD5 \
                           --v3-priv-key=maplesyrup --v3-priv-proto=DES \
  --v3-user=unsafe --v3-auth-proto=NONE --v3-priv-proto=NONE
sleep 20 # give some time for the simulator to boot


