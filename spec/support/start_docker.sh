sudo docker build -t snmp-server-emulator -f spec/support/Dockerfile .
sudo docker run -d -p :1161/udp --name test-snmp-emulator snmp-server-emulator --agent-udpv4-endpoint=0.0.0.0:1161 --agent-udpv6-endpoint='[::0]:1161'


