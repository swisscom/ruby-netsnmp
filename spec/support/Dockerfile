FROM python:2.7-alpine
Maintainer Tiago Cardoso <cardoso_tiago@hotmail.com>

RUN easy_install snmpsim==0.3.0
RUN easy_install pycrypto==2.6.1
EXPOSE 1161
# Create non-privileged user
RUN useradd -m snmp_server


USER snmp_server
ENTRYPOINT ["/usr/local/bin/snmpsimd.py"]

CMD ["--help"]
