FROM python:2
Maintainer Tiago Cardoso <tiago.cardoso@swisscom.com>

RUN easy_install snmpsim==0.3.0
RUN easy_install pycrypto 
EXPOSE 1161
# Create non-privileged user
RUN useradd -m snmp_server


USER snmp_server
ENTRYPOINT ["/usr/local/bin/snmpsimd.py"]

CMD ["--help"]
