FROM python:2
Maintainer Tiago Cardoso <tiago.cardoso@swisscom.com>
ENV http_proxy serverproxy.corproot.net:8080
ENV https_proxy serverproxy.corproot.net:8080

RUN easy_install snmpsim
RUN easy_install pycrypto 
EXPOSE 1161
# Create non-privileged user
RUN useradd -m snmp_server


USER snmp_server
ENTRYPOINT ["/usr/local/bin/snmpsimd.py"]

CMD ["--help"]
