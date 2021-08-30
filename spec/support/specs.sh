#!/bin/sh

set -e

RUBY_ENGINE=`ruby -e 'puts RUBY_ENGINE'`

if [[ "$RUBY_ENGINE" = "truffleruby" ]]; then
  microdnf install -y git net-snmp-utils
elif [[ "$RUBY_ENGINE" = "jruby" ]]; then
  apt-get update
  apt-get install -y git snmp-mibs-downloader
  sudo sed -i 's/mibs :/# mibs :/g' /etc/snmp/snmp.conf
else
  apk --update add g++ make git net-snmp-libs
fi

gem install bundler -v="1.17.3" --no-doc --conservative
cd /home

bundle -v
bundle install

if [[ ${RUBY_VERSION:0:1} = "3" ]]; then
  export RUBYOPT='-rbundler/setup -rrbs/test/setup'
  export RBS_TEST_RAISE=true
  export RBS_TEST_LOGLEVEL=error
  export RBS_TEST_OPT='-Isig -ripaddr -ropenssl -rsocket'
  export RBS_TEST_TARGET='NETSNMP*'
fi

bundle exec rake spec:ci
