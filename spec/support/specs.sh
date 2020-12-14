#!/bin/sh

apk --update add g++ make git

cd /home
bundle install --quiet

if [[ ${RUBY_VERSION:0:1} = "3" ]]; then
  export RUBYOPT='-rbundler/setup -rrbs/test/setup'
  export RBS_TEST_RAISE=true
  export RBS_TEST_LOGLEVEL=error
  export RBS_TEST_OPT='-Isig -ripaddr'
  export RBS_TEST_TARGET='NETSNMP*'
fi

bundle exec rake spec:ci
