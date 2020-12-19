#!/bin/sh

RUBY_ENGINE=`ruby -e 'puts RUBY_ENGINE'`

if [[ "$RUBY_ENGINE" = "truffleruby" ]]; then
  apt-get update && apt-get install -y git
else
  apk --update add g++ make git
fi

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
