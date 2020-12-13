#!/bin/sh

apk --update add g++ make git

cd /home
bundle install --quiet
bundle exec rake spec:ci
