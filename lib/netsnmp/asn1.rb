# frozen_string_literal: true

if RUBY_ENGINE == "jruby"
  require "rasn1"
  RASN1.include(RASN1::Types)
  module NETSNMP
    ASN1 = RASN1
  end
else
  module NETSNMP
    require "openssl"
    ASN1 = OpenSSL::ASN1
  end
end
