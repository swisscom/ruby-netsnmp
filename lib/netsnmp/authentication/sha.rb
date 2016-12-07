module NETSNMP
  module Authentication
    class SHA
      def initialize(password)
        @password = password
      end
    end
  end
end

