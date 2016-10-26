module NETSNMP
  module Authentication 
    class None


      def generate_param(*)
        ("\x00" * 12)
      end
    end
  end
end

