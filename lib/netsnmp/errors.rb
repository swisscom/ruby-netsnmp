module NETSNMP
  Error = Class.new(StandardError)
  ConnectionFailed = Class.new(Error)
  AuthenticationFailed = Class.new(Error)

  SendError = Class.new(Error)
  ReceiveError = Class.new(Error)
end
