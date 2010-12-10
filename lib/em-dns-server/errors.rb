require 'yaml'

module DNSServer

  # All errors are derived from ServiceError.  It's never actually raised itself, though.
  class ServiceError < Exception; end
     
  # A factory for building exception classes.
  YAML::load(<<-END).
      AccessDenied: [403, Access Denied]
      NotImplemented: [501, A header you provided implies functionality that is not implemented.]
      InternalError: [500, We encountered an internal error. Please try again.]
      InvalidDomainName: [403, The specified domain name is not valid.]
      HostedZoneAlreadyExists: [403, The hosted zone you are attempting to create already exists.]
      InvalidSignature: [403, The request signature Amazon Route 53 calculated does not match the signature you provided. ]
      MissingAuthenticationToken: [403, Missing Authentication Token ]
  END
  each do |code, (status, msg)|
    const_set(code, Class.new(ServiceError) {
      {:code=>code, :status=>status, :message=>msg}.each do |k,v|
        define_method(k) { v }
      end
    })
  end

end
