require 'sinatra/base'
require 'builder'
require 'hmac'
require 'hmac-sha2'
require 'base64'
require 'rexml/document'
require File.join(File.dirname(__FILE__), 'uuid')
require File.join(File.dirname(__FILE__), 'errors')

module DNSServer
  class WebAPI < Sinatra::Base

    API_PREFIX = '^\/2010-10-01'

    disable :raise_errors, :show_exception
    set :environment, :production
    
    before do
      @request_id = UUID.create
      @current_date = Time.now.getgm.httpdate
      headers 'x-amz-request-id' => @request_id.to_s
      headers 'Date' => @current_date.to_s

      raise MissingAuthenticationToken unless env.has_key?('HTTP_X_AMZN_AUTHORIZATION') && env.has_key?('HTTP_DATE')
      
      # no actual users yet so the only secret key that works is...
      client_access_key = "J3232H5H235JHSADF"
      client_secret_key = "/Ml61L9VxlzloZ091/lkqVV5X1/YvaJtI9hW4Wr9"

      if env['HTTP_X_AMZN_AUTHORIZATION'] =~ /^AWS3-HTTPS AWSAccessKeyId=(.*),Algorithm=HmacSHA256,Signature=(.*)$/
        access_key = $1
        signature = $2
        user_date = env['HTTP_DATE']
        hmac = HMAC::SHA256.new(client_secret_key)
        hmac.update(user_date)
        test = Base64.encode64(hmac.digest).chomp
        raise AccessDenied if test != signature
      else
        raise InvalidSignature
      end
    end

    get %r{#{API_PREFIX}\/hostedzone$} do
      max_items = (params[:maxitems] || 100).to_i
      max_items = 100 if max_items <= 0 || max_items > 100
      marker = params[:marker]

      z, next_marker = DNSServer.zones(max_items,marker)

      xml do |x|
        x.ListHostedZonesResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
          x.HostedZones do
            z.each do |origin,zone|
              x.HostedZone do
                x.Id "/hostedzone/#{zone[:key]}"
                x.Name origin
                x.CallerReference zone[:ref]
                x.Config do
                  x.Comment zone[:comment]
                end
              end
            end
          end
          x.MaxItems max_items
          x.IsTruncated next_marker.nil? ? false : true
          x.NextMarker next_marker
        end
      end
    end

    get %r{#{API_PREFIX}\/hostedzone\/([\w]+)$} do
      zone_id = params[:captures].first
      z, zone_data = DNSServer.get_zone_by_key(zone_id)

      xml do |x|
        x.GetHostedZoneResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
          x.HostedZone do
            x.Id "/hostedzone/#{zone_id}"
            x.Name z
            x.CallerReference zone_data[:ref]
            x.Config do
              x.Comment zone_data[:comment]
            end
          end
          x.DelegationSet do
            x.NameServers do
              zone_data[:records].each do |record|
                x.NameServer expanded_address(record[:address],z) if expanded_address(record[:name],z) == z && record[:type] == "NS"
              end
            end
          end
        end
      end
    end

    post %r{#{API_PREFIX}\/hostedzone$} do
      env['rack.input'].rewind
      data = env['rack.input'].read
      xml_request = REXML::Document.new(data).root
      z = xml_request.elements["CreateHostedZoneRequest/Name"].text
      ref = xml_request.elements["CreateHostedZoneRequest/CallerReference"].text
      comment = xml_request.elements["CreateHostedZoneRequest/HostedZoneConfig/Comment"].text

      begin
        DNSServer.get_zone(z)
        raise HostedZoneAlreadyExists
      rescue AccessDenied
        # domain does not exist, continue
      end
      raise InvalidDomainName if z[-1,1] != "."

      change_id = DNSServer.create_zone(z,ref,comment)
      zone_data = DNSServer.get_zone(z)

      xml do |x|
        x.CreateHostedZoneResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
          x.HostedZone do
            x.Id "/hostedzone/#{zone_data[:key]}"
            x.Name z
            x.CallerReference ref
            x.Config do
              x.Comment comment
            end
          end
          x.ChangeInfo do
            x.Id "/change/#{change_id}"
            x.Status "PENDING"
            x.SubmittedAt Time.now.getgm.iso8601
          end
          x.DelegationSet do
            x.NameServers do
              zone_data[:records].each do |record|
                x.NameServer expand_address(record[:address],z) if expanded_address(record[:name],z) == z && record[:type] == "NS"
              end
            end
          end
        end
      end
    end

    delete %r{#{API_PREFIX}\/hostedzone\/([\w]+)$} do
      zone_id = params[:captures].first
      z, zone_data = DNSServer.get_zone_by_key(zone_id)
      change_id = DNSServer.delete_zone(z)

      xml do |x|
        x.DeleteHostedZoneResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
          x.ChangeInfo do
            x.Id "/change/#{change_id}"
            x.Status "PENDING"
            x.SubmittedAt Time.now.getgm.iso8601
          end
        end
      end
    end

    post %r{#{API_PREFIX}\/hostedzone\/([\w]+)\/rrset$} do
      zone_id = params[:captures].first
      z, zone_data = DNSServer.get_zone_by_key(zone_id)
      env['rack.input'].rewind
      data = env['rack.input'].read
      xml_request = REXML::Document.new(data).root

      xml_request.each_element('//ChangeResourceRecordSetsRequest/ChangeBatch/Changes/Change') do |element|
        action = element.elements["Action"].text
        name = element.elements["ResourceRecordSet/Name"].text
        type = element.elements["ResourceRecordSet/Type"].text
        ttl = element.elements["ResourceRecordSet/TTL"].text
        element.each_element('ResourceRecordSet/ResourceRecords/ResourceRecord/Value') do |addy|
          case action.upcase
          when "DELETE"
            DNSServer.delete_record(z, name, type, ttl, addy.text)
          when "CREATE"
            DNSServer.create_record(z, name, type, ttl, addy.text)
          end
        end
      end

      change_id = DNSServer.record_change(z, "ChangeResourceRecordSets", data)

      xml do |x|
        x.ChangeResourceRecordSetsResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
          x.ChangeInfo do
            x.Id "/change/#{change_id}"
            x.Status "PENDING"
            x.SubmittedAt Time.now.getgm.iso8601
          end
        end
      end
    end

    get %r{#{API_PREFIX}\/hostedzone\/([\w]+)\/rrset$} do
      zone_id = params[:captures].first
      z, zone_data = DNSServer.get_zone_by_key(zone_id)
      max_items = (params[:maxitems] || 100).to_i
      type = params[:type]
      name = params[:name]

      records, next_marker = DNSServer.zone_records(zone_data[:records],name,type,max_items)

      xml do |x|
        x.ListResourceRecordSetsResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
          records.each do |key,value|
            x.ResourceRecordSets do
              x.ResourceRecordSet do
                x.Name expanded_address(value[:record][:name],z)
                x.Type value[:record][:type]
                x.TTL value[:record][:ttl]
                x.ResourceRecords do |bla|
                  value[:addresses].each do |address|
                    x.ResourceRecord do
                      case value[:record][:type]
                      when "SOA"
                        x.Value "#{value[:record][:ns]} #{value[:record][:email]} #{value[:record][:address].join(' ')}"
                      when "MX"
                        x.Value "#{value[:record][:priority]} #{expanded_address(address,z)}"
                      else
                        x.Value expanded_address(address,z)
                      end
                    end
                  end
                end
              end
            end
          end
          x.IsTruncated next_marker.nil? ? false : true
          x.MaxItems max_items
          x.NextRecordName expanded_address(next_marker[:name],z) unless next_marker.nil?
          x.NextRecordType next_marker[:type] unless next_marker.nil?
        end
      end
    end

    get %r{#{API_PREFIX}\/change\/([\w]+)$} do
      change_id = params[:captures].first
      change = DNSServer.get_change(change_id)

      xml do |x|
        x.GetChangeResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
          x.ChangeInfo do
            x.Id "/change/#{change_id}"
            x.Status "INSYNC"
            x.SubmittedAt change[:time]
          end
        end
      end
    end

    error do
      error = Builder::XmlMarkup.new
      error.instruct! :xml, :version=>"1.0", :encoding=>"UTF-8"

      error.ErrorResponse :xmlns => "https://route53.amazonaws.com/doc/2010-10-01/" do
        error.Error do
          error.Type "Sender"
          error.Code request.env['sinatra.error'].code
          error.Message request.env['sinatra.error'].message
        end
        error.RequestId @request_id
      end

      status request.env['sinatra.error'].status.nil? ? 500 : request.env['sinatra.error'].status
      content_type 'application/xml'
      body error.target!
    end

    protected
    def expanded_address(address,zone)
      return address if address =~ /^\d+\.\d+\.\d+\.\d+$/
      return zone if address == "@"
      return "#{address}.#{zone}" if address[-1,1] != "."
      address
    end

    def xml
      xml = Builder::XmlMarkup.new
      xml.instruct! :xml, :version=>"1.0", :encoding=>"UTF-8"
      yield xml
      content_type 'application/xml'
      xml.target!
    end

  end
end
