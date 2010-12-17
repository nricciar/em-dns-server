require 'eventmachine'
require 'dnsruby'
require 'daemons'
require 'em-dns-server/geoip'
require 'em-dns-server/parser'

module DNSServer

  include GeoIPRoute

  PLUGIN_PATH = File.join(File.dirname(__FILE__),'..')
  ZONE_FILES = File.expand_path(ENV['ZONE_FILES'] || File.join(PLUGIN_PATH,'zones'))
  VERSION = "0.3.0"
  
  @@ZONEMAP = {}

  def self.zonemap
    @@ZONEMAP
  end

  def self.init()
    @@GEOIP = GeoIP.new(self.geoip_data_path) unless !File.exists?(self.geoip_data_path)
  end

  def self.load_zone(filename)
    zone = ZoneFile.new(filename)
    puts "Loading zone #{zone.origin}"
    @@ZONEMAP[zone.origin] = zone
  rescue
    puts "-- Invalid zone file #{filename}"
  end

  def receive_data(data)
    msg = Dnsruby::Message.decode(data)

    operation = proc do
      client_ip = get_peername[2,6].unpack("nC4")[1,4].join(".")
      @geoip_data = @@GEOIP.country(client_ip) if DNSServer.geoip_enabled?
      @resolver = Dnsruby::Resolver.new
      @query_id = 10
      @query_queue = Queue.new

      msg.question.each do |question|
        resolv(question,msg)
      end
    end

    callback = proc do |res|
      # mark the message as a response and send it to the client
      msg.header.qr = true
      send_data msg.encode
    end

    EM.defer(operation,callback)
  end

  protected
  def resolv(question,msg)
    success = false
    query = question.qname.to_s
    query += "." if query[-1,1] != "."
    domain = nil
    zone_records = []

    # load the zone information for the current question
    @@ZONEMAP.each { |key,value| domain = key if query =~ /#{key}$/ }
    zone_records = @@ZONEMAP[domain].records unless domain.nil?
    if domain.nil?
      msg.header.rcode = Dnsruby::RCode::REFUSED
      return
    end

    begin
      puts "Q: #{query}"

      match_distance = nil
      match_record = nil
      wildcard_match = nil

      zone_records.each do |rr|
        if rr.full_name == query.to_s && rr.class == question.qclass.to_s && rr.type == question.qtype.to_s
          if DNSServer.geoip_enabled? && !@geoip_data.nil? && rr.type == "A"
            # get the location information for the current record
            rr_geo = @@GEOIP.country(rr.full_address)
            distance = rr_geo.nil? ? 0 : haversine_distance(@geoip_data[9],@geoip_data[10],
		rr_geo[9],rr_geo[10])["mi"].to_i

            # if this is the first match or if we have found a match closer
            # to the client
            if match_record.nil? || match_distance.nil? || match_distance > distance
              match_distance = distance
              match_record = rr
            end
          else
            # go ahead and add to response if geoip based responses are disabled
            msg.add_answer(Dnsruby::RR.create(formatted_response(rr,domain)))
            puts "#{question.qclass} #{question.qtype} #{question.qname.to_s} Resolved to #{rr.full_address}"
            success = true
          end
        elsif rr.full_name == query && rr.type == "CNAME" && question.qtype == "A"
          # add the CNAME to our response, and then attempt to resolve the record
          msg.add_answer(Dnsruby::RR.create(formatted_response(rr,domain)))
          address = rr.address
          if address[-1,1] != "."
            address += ".#{domain}"
          else
            success = true
          end
          raise DnsRedirect, address
        elsif success == false && rr.name =~ /\*/
          # possible wildcard match
          tmp_query = rr.name.gsub(/\*/,'([\w\-\.]+)')
          tmp_name = question.qname.to_s
          tmp_name += "." if question.qname.to_s[-1,1] != "."
          wildcard_match = rr if query.to_s =~ /#{tmp_query}/
        end
      end
      unless match_record.nil?
        # the final result for the current question
        msg.add_answer(Dnsruby::RR.create(formatted_response(match_record,domain)))
        puts "#{question.qclass} #{question.qtype} #{question.qname.to_s} Resolved to #{match_record.full_address} -- Distance: #{match_distance}"
        success = true
      end
      if success == false && !wildcard_match.nil?
        # no match found, but a wildcard match qualifies
        msg.add_answer(Dnsruby::RR.create(formatted_response(wildcard_match,domain,query)))
        puts "#{question.qclass} #{question.qtype} #{question.qname.to_s} Resolved to #{wildcard_match.full_address} with wildcard."
        success = true
      end
    rescue DnsRedirect => redirect
      query = redirect.message
      query += ".#{domain}" if query[-1,1] != "."
      retry
    end
    if success == true
      zone_records.each do |rr|
        msg.add_authority(Dnsruby::RR.create(formatted_response(rr,domain))) if rr.type == "NS"
      end
      msg.header.rcode = Dnsruby::RCode.NoError
    else
      zone_records.each do |rr|
        msg.add_authority(Dnsruby::RR.create(formatted_response(rr,domain))) if rr.full_name == domain && rr.type == "SOA"
      end
      msg.header.rcode = Dnsruby::RCode::NXDOMAIN
    end
  end

  def formatted_response(rr,domain,name_override=nil)
    case rr.type
    when "SOA"
      "#{rr.full_name} #{rr.ttl} #{rr.class} #{rr.type} #{rr.ns} #{rr.email} #{rr.address.join(' ')}"
    when "MX"
      "#{rr.full_name} #{rr.ttl} #{rr.class} #{rr.type} #{rr.priority} #{rr.full_address}"
    else
      "#{name_override || rr.full_name} #{rr.ttl} #{rr.class} #{rr.type} #{rr.full_address}"
    end
  end

  class DnsRedirect < Exception
  end

end
