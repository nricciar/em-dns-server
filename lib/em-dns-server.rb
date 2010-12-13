require 'eventmachine'
require 'dnsruby'
require 'daemons'
require File.join(File.dirname(__FILE__),'em-dns-server/geoip')
require File.join(File.dirname(__FILE__),'em-dns-server/zonefile')

module DNSServer

  include GeoIPRoute
  include ZoneFile

  PLUGIN_PATH = File.join(File.dirname(__FILE__),'..')
  ZONE_FILES = File.expand_path(ENV['ZONE_FILES'] || File.join(PLUGIN_PATH,'zones'))
  VERSION = "0.2.0"
  
  @@ZONEMAP = {}

  def self.zonemap
    @@ZONEMAP
  end

  def self.init()
    Dir.entries(ZONE_FILES).each do |file|
      if file =~ /^(.*).zone$/
        zonefile = File.read(File.join(ZONE_FILES, file))
        @@ZONEMAP.merge!(self.parse_zone_file(File.join(ZONE_FILES, file)))
      end
    end
    
    @@GEOIP = GeoIP.new(self.geoip_data_path) unless !File.exists?(self.geoip_data_path)
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
      msg.header.rcode = msg.answer.empty? ? Dnsruby::RCode::REFUSED : Dnsruby::RCode.NoError
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
    zone_records = @@ZONEMAP[domain][:records] unless domain.nil?

    begin
      puts "Q: #{query}"
      query.gsub!(/#{domain}/,"")
      query = query == "" ? "@" : query.chomp(".")

      match_distance = nil
      match_record = nil
      wildcard_match = nil

      zone_records.each do |rr|
        if rr[:name] == query.to_s && rr[:class] == question.qclass.to_s && rr[:type] == question.qtype.to_s
          if DNSServer.geoip_enabled? && !@geoip_data.nil? && rr[:type] != "SOA"
            # get the location information for the current record
            rr_geo = @@GEOIP.country(rr[:address])
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
            msg.add_answer(Dnsruby::RR.create(formatted_line_from_hash(rr,domain)))
            puts "#{question.qclass} #{question.qtype} #{question.qname.to_s} Resolved to #{rr[:address]}"
            success = true
          end
        elsif rr[:name] == query && rr[:type] == "CNAME" && question.qtype == "A"
          # add the CNAME to our response, and then attempt to resolve the record
          msg.add_answer(Dnsruby::RR.create(formatted_line_from_hash(rr,domain)))
          address = rr[:address]
          if address[-1,1] != "."
            address += ".#{domain}"
          else
            success = true
          end
          raise DnsRedirect, address
        elsif success == false && rr[:name] =~ /\*/
          # possible wildcard match
          tmp_query = rr[:name].gsub(/\*/,'([\w\-\.]+)')
          tmp_name = question.qname.to_s
          tmp_name += "." if question.qname.to_s[-1,1] != "."
          wildcard_match = rr.merge(:name => tmp_name) if query.to_s =~ /#{tmp_query}/
        end
      end
      unless match_record.nil?
        # the final result for the current question
        msg.add_answer(Dnsruby::RR.create(formatted_line_from_hash(match_record,domain)))
        puts "#{question.qclass} #{question.qtype} #{question.qname.to_s} Resolved to #{match_record[:address]} -- Distance: #{match_distance}"
        success = true
      end
      if success == false && !wildcard_match.nil?
        # no match found, but a wildcard match qualifies
        msg.add_answer(Dnsruby::RR.create(formatted_line_from_hash(wildcard_match,domain)))
        puts "#{question.qclass} #{question.qtype} #{question.qname.to_s} Resolved to #{wildcard_match[:address]} with wildcard."
        success = true
      end
    rescue DnsRedirect => redirect
      query = redirect.message
      query += ".#{domain}" if query[-1,1] != "."
      retry
    end
    if success == true
      zone_records.each do |rr|
        msg.add_authority(Dnsruby::RR.create(formatted_line_from_hash(rr,domain))) if rr[:type] == "NS"
      end
    end
  end

  def formatted_line_from_hash(rr,domain)
    case rr[:type]
    when "SOA"
      "#{expanded_address(rr[:name],domain)} #{rr[:ttl]} #{rr[:class]} #{rr[:type]} #{expanded_address(rr[:ns],domain)} #{expanded_address(rr[:email],domain)} #{rr[:address].join(' ')}"
    when "MX"
      "#{expanded_address(rr[:name],domain)} #{rr[:ttl]} #{rr[:class]} #{rr[:type]} #{rr[:priority]} #{expanded_address(rr[:address],domain)}"
    else
      "#{expanded_address(rr[:name],domain)} #{rr[:ttl]} #{rr[:class]} #{rr[:type]} #{expanded_address(rr[:address],domain)}"
    end
  end

  def expanded_address(address,zone)
    return address if address =~ /^\d+\.\d+\.\d+\.\d+$/
    return zone if address == "@"
    return "#{address}.#{zone}" if address[-1,1] != "."
    address
  end

  class DnsRedirect < Exception
  end

end
