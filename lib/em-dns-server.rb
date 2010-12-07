require 'eventmachine'
require 'dnsruby'
require 'daemons'
require File.join(File.dirname(__FILE__),'em-dns-server/geoip')
require File.join(File.dirname(__FILE__),'em-dns-server/zonefile')

module DNSServer

  include GeoIPRoute
  include ZoneFile

  PLUGIN_PATH = File.join(File.dirname(__FILE__),'..')
  VERSION = "0.1.2"
  
  @@ZONEMAP = {}

  def self.init()
    Dir.entries("zones").each do |file|
      if file =~ /^(.*).zone$/
        zonefile = File.read("zones/#{file}")
        @@ZONEMAP.merge!(self.parse_zone_file("zones/#{file}"))
      end
    end

    @@GEOIP = GeoIP.new(self.geoip_data_path) unless !File.exists?(self.geoip_data_path)
  end

  def receive_data(data)
    msg = Dnsruby::Message.decode(data)

    operation = proc do
      client_ip = get_peername[2,6].unpack("nC4")[1,4].join(".")
      geoip_data = @@GEOIP.country(client_ip) if DNSServer.geoip_enabled?

      msg.question.each do |question|
        resolv(question,msg,geoip_data)
      end
    end

    callback = proc do |res|
      # mark the message as a response and send it to the client
      msg.header.qr = true
      msg.header.rcode = Dnsruby::RCode.NoError
      send_data msg.encode
    end

    EM.defer(operation,callback)
  end

  protected
  def resolv(question,msg,geoip_data=nil)
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
          if DNSServer.geoip_enabled?
            # get the location information for the current record
            rr_geo = @@GEOIP.country(rr[:address])
            distance = rr_geo.nil? ? 0 : haversine_distance(geoip_data[9],geoip_data[10],
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
    rr = rr.clone
    rr[:name] += ".#{domain}" if rr[:name] != "@" && rr[:name][-1,1] != "."
    rr[:name] = domain if rr[:name] == "@"
    rr[:address] += ".#{domain}" if rr[:address] !~ /^\d+\.\d+\.\d+\.\d+$/ && rr[:address][-1,1] != "."
    case rr[:type]
    when "MX"
      "#{rr[:name]} #{rr[:ttl]} #{rr[:class]} #{rr[:type]} #{rr[:priority]} #{rr[:address]}"
    else
      "#{rr[:name]} #{rr[:ttl]} #{rr[:class]} #{rr[:type]} #{rr[:address]}"
    end
  end

  class DnsRedirect < Exception
  end

end
