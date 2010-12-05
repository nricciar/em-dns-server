require 'eventmachine'
require 'dnsruby'
require 'daemons'
begin
  require 'geoip'
rescue LoadError
  puts "-- geoip gem not installed, geoip support disabled."
end

module DNSServer

  PLUGIN_PATH = File.join(File.dirname(__FILE__),'..')
  RAD_PER_DEG = 0.017453293
  VERSION = "0.1.2"
  
  @@GEOIP = nil
  @@ZONEMAP = {}

  def self.geoip_data_path
    @@GEOIP_PATH ||= File.join(PLUGIN_PATH,"GeoLiteCity.dat")
  end

  def self.geoip_data_path=(val)
    @@GEOIP_PATH = val
  end

  def self.geoip_enabled?
    !@@GEOIP.nil?
  end

  def self.init()
    @@GEOIP = GeoIP.new(geoip_data_path) unless !File.exists?(geoip_data_path)

    # the following is NOT an example of how to parse a bind zone file
    # some things will be completly ignored and anything exotic will 
    # likely cause the following code to fail.
    Dir.entries("zones").each do |file|
      if file =~ /^(.*).zone$/
        zonefile = File.read("zones/#{file}")
        @@ZONEMAP.merge!(self.parse_zone_file("zones/#{file}"))
      end
    end
  end

  def self.reload_zone_file(filename)
    @@ZONEMAP.merge!(self.parse_zone_file(filename))
  end

  def self.parse_zone_file(filename)
    ret = {}
    origin = nil
    ttl = nil
    records = []

    file = File.new(filename,'r')
    while (line = file.gets)
      case line.split(";").first
      when /\$ORIGIN\s+([^\s]+)$/
        origin = $1
      when /\$TTL\s+([\w]+)(.+)$/
        ttl = $1
      when /^(([\w@\*\-\.]+)\s+(([0-9]+)\s+|)([A-Za-z]+)\s+([A-Za-z]+)\s+(([0-9]+)\s+|)([\w@\-\.:]+))/
        records << { :name => $2, :ttl => $4, :class => $5, :type => $6, 
	  :priority => $8, :address => $9}
      end
    end
    file.close
    origin = File.basename(filename, ".zone") if origin.nil?
    origin += "." if origin[-1,1] != "."
    ret[origin] = { :records => records, :ttl => ttl }
    ret
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
      puts "Q: #{query}"

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
    case rr[:type]
    when "MX"
      "#{rr[:name]} #{rr[:ttl]} #{rr[:class]} #{rr[:type]} #{rr[:priority]} #{rr[:address]}"
    else
      "#{rr[:name]} #{rr[:ttl]} #{rr[:class]} #{rr[:type]} #{rr[:address]}"
    end
  end

  # mostly taken from http://www.codecodex.com/wiki/Calculate_distance_between_two_points_on_a_globe#Ruby
  def haversine_distance( lat1, lon1, lat2, lon2 )
    distances = Hash.new
    dlon = lon2 - lon1
    dlat = lat2 - lat1

    dlon_rad = dlon * RAD_PER_DEG
    dlat_rad = dlat * RAD_PER_DEG

    lat1_rad = lat1 * RAD_PER_DEG
    lon1_rad = lon1 * RAD_PER_DEG

    lat2_rad = lat2 * RAD_PER_DEG
    lon2_rad = lon2 * RAD_PER_DEG

    a = Math.sin(dlat_rad/2)**2 + Math.cos(lat1_rad) * Math.cos(lat2_rad) * Math.sin(dlon_rad/2)**2
    c = 2 * Math.asin( Math.sqrt(a))

    dMi = 3956 * c          # delta between the two points in miles
    dKm = 6371 * c             # delta in kilometers
    dFeet = 20887680 * c         # delta in feet
    dMeters = 6371000 * c     # delta in meters

    distances["mi"] = dMi
    distances["km"] = dKm
    distances["ft"] = dFeet
    distances["m"] = dMeters
    distances
  end

  class DnsRedirect < Exception
  end

end
