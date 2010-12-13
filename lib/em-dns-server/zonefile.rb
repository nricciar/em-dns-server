require 'fileutils'
require 'yaml'

module DNSServer
  module ZoneFile

    def self.included(base) 
      class << base
        def get_zone(zone)
          self.zonemap[zone] || raise(AccessDenied)
        end

        def delete_zone(zone)
          z = get_zone(zone)
          dir = File.join(DNSServer::ZONE_FILES,"deleted")
          FileUtils.mkdir_p(dir) unless File.exists?(dir)
          FileUtils.mv z[:filename], dir
          self.zonemap.delete(zone)
          record_change(zone, "DeleteHostedZone", nil)
        rescue
          raise InternalError
        end

        def create_zone(zone,ref,comment)
          filename = File.join(DNSServer::ZONE_FILES, "#{zone}zone")
          zone_id = generate_key
          ttl = 86400
          zone_file = <<EOS
;$REF #{ref}
;$ZONEID #{zone_id} ; #{comment}
$TTL    #{ttl}
$ORIGIN #{zone}
@  1D  IN        SOA ns1.#{zone}   hostmaster.#{zone} (
                              2002022401 ; serial
                              3H ; refresh
                              15 ; retry
                              1w ; expire
                              3h ; minimum
                             )
@      IN  NS     ns1.example.com.
@      IN  NS     ns2.smokeyjoe.com.
EOS
          File.open(filename,'w') { |f| f.write(zone_file) }
          DNSServer.record_change(zone, "CreateHostedZone", { :ref => ref, :comment => comment })
          self.zonemap.merge!(parse_zone_file(filename))
        end

        def create_record(zone, name, type, ttl, address)
          z = get_zone(zone)
          name.sub!($3,"") if name =~ /((.*)((\A|.)#{zone}))$/
          name = "@" if name == ""

          if type == "MX" && address =~ /^(\d+)\s+(.*)$/
            type = "MX #{$1}"
            address = $2
          end

          address.sub!($3,"") if address =~ /((.*)((\A|.)#{zone}))$/
          address = "@" if address == ""
          rr = "#{name} #{ttl} IN #{type} #{address}\n"
          File.open(z[:filename],'a') { |f| f.puts(rr) }
          self.zonemap.merge!(parse_zone_file(z[:filename]))
        rescue
          raise InternalError
        end

        def delete_record(zone, name, type, ttl, address)
          z = get_zone(zone)
          line_arr = File.readlines(z[:filename])

          z[:records].each do |record|
            if name == expanded_address(record[:name],zone) && type == record[:type] && address == expanded_address(record[:address],zone)
              line_arr.delete_at(record[:line]-1)           
            end
          end

          File.open(z[:filename],'w') { |f| f.write(line_arr) }
          self.zonemap.merge!(parse_zone_file(z[:filename]))
        rescue
          raise InternalError
        end

        def get_change(change_id)
          dir = File.join(DNSServer::ZONE_FILES,"changes")
          file = File.join(dir, change_id)
          if File.exists?(file)
            YAML::load(File.read(file))
          else
            raise AccessDenied
          end
        end

        def record_change(zone, change_type, data)
          dir = File.join(DNSServer::ZONE_FILES,"changes")
          FileUtils.mkdir_p(dir) unless File.exists?(dir)
          change_id = generate_key
          file = File.join(dir, change_id)
          File.open(file, "w") { |f| f.write(YAML::dump({ :zone => zone, :change_type => change_type, 
		:data => data, :time => Time.now.getgm.iso8601 })) }
          change_id
        rescue
          raise InternalError
        end

        def get_zone_by_key(zone_id)
          self.zonemap.each do |key,value|
            return [ key, value ] if value[:key] == zone_id
          end
          raise AccessDenied
        end

        def update_zone_record(zone, rr, name, ttl, address, priority = 10)
          linedata = rr[:record].clone
          linedata.sub!(rr[:name], name)
          linedata.sub!(rr[:ttl].to_s, ttl.to_s)
          linedata.sub!(rr[:address], address)
          if rr[:type] == "MX"
            linedata.sub!(/(MX\s+(\d+)\s+)/) do |s|
              $~.to_s.sub!($2.to_s,priority.to_s)
            end
          end

          newfile = `sed -e '#{rr[:line]}s/#{rr[:record]}/#{linedata}/g' #{zone[:filename]}`
          File.open(zone[:filename],'w') { |f| f.write(newfile) }
        rescue
          raise InternalError
        end

        def zone_records(records,name,type,max_items)
          ret = {}
          count = 0
          next_marker = nil
          records.sort! { |x,y| "#{x[:name]}#{x[:type]}" <=> "#{x[:name]}#{x[:type]}" }

          records.each do |record|
            if count == max_items
              next_marker = record
              break
            else
              if type.nil?
                if type.nil? || type == record[:type]
                  ret["#{record[:name]}:#{record[:type]}"] ||= { :record => record, :addresses => [] }
                  ret["#{record[:name]}:#{record[:type]}"][:addresses] << record[:address]
                  count += 1
                end
              else
                if record[:type] == type && name == record[:name]

                end
              end
            end
          end
          [ ret, next_marker ]
        rescue
          raise InternalError
        end

        def zones(max_items,marker)
          ret = {}
          count = 0
          next_marker = nil

          self.zonemap.each do |key,value|
            if count == max_items
              next_marker = value[:key]
              break
            else
              if marker.nil?
                ret[key] = value
                count += 1
              else
                ret[key] = value and count += 1 if ret.length > 0 || value[:key] == marker
              end
            end
          end
          [ ret, next_marker ]
        end

	def parse_zone_file(filename)
	  ret = {}
	  origin = nil
          zone_id = nil
          zone_comment = nil
          zone_ref = nil
	  ttl = nil
	  records = []
          rrline = 0
	  file = File.read(filename)
          if file =~ /(^\A|\n)\s*(;|)\s*\$REF\s+([^\s;]+)/
            zone_ref = $3
          end
          if file =~ /(^\A|\n)\s*(;|)\s*\$ZONEID\s+([^\s;]+)\s*(;\s*(.+)|)/
            zone_id = $3
            zone_comment = $5
          end

	  file.gsub!(/;.*$/,"") # strip comments
	  file.gsub!(/\t+/," ") # fold whitespace

          if file =~ /(\n|\A)(|\*\.[\w\d\.]+|\*|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?)) 
		\s+ (([\dDdHhWw]+|IN|HESIOD|CHAOS)\s+)? (([\dDdHhWw]+|IN|HESIOD|CHAOS)\s+)? 
		(SOA) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?) 
		\s+ \( \s+ ([^)]+) \)/mxi
            record = { :name => $2, :type => "SOA", :ns => $10, :email => $13 }
            soa_data = $16.split("\n").collect { |c| c.strip.empty? ? nil : get_ttl_from_string(c.strip) }.compact
            record[:address] = soa_data
            record.merge!(fix_ttl_class($6,$8,ttl))
            records << record
          end
	  file.split("\n").each do |line|
            rrline += 1
	    record = nil
	    case line
	    # $ORIGIN
	    when /\$ORIGIN\s+([^\s]+)$/
	      origin = $1
	    # $TTL
	    when /\$TTL\s+([^\s;]+)(;?[\d\s\w]+)?\s*/
	      ttl = get_ttl_from_string($1)
	    # MX
	    when /\A(|\*\.[\w\d\.]+|\*|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?))
	      \s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	      (MX) \s+ (\d+) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?) \s*$/mxi
	      record = { :name => $1, :type => $8, :priority => $9, :address => $10, :record => $~.to_s, :line => rrline }
	      record.merge!(fix_ttl_class($5,$7,ttl))
	    # PTR, NS, CNAME
	    when /\A(|\*|\w+|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?))
	      \s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	      (PTR|NS|CNAME) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?|\@) \s*$/mxi
	      record = { :name => $1, :type => $8, :address => $9, :record => $~.to_s, :line => rrline }
	      record.merge!(fix_ttl_class($5,$7,ttl))
	    # TXT, HINFO, AAAA
	    when /\A(|\*|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?)?)
	      \s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	      (TXT|HINFO|AAAA) \s+ (".+?"|[:\d\w]+) \s*$/
	      record = { :name => $1, :type => $8, :address => $9, :record => $~.to_s, :line => rrline }
	      record.merge!(fix_ttl_class($5,$7,ttl))
	    # A
	    when /\A(|\*|\*.[-\w\d\.]+|[-\w\d\.]+|\s*\@|\.|[-\w\d]+(((\.[-\w\d]+)*)\.?)?)
	      \s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	      (A) \s+ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \s*$/mxi
	      record = { :name => $1, :type => $9, :address => $10, :record => $~.to_s, :line => rrline }
	      record.merge!(fix_ttl_class($6,$8,ttl))
	    end
	    records << record unless record.nil?
	  end
	  origin = File.basename(filename, ".zone") if origin.nil?
	  origin += "." if origin[-1,1] != "."
	  ret[origin] = { :records => records, :ttl => ttl, :filename => filename, :mtime => File.mtime(filename), 
		:key => (zone_id || generate_key), :comment => zone_comment, :ref => zone_ref }
	  ret
	end

        protected
        def expanded_address(address,zone)
          return address if address =~ /^\d+\.\d+\.\d+\.\d+$/
          return zone if address == "@"
          return "#{address}.#{zone}" if address[-1,1] != "."
          address
        end

        def generate_key
          abc = %{ABCDEF0123456789}
          (1..14).map { abc[rand(abc.size),1] }.join
        end

	def fix_ttl_class(ct1,ct2,ttl)
	  if ct1 =~ /^\d+$/
	    { :ttl => get_ttl_from_string(ct1), :class => (ct2 || 'IN') }
          elsif ct1 =~ /^((\d+)([MHSDW]))$/i
            { :ttl => get_ttl_from_string(ct1), :class => (ct2 || 'IN') }
	  else
	    { :ttl => get_ttl_from_string((ct2 || (ttl || 0))), :class => (ct1 || 'IN') }
	  end
	end

	def get_ttl_from_string(ttl)
	  case ttl.to_s
	  when /^([0-9]+)$/
	    ttl.to_i
	  when /^([0-9]+)D$/i
	    $1.to_i * 86400
	  when /^([0-9]+)H$/i
	    $1.to_i * 3600
	  when /^([0-9]+)W$/i
	    $1.to_i * 604800
	  when /^([0-9]+)S$/i
	    $1.to_i
	  when /^([0-9]+)M$/i
	    $1.to_i * 60
	  else
	    0
	  end
	end
      end
    end

  end
end
