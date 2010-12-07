module DNSServer
  module ZoneFile

    def self.included(base) 
      class << base
	def parse_zone_file(filename)
	  ret = {}
	  origin = nil
	  ttl = nil
	  records = []
	  file = File.read(filename)
	  file.gsub!(/;.*$/,"") # strip comments
	  file.gsub!(/\t+/," ") # fold whitespace

	  file.split("\n").each do |line|
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
	      record = { :name => $1, :type => $8, :priority => $9, :address => $10 }
	      record.merge!(fix_ttl_class($5,$7,ttl))
	    # PTR, NS, CNAME
	    when /\A(|\*|\w+|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?))
	      \s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	      (PTR|NS|CNAME) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?|\@) \s*$/mxi
	      record = { :name => $1, :type => $8, :address => $9 }
	      record.merge!(fix_ttl_class($5,$7,ttl))
	    # TXT, HINFO, AAAA
	    when /\A(|\*|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?)?)
	      \s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	      (TXT|HINFO|AAAA) \s+ (".+?"|[:\d\w]+) \s*$/
	      record = { :name => $1, :type => $8, :address => $9 }
	      record.merge!(fix_ttl_class($5,$7,ttl))
	    # A
	    when /\A(|\*|\*.[-\w\d\.]+|[-\w\d\.]+|\s*\@|\.|[-\w\d]+(((\.[-\w\d]+)*)\.?)?)
	      \s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	      (A) \s+ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \s*$/mxi
	      record = { :name => $1, :type => $9, :address => $10 }
	      record.merge!(fix_ttl_class($6,$8,ttl))
	    end
	    records << record unless record.nil?
	  end
	  origin = File.basename(filename, ".zone") if origin.nil?
	  origin += "." if origin[-1,1] != "."
	  ret[origin] = { :records => records, :ttl => ttl, :filename => filename, :mtime => File.mtime(filename) }
	  ret
	end

	protected
	def fix_ttl_class(ct1,ct2,ttl)
	  if ct1 =~ /^\d+$/
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
