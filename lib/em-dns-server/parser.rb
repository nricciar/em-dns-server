module DNSServer
class ZoneFile

  VERSION = "0.9.1"
  SORT_ORDER = { "SOA" => 1, "NS" => 2, "MX" => "3", "A" => 4, "AAAA" => 4, "CNAME" => 6, "PTR" => 7, "TXT" => 8 }

  def initialize(filename)
    @path = filename
    @data = File.read(filename)
    @id = nil
    @ref = nil
    @comment = nil
    @origin = nil
    @ttl = 3600
    @records = []
    @uid = nil

    if @data =~ /(^\A|\n)\s*(;|)\s*\$REF\s+([^\s;]+)/
      @ref = $3
    end
    if @data =~ /(^\A|\n)\s*(;|)\s*\$UID\s+([^\s;]+)/
      @uid = $3
    end
    if @data =~ /(^\A|\n)\s*(;|)\s*\$ZONEID\s+([^\s;]+)\s*(;\s*(.+)|)/
      @id = $3
      @comment = $5
    end

    @data.gsub!(/;.*$/,"") # strip comments
    @data.gsub!(/\t+/," ") # fold whitespace

    until (record = get_next_record()).nil?
      @records << ZoneFileRecord.new(record,self)
    end
    @records.sort! { |x,y| "#{SORT_ORDER[x.type] || 9}#{x.name}" <=> "#{SORT_ORDER[y.type] || 9}#{y.name}" }
  end

  def add_record(record)
    @records << ZoneFileRecord.new(record,self)
  end

  def ref
    @ref
  end

  def uid
    @uid
  end

  def comment
    @comment
  end

  def key
    @id
  end

  def origin
    @origin
  end

  def origin=(val)
    @origin = val
  end

  def ttl
    @ttl
  end

  def ttl=(val)
    @ttl = val
  end

  def records
    @records
  end

  def save
    File.open(@path, 'w') { |f| f.write(output) }
  end

  def filename
    @path
  end

  def output
    out = ";$REF #{@ref}\n;$ZONEID #{@id} ; #{@comment}\n;$UID #{@uid}\n"
    out << "$TTL #{@ttl}\n" unless @ttl.nil?
    out << "$ORIGIN #{@origin}\n"
    records.each do |record|
      case record.type
      when "SOA"
        out << "#{record.name} #{record.ttl} #{record.class} #{record.type} #{record.ns} #{record.email} (\n"
        out << "                     #{record.address[0].to_s.ljust(18,' ')}  ; serial\n"
        out << "                     #{record.address[1].to_s.ljust(18,' ')}  ; refresh\n"
        out << "                     #{record.address[2].to_s.ljust(18,' ')}  ; retry\n"
        out << "                     #{record.address[3].to_s.ljust(18,' ')}  ; expire\n"
        out << "                     #{(record.address[4].to_s+')').ljust(18,' ')}  ; minimum\n"
      when "MX"
        out << "#{record.name.ljust(20,' ')} #{record.ttl.to_s.ljust(9,' ')} #{record.class} MX #{record.priority}  #{record.address}\n"
      else
        out << "#{record.name.ljust(20,' ')} #{record.ttl.to_s.ljust(9,' ')} #{record.class} #{record.type.ljust(6,' ')} #{record.address}\n"
      end
    end
    out
  end

  protected
  def get_next_record
    record = nil
    begin
      @data.lstrip!
      case @data
      when /\A\$ORIGIN\s+([-\w\d]+((\.[-\w\d]+)*)?\.?)\s*/i
        @data = $'
        @origin = $1
        raise NotRecord
      when /\A\$TTL\s+([A-Z0-9]+)\s*/i
        @data = $'
        @ttl = get_ttl_from_string($1)
        raise NotRecord
      when /\A(|\*\.[\w\d\.]+|\*|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?)) 
	\s+ (([\dDdHhWw]+|IN|HESIOD|CHAOS)\s+)? (([\dDdHhWw]+|IN|HESIOD|CHAOS)\s+)? 
	(SOA) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?) 
	\s+ \( \s+ ([^)]+) \) \s*/mxi
        @data = $'
        soa_data = $15
        record = { :name => $1, :type => "SOA", :ns => $9, :email => $12, :record => $~.to_s }
        record.merge!(fix_ttl_class($5,$7,@ttl))
        soa_data = soa_data.split("\n").collect { |c| c.strip.empty? ? nil : get_ttl_from_string(c.strip) }.compact
        record[:address] = soa_data
      when /\A(|\*\.[\w\d\.]+|\*|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?))
	\s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	(MX) \s+ (\d+) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?) \s*\n/mxi
        @data = $'
        record = { :name => $1, :type => $8, :priority => $9, :address => $10, :record => $~.to_s }
        record.merge!(fix_ttl_class($5,$7,@ttl))
      when /\A(|\*|\w+|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?))
	\s+((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	(PTR|NS|CNAME) \s+ ([-\w\d]+((\.[-\w\d]+)*)?\.?|\@) \s*/mxi
        @data = $'
        record = { :name => $1, :type => $8, :address => $9, :record => $~.to_s }
        record.merge!(fix_ttl_class($5,$7,@ttl))
      when /\A(|\*|\s*\@|\.|([-\w\d]+(\.[-\w\d]+)*\.?)?)
	\s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	(TXT|HINFO|AAAA) \s+ (".+?"|[:\d\w]+) \s*\n/mxi
        @data = $'
        record = { :name => $1, :type => $8, :address => $9, :record => $~.to_s }
        record.merge!(fix_ttl_class($5,$7,@ttl))
      when /\A(|\*|\*.[-\w\d\.]+|[-\w\d\.]+|\s*\@|\.|[-\w\d]+(((\.[-\w\d]+)*)\.?)?)
	\s+ ((\d+|IN|HESIOD|CHAOS)\s+)? ((\d+|IN|HESIOD|CHAOS)\s+)?
	(A) \s+ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) \s*/mxi
        @data = $'
        record = { :name => $1, :type => $9, :address => $10, :record => $~.to_s }
        record.merge!(fix_ttl_class($6,$8,@ttl))
      when /\A\s*$/
        raise EndOfFile
      else
        raise InvalidInput, @data
      end
    rescue NotRecord
      retry
    rescue EndOfFile
      return nil
    end
    record
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

class ZoneFileRecord

  def initialize(record,zone)
    @record = record
    @zone = zone
  end

  def name
    @record[:name]
  end

  def name=(val)
    @record[:name] = val
  end

  def full_name
    expanded_address(@record[:name],@zone.origin)
  end

  def type
    @record[:type]
  end

  def class
    @record[:class]
  end

  def ttl
    @record[:ttl]
  end

  def ttl=(val)
    @record[:ttl] = val
  end

  def address
    @record[:address]
  end

  def address=(val)
    @record[:address] = val
  end

  def priority
    @record[:priority]
  end

  def priority=(val)
    @record[:priority] = val
  end

  def full_address
    expanded_address(@record[:address],@zone.origin)
  end

  def email
    expanded_address(@record[:email],@zone.origin)
  end

  def ns
    expanded_address(@record[:ns],@zone.origin)
  end

  protected
  def expanded_address(address,zone)
    return address if address =~ /^\d+\.\d+\.\d+\.\d+$/
    return zone if address == "@"
    return "#{address}.#{zone}" if address[-1,1] != "."
    address
  end

end

class InvalidInput < Exception
end
class NotRecord < Exception
end
class EndOfFile < Exception
end
end
