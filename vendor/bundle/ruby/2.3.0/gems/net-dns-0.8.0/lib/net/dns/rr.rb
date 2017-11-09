require 'ipaddr'
require 'net/dns/names'
require 'net/dns/rr/types'
require 'net/dns/rr/classes'

%w(a aaaa cname hinfo mr mx ns ptr soa srv txt).each do |file|
  require "net/dns/rr/#{file}"
end

module Net
  module DNS

    #
    # = Net::DNS::RR - DNS Resource Record class
    #
    # The Net::DNS::RR is the base class for DNS Resource
    # Record (RR) objects. A RR is a pack of data that represents
    # resources for a DNS zone. The form in which this data is
    # shows can be drawed as follow:
    #
    #   "name  ttl  class  type  data"
    #
    # The +name+ is the name of the resource, like an canonical
    # name for an +A+ record (internet ip address). The +ttl+ is the
    # time to live, expressed in seconds. +type+ and +class+ are
    # respectively the type of resource (+A+ for ip addresses, +NS+
    # for nameservers, and so on) and the class, which is almost
    # always +IN+, the Internet class. At the end, +data+ is the
    # value associated to the name for that particular type of
    # resource record. An example:
    #
    #   # A record for IP address
    #   "www.example.com  86400  IN  A  172.16.100.1"
    #
    #   # NS record for name server
    #   "www.example.com  86400  IN  NS  ns.example.com"
    #
    # A new RR object can be created in 2 ways: passing a string
    # such the ones above, or specifying each field as the pair
    # of an hash. See the Net::DNS::RR.new method for details.
    #
    class RR
      include Names


      # Base error class.
      class Error < StandardError
      end

      # Error in parsing binary data, maybe from a malformed packet.
      class DataError < Error
      end


      # Regexp matching an RR string
      RR_REGEXP = Regexp.new("^\\s*(\\S+)\\s*(\\d+)?\\s+(" +
                               Net::DNS::RR::Classes.regexp +
                               "|CLASS\\d+)?\\s*(" +
                               Net::DNS::RR::Types.regexp +
                               "|TYPE\\d+)?\\s*(.*)$", Regexp::IGNORECASE)

      # Dimension of the sum of class, type, TTL and rdlength fields in a
      # RR portion of the packet, in bytes
      RRFIXEDSZ = 10


      # Create a new instance of Net::DNS::RR class, or an instance of
      # any of the subclass of the appropriate type.
      #
      # Argument can be a string or an hash. With a sting, we can pass
      # a RR resource record in the canonical format:
      #
      #   a     = Net::DNS::RR.new("foo.example.com. 86400 A 10.1.2.3")
      #   mx    = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #   cname = Net::DNS::RR.new("www.example.com 300 IN CNAME www1.example.com")
      #   txt   = Net::DNS::RR.new('baz.example.com 3600 HS TXT "text record"')
      #
      # Incidentally, +a+, +mx+, +cname+ and +txt+ objects will be instances of
      # respectively Net::DNS::RR::A, Net::DNS::RR::MX, Net::DNS::RR::CNAME and
      # Net::DNS::RR::TXT classes.
      #
      # The name and RR data are required; all other informations are optional.
      # If omitted, the +TTL+ defaults to 10800, +type+ default to +A+ and the RR class
      # defaults to +IN+.  Omitting the optional fields is useful for creating the
      # empty RDATA sections required for certain dynamic update operations.
      # All names must be fully qualified.  The trailing dot (.) is optional.
      #
      # The preferred method is however passing an hash with keys and values:
      #
      #   rr = Net::DNS::RR.new(
      #                 :name    => "foo.example.com",
      #                 :ttl     => 86400,
      #                 :cls     => "IN",
      #                 :type    => "A",
      #                 :address => "10.1.2.3"
      #         )
      #
      #   rr = Net::DNS::RR.new(
      #                 :name => "foo.example.com",
      #                 :rdata => "10.1.2.3"
      #         )
      #
      # Name and data are required; all the others fields are optionals like
      # we've seen before. The data field can be specified either with the
      # right name of the resource (+:address+ in the example above) or with
      # the generic key +:rdata+. Consult documentation to find the exact name
      # for the resource in each subclass.
      #
      def initialize(arg)
        instance = case arg
          when String
            new_from_string(arg)
          when Hash
            new_from_hash(arg)
          else
            raise ArgumentError, "Invalid argument, must be a RR string or an hash of values"
        end

        if @type.to_s == "ANY"
          @cls = Net::DNS::RR::Classes.new("IN")
        end

        build_pack
        set_type

        instance
      end

      # Return a new RR object of the correct type (like Net::DNS::RR::A
      # if the type is A) from a binary string, usually obtained from
      # network stream.
      #
      # This method is used when parsing a binary packet by the Packet
      # class.
      #
      def RR.parse(data)
        o = allocate
        obj, offset = o.send(:new_from_binary, data, 0)
        obj
      end

      # Same as RR.parse, but takes an entire packet binary data to
      # perform name expansion. Default when analizing a packet
      # just received from a network stream.
      #
      # Return an instance of appropriate class and the offset
      # pointing at the end of the data parsed.
      #
      def RR.parse_packet(data, offset)
        o = allocate
        o.send(:new_from_binary, data, offset)
      end

      def name
        @name
      end

      def ttl
        @ttl
      end

      # Type accessor
      def type
        @type.to_s
      end

      # Class accessor
      def cls
        @cls.to_s
      end


      def value
        get_inspect
      end

      # Data belonging to that appropriate class,
      # not to be used (use real accessors instead)
      def rdata
        @rdata
      end

      # Return the RR object in binary data format, suitable
      # for using in network streams.
      #
      #   raw_data = rr.data
      #   puts "RR is #{raw_data.size} bytes long"
      #
      def data
        str = pack_name(@name)
        str + [@type.to_i, @cls.to_i, ttl, @rdlength].pack("n2 N n") + get_data
      end

      # Return the RR object in binary data format, suitable
      # for using in network streams, with names compressed.
      # Must pass as arguments the offset inside the packet
      # and an hash of compressed names.
      #
      # This method is to be used in other classes and is
      # not intended for user space programs.
      #
      # TO FIX in one of the future releases
      #
      def comp_data(offset,compnames)
        str, offset, names = dn_comp(@name, offset, compnames)
        str    += [@type.to_i, @cls.to_i, ttl, @rdlength].pack("n2 N n")
        offset += Net::DNS::RRFIXEDSZ
        [str, offset, names]
      end


      # Returns a human readable representation of this record.
      # The value is always a String.
      #
      #   mx = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #   #=> example.com.            7200    IN      MX      10 mailhost.example.com.
      #
      def inspect
        to_s
      end

      # Returns a String representation of this record.
      #
      #   mx = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #   mx.to_s
      #   #=> "example.com.            7200    IN      MX      10 mailhost.example.com."
      #
      def to_s
        items = to_a.map { |e| e.to_s }
        if @name.size < 24
          items.pack("A24 A8 A8 A8 A*")
        else
          items.join("   ")
        end.to_s
      end

      # Returns an Array with all the attributes for this record.
      #
      #   mx = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
      #   mx.to_a
      #   #=> ["example.com.", 7200, "IN", "MX", "10 mailhost.example.com."]
      #
      def to_a
        [name, ttl, cls.to_s, type.to_s, value]
      end


      private

        def new_from_string(rrstring)
          unless rrstring =~ RR_REGEXP
            raise ArgumentError,
            "Format error for RR string (maybe CLASS and TYPE not valid?)"
          end

          # Name of RR - mandatory
          begin
            @name = $1.downcase
          rescue NoMethodError
            raise ArgumentError, "Missing name field in RR string #{rrstring}"
          end

          # Time to live for RR, default 3 hours
          @ttl = $2 ? $2.to_i : 10800

          # RR class, default to IN
          @cls = Net::DNS::RR::Classes.new $3

          # RR type, default to A
          @type = Net::DNS::RR::Types.new $4

          # All the rest is data
          @rdata = $5 ? $5.strip : ""

          if self.class == Net::DNS::RR
            Net::DNS::RR.const_get(@type.to_s).new(rrstring)
          else
            subclass_new_from_string(@rdata)
            self.class
          end
        end

        def new_from_hash(args)
          # Name field is mandatory
          unless args.has_key? :name
            raise ArgumentError, ":name field is mandatory"
          end

          @name  = args[:name].downcase
          @ttl   = args[:ttl] ? args[:ttl].to_i : 10800 # Default 3 hours
          @type  = Net::DNS::RR::Types.new args[:type]
          @cls  = Net::DNS::RR::Classes.new args[:cls]

          @rdata = args[:rdata] ? args[:rdata].strip : ""
          @rdlength = args[:rdlength] || @rdata.size

          if self.class == Net::DNS::RR
            Net::DNS::RR.const_get(@type.to_s).new(args)
          else
            hash = args - [:name, :ttl, :type, :cls]
            if hash.has_key? :rdata
              subclass_new_from_string(hash[:rdata])
            else
              subclass_new_from_hash(hash)
            end
            self.class
          end
        end

        def new_from_binary(data,offset)
          if self.class == Net::DNS::RR
            temp = dn_expand(data,offset)[1]
            type = Net::DNS::RR::Types.new data.unpack("@#{temp} n")[0]
            (eval "Net::DNS::RR::#{type}").parse_packet(data,offset)
          else
            @name,offset = dn_expand(data,offset)
            rrtype,cls,@ttl,@rdlength = data.unpack("@#{offset} n2 N n")
            @type = Net::DNS::RR::Types.new rrtype
            @cls = Net::DNS::RR::Classes.new cls
            offset += RRFIXEDSZ
            offset = subclass_new_from_binary(data,offset)
            build_pack
            set_type
            [self, offset]
          end
        end

        # Methods to be overridden by subclasses
        def subclass_new_from_array(arr)
        end
        def subclass_new_from_string(str)
        end
        def subclass_new_from_hash(hash)
        end
        def subclass_new_from_binary(data, offset)
        end
        def build_pack
        end
        def get_inspect
          @rdata
        end
        def get_data
          @rdata
        end

        def set_type
          # TODO: Here we should probably
          # raise NotImplementedError
          # if we want the method to be implemented in any subclass.
        end


      def self.new(*args)
        o   = allocate
        obj = o.send(:initialize,*args)
        if self == Net::DNS::RR
          obj
        else
          o
        end
      end

    end

  end
end
