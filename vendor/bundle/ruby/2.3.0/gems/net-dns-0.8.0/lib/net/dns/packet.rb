require 'logger'
require 'net/dns/names'
require 'net/dns/header'
require 'net/dns/question'
require 'net/dns/rr'

module Net
  module DNS

    #
    # = Net::DNS::Packet
    #
    # The Net::DNS::Packet class represents an entire DNS packet,
    # divided in his main section:
    #
    # * Header (instance of Net::DNS::Header)
    # * Question (array of Net::DNS::Question objects)
    # * Answer, Authority, Additional (each formed by an array of Net::DNS::RR
    #   objects)
    #
    # You can use this class whenever you need to create a DNS packet, whether
    # in an user application, in a resolver instance (have a look, for instance,
    # at the <tt>Net::DNS::Resolver#send</tt> method) or for a nameserver.
    #
    # For example:
    #
    #   # Create a packet
    #   packet = Net::DNS::Packet.new("www.example.com")
    #   mx = Net::DNS::Packet.new("example.com", Net::DNS::MX)
    #
    #   # Getting packet binary data, suitable for network transmission
    #   data = packet.data
    #
    # A packet object can be created from binary data too, like an
    # answer packet just received from a network stream:
    #
    #   packet = Net::DNS::Packet::parse(data)
    #
    # Each part of a packet can be gotten by the right accessors:
    #
    #   header = packet.header     # Instance of Net::DNS::Header class
    #   question = packet.question # Instance of Net::DNS::Question class
    #
    #   # Iterate over additional RRs
    #   packet.additional.each do |rr|
    #     puts "Got an #{rr.type} record"
    #   end
    #
    # Some iterators have been written to easy the access of those RRs,
    # which are often the most important. So instead of doing:
    #
    #   packet.answer.each do |rr|
    #     if rr.type == Net::DNS::RR::Types::A
    #       # do something with +rr.address+
    #     end
    #   end
    #
    # we can do:
    #
    #   packet.each_address do |ip|
    #     # do something with +ip+
    #   end
    #
    # Be sure you don't miss all the iterators in the class documentation.
    #
    # == Logging facility
    #
    # As Net::DNS::Resolver class, Net::DNS::Packet class has its own logging
    # facility too. It work in the same way the other one do, so you can
    # maybe want to override it or change the file descriptor.
    #
    #   packet = Net::DNS::Packet.new("www.example.com")
    #   packet.logger = $stderr
    #
    #   # or even
    #   packet.logger = Logger.new("/tmp/packet.log")
    #
    # If the <tt>Net::DNS::Packet</tt> class is directly instantiated by the <tt>Net::DNS::Resolver</tt>
    # class, like the great majority of the time, it will use the same logger facility.
    #
    # Logger level will be set to <tt>Logger::Debug</tt> if <tt>$DEBUG</tt> variable is set.
    #
    class Packet
      include Names

      # Base error class.
      class Error < StandardError
      end

      # Generic Packet Error.
      class PacketError < Error
      end


      attr_reader :header, :question, :answer, :authority, :additional
      attr_reader :answerfrom, :answersize

      # Creates a new instance of <tt>Net::DNS::Packet</tt> class. Arguments are the
      # canonical name of the resource, an optional type field and an optional
      # class field. The record type and class can be omitted; they default
      # to +A+ and +IN+.
      #
      #   packet = Net::DNS::Packet.new("www.example.com")
      #   packet = Net::DNS::Packet.new("example.com", Net::DNS::MX)
      #   packet = Net::DNS::Packet.new("example.com", Net::DNS::TXT, Net::DNS::CH)
      #
      # This class no longer instantiate object from binary data coming from
      # network streams. Please use <tt>Net::DNS::Packet.parse</tt> instead.
      def initialize(name, type = Net::DNS::A, cls = Net::DNS::IN)
        @header = Net::DNS::Header.new(:qdCount => 1)
        @question = [Net::DNS::Question.new(name, type, cls)]
        @answer = []
        @authority = []
        @additional = []
        @logger = Logger.new $stdout
        @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN
      end


      # Checks if the packet is a QUERY packet
      def query?
        @header.opCode == Net::DNS::Header::QUERY
      end

      # Returns the packet object in binary data, suitable
      # for sending across a network stream.
      #
      #   packet_data = packet.data
      #   puts "Packet is #{packet_data.size} bytes long"
      #
      def data
        qdcount=ancount=nscount=arcount=0
        data = @header.data
        headerlength = data.length

        @question.each do |question|
          data += question.data
          qdcount += 1
        end
        @answer.each do |rr|
          data += rr.data#(data.length)
          ancount += 1
        end
        @authority.each do |rr|
          data += rr.data#(data.length)
          nscount += 1
        end
        @additional.each do |rr|
          data += rr.data#(data.length)
          arcount += 1
        end

        @header.qdCount = qdcount
        @header.anCount = ancount
        @header.nsCount = nscount
        @header.arCount = arcount

        @header.data + data[Net::DNS::HFIXEDSZ..data.size]
      end

      # Same as <tt>Net::DNS::Packet#data</tt>, but implements name compression
      # (see RFC1025) for a considerable save of bytes.
      #
      #   packet = Net::DNS::Packet.new("www.example.com")
      #   puts "Size normal is #{packet.data.size} bytes"
      #   puts "Size compressed is #{packet.data_comp.size} bytes"
      #
      def data_comp
        offset = 0
        compnames = {}
        qdcount=ancount=nscount=arcount=0
        data = @header.data
        headerlength = data.length

        @question.each do |question|
          str,offset,names = question.data
          data += str
          compnames.update(names)
          qdcount += 1
        end

        @answer.each do |rr|
          str,offset,names = rr.data(offset,compnames)
          data += str
          compnames.update(names)
          ancount += 1
        end

        @authority.each do |rr|
          str,offset,names = rr.data(offset,compnames)
          data += str
          compnames.update(names)
          nscount += 1
        end

        @additional.each do |rr|
          str,offset,names = rr.data(offset,compnames)
          data += str
          compnames.update(names)
          arcount += 1
        end

        @header.qdCount = qdcount
        @header.anCount = ancount
        @header.nsCount = nscount
        @header.arCount = arcount

        @header.data + data[Net::DNS::HFIXEDSZ..data.size]
      end

      # Returns a string containing a human-readable representation
      # of this <tt>Net::DNS::Packet</tt> instance.
      def inspect
        retval = ""
        if @answerfrom != "0.0.0.0:0" and @answerfrom
          retval += ";; Answer received from #@answerfrom (#{@answersize} bytes)\n;;\n"
        end

        retval += ";; HEADER SECTION\n"
        retval += @header.inspect

        retval += "\n"
        section = (@header.opCode == "UPDATE") ? "ZONE" : "QUESTION"
        retval += ";; #{section} SECTION (#{@header.qdCount} record#{@header.qdCount == 1 ? '' : 's'}):\n"
        @question.each do |qr|
          retval += ";; " + qr.inspect + "\n"
        end

        unless @answer.size == 0
          retval += "\n"
          section = (@header.opCode == "UPDATE") ? "PREREQUISITE" : "ANSWER"
          retval += ";; #{section} SECTION (#{@header.anCount} record#{@header.anCount == 1 ? '' : 's'}):\n"
          @answer.each do |rr|
            retval += rr.inspect + "\n"
          end
        end

        unless @authority.size == 0
          retval += "\n"
          section = (@header.opCode == "UPDATE") ? "UPDATE" : "AUTHORITY"
          retval += ";; #{section} SECTION (#{@header.nsCount} record#{@header.nsCount == 1 ? '' : 's'}):\n"
          @authority.each do |rr|
            retval += rr.inspect + "\n"
          end
        end

        unless @additional.size == 0
          retval += "\n"
          retval += ";; ADDITIONAL SECTION (#{@header.arCount} record#{@header.arCount == 1 ? '' : 's'}):\n"
          @additional.each do |rr|
            retval += rr.inspect + "\n"
          end
        end

        retval
      end
      alias_method :to_s, :inspect

      # Delegates to <tt>Net::DNS::Header#truncated?</tt>.
      def truncated?
        @header.truncated?
      end

      # Assigns a <tt>Net::DNS::Header</tt> <tt>object</tt>
      # to this <tt>Net::DNS::Packet</tt> instance.
      def header=(object)
        if object.kind_of? Net::DNS::Header
          @header = object
        else
          raise ArgumentError, "Argument must be a Net::DNS::Header object"
        end
      end

      # Assigns a <tt>Net::DNS::Question</tt> <tt>object</tt>
      # to this <tt>Net::DNS::Packet</tt> instance.
      def question=(object)
        case object
        when Array
          if object.all? {|x| x.kind_of? Net::DNS::Question}
            @question = object
          else
            raise ArgumentError, "Some of the elements is not an Net::DNS::Question object"
          end
        when Net::DNS::Question
          @question = [object]
        else
          raise ArgumentError, "Invalid argument, not a Question object nor an array of objects"
        end
      end

      # Assigns one or an array of <tt>Net::DNS::RR</tt> <tt>object</tt>s
      # to the answer section of this <tt>Net::DNS::Packet</tt> instance.
      def answer=(object)
        case object
          when Array
            if object.all? {|x| x.kind_of? Net::DNS::RR}
              @answer = object
            else
              raise ArgumentError, "Some of the elements is not an Net::DNS::RR object"
            end
          when Net::DNS::RR
            @answer = [object]
          else
            raise ArgumentError, "Invalid argument, not a RR object nor an array of objects"
        end
      end

      # Assigns one or an array of <tt>Net::DNS::RR</tt> <tt>object</tt>s
      # to the additional section of this <tt>Net::DNS::Packet</tt> instance.
      def additional=(object)
        case object
          when Array
            if object.all? {|x| x.kind_of? Net::DNS::RR}
              @additional = object
            else
              raise ArgumentError, "Some of the elements is not an Net::DNS::RR object"
            end
          when Net::DNS::RR
            @additional = [object]
          else
            raise ArgumentError, "Invalid argument, not a RR object nor an array of objects"
        end
      end

      # Assigns one or an array of <tt>Net::DNS::RR</tt> <tt>object</tt>s
      # to the authority section of this <tt>Net::DNS::Packet</tt> instance.
      def authority=(object)
        case object
          when Array
            if object.all? {|x| x.kind_of? Net::DNS::RR}
              @authority = object
            else
              raise ArgumentError, "Some of the elements is not an Net::DNS::RR object"
            end
          when Net::DNS::RR
            @authority = [object]
          else
            raise ArgumentError, "Invalid argument, not a RR object nor an array of objects"
        end
      end

      # Iterates every address in the +answer+ section
      # of this <tt>Net::DNS::Packet</tt> instance.
      #
      #   packet.each_address do |ip|
      #     ping ip.to_s
      #   end
      #
      # As you can see in the documentation for the <tt>Net::DNS::RR::A</tt> class,
      # the address returned is an instance of <tt>IPAddr</tt> class.
      def each_address(&block)
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::A
          yield elem.address
        end
      end

      # Iterates every nameserver in the +answer+ section
      # of this <tt>Net::DNS::Packet</tt> instance.
      #
      #   packet.each_nameserver do |ns|
      #     puts "Nameserver found: #{ns}"
      #   end
      #
      def each_nameserver(&block)
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::NS
          yield elem.nsdname
        end
      end

      # Iterates every exchange record in the +answer+ section
      # of this <tt>Net::DNS::Packet</tt> instance.
      #
      #   packet.each_mx do |pref,name|
      #     puts "Mail exchange #{name} has preference #{pref}"
      #   end
      #
      def each_mx(&block)
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::MX
          yield elem.preference, elem.exchange
        end
      end

      # Iterates every canonical name in the +answer+ section
      # of this <tt>Net::DNS::Packet</tt> instance.
      #
      #   packet.each_cname do |cname|
      #     puts "Canonical name: #{cname}"
      #   end
      #
      def each_cname(&block)
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::CNAME
          yield elem.cname
        end
      end

      # Iterates every pointer in the +answer+ section
      # of this <tt>Net::DNS::Packet</tt> instance.
      #
      #   packet.each_ptr do |ptr|
      #     puts "Pointer for resource: #{ptr}"
      #   end
      #
      def each_ptr(&block)
        @answer.each do |elem|
          next unless elem.class == Net::DNS::RR::PTR
          yield elem.ptrdname
        end
      end

      # Returns the packet size in bytes.
      #
      #   Resolver("www.google.com") do |packet|
      #     puts packet.size + " bytes"}
      #   end
      #   # => 484 bytes
      #
      def size
        data.size
      end

      # Checks whether the query returned a NXDOMAIN error,
      # meaning the queried domain name doesn't exist.
      #
      #   %w[a.com google.com ibm.com d.com].each do |domain|
      #     response = Net::DNS::Resolver.new.send(domain)
      #     puts "#{domain} doesn't exist" if response.nxdomain?
      #   end
      #   # => a.com doesn't exist
      #   # => d.com doesn't exist
      #
      def nxdomain?
        header.rCode.code == Net::DNS::Header::RCode::NAME
      end


      # Creates a new instance of <tt>Net::DNS::Packet</tt> class from binary data,
      # taken out from a network stream. For example:
      #
      #   # udp_socket is an UDPSocket waiting for a response
      #   ans = udp_socket.recvfrom(1500)
      #   packet = Net::DNS::Packet::parse(ans)
      #
      # An optional +from+ argument can be used to specify the information
      # of the sender. If data is passed as is from a Socket#recvfrom call,
      # the method will accept it.
      #
      # Be sure that your network data is clean from any UDP/TCP header,
      # especially when using RAW sockets.
      #
      def self.parse(*args)
        o = allocate
        o.send(:new_from_data, *args)
        o
      end

      private

        # New packet from binary data
        def new_from_data(data, from = nil)
          unless from
            if data.kind_of? Array
              data, from = data
            else
              from = [0, 0, "0.0.0.0", "unknown"]
            end
          end

          @answerfrom = from[2] + ":" + from[1].to_s
          @answersize = data.size
          @logger = Logger.new $stdout
          @logger.level = $DEBUG ? Logger::DEBUG : Logger::WARN

          #------------------------------------------------------------
          # Header section
          #------------------------------------------------------------
          offset = Net::DNS::HFIXEDSZ
          @header = Net::DNS::Header.parse(data[0..offset-1])

          @logger.debug ";; HEADER SECTION"
          @logger.debug @header.inspect

          #------------------------------------------------------------
          # Question section
          #------------------------------------------------------------
          section = @header.opCode == "UPDATE" ? "ZONE" : "QUESTION"
          @logger.debug ";; #{section} SECTION (#{@header.qdCount} record#{@header.qdCount == 1 ? '': 's'})"

          @question = []
          @header.qdCount.times do
            qobj,offset = parse_question(data,offset)
            @question << qobj
            @logger.debug ";; #{qobj.inspect}"
          end

          #------------------------------------------------------------
          # Answer/prerequisite section
          #------------------------------------------------------------
          section = @header.opCode == "UPDATE" ? "PREREQUISITE" : "ANSWER"
          @logger.debug ";; #{section} SECTION (#{@header.qdCount} record#{@header.qdCount == 1 ? '': 's'})"

          @answer = []
          @header.anCount.times do
            begin
              rrobj,offset = Net::DNS::RR.parse_packet(data,offset)
              @answer << rrobj
              @logger.debug rrobj.inspect
            rescue NameError => e
              warn "Net::DNS unsupported record type: #{e.message}"
            end
          end

          #------------------------------------------------------------
          # Authority/update section
          #------------------------------------------------------------
          section = @header.opCode == "UPDATE" ? "UPDATE" : "AUTHORITY"
          @logger.debug ";; #{section} SECTION (#{@header.nsCount} record#{@header.nsCount == 1 ? '': 's'})"

          @authority = []
          @header.nsCount.times do
            begin
              rrobj,offset = Net::DNS::RR.parse_packet(data,offset)
              @authority << rrobj
              @logger.debug rrobj.inspect
            rescue NameError => e
              warn "Net::DNS unsupported record type: #{e.message}"
            end
          end

          #------------------------------------------------------------
          # Additional section
          #------------------------------------------------------------
          @logger.debug ";; ADDITIONAL SECTION (#{@header.arCount} record#{@header.arCount == 1 ? '': 's'})"

          @additional = []
          @header.arCount.times do
            begin
              rrobj,offset = Net::DNS::RR.parse_packet(data,offset)
              @additional << rrobj
              @logger.debug rrobj.inspect
            rescue NameError => e
              warn "Net::DNS supported record type: #{e.message}"
            end
          end

        end


        # Parse question section
        def parse_question(data,offset)
          size = (dn_expand(data, offset)[1] - offset) + (2 * Net::DNS::INT16SZ)
          return [Net::DNS::Question.parse(data[offset, size]), offset + size]
        rescue StandardError => e
          raise PacketError, "Caught exception, maybe packet malformed => #{e.message}"
        end

    end

  end
end
