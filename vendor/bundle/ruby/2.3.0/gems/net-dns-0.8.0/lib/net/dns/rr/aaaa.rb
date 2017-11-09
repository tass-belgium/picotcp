module Net
  module DNS
    class RR

      #
      # = IPv6 Address Record (AAAA)
      #
      # Class for DNS IPv6 Address (AAAA) resource records.
      #
      class AAAA < RR

        # Gets the current IPv6 address for this record.
        #
        # Returns an instance of IPAddr.
        def address
          @address
        end

        # Assigns a new IPv6 address to this record, which can be in the
        # form of a <tt>String</tt> or an <tt>IPAddr</tt> object.
        #
        # Examples
        #
        #   a.address = "192.168.0.1"
        #   a.address = IPAddr.new("10.0.0.1")
        #
        # Returns the new allocated instance of IPAddr.
        def address=(string_or_ipaddr)
          @address = check_address(string_or_ipaddr)
          build_pack
          @address
        end

        # Gets the standardized value for this record,
        # represented by the value of <tt>address</tt>.
        #
        # Returns a String.
        def value
          address.to_s
        end


        private

          def subclass_new_from_hash(options)
            if options.has_key?(:address)
              @address = check_address(options[:address])
            else
              raise ArgumentError, ":address field is mandatory"
            end
          end

          def subclass_new_from_string(str)
            @address = check_address(str)
          end

          def subclass_new_from_binary(data, offset)
            tokens = data.unpack("@#{offset} n8")
            @address = IPAddr.new(sprintf("%x:%x:%x:%x:%x:%x:%x:%x", *tokens))
            offset + 16
          end


          def set_type
            @type = Net::DNS::RR::Types.new("AAAA")
          end

          def get_inspect
            value
          end


          def check_address(input)
            address = case input
              when IPAddr
                input
              when String
                IPAddr.new(input)
              else
                raise ArgumentError, "Invalid IP address `#{input}'"
            end

            if !address.ipv6?
              raise(ArgumentError, "Must specify an IPv6 address")
            end

            address
          end

          def build_pack
            @address_pack = @address.hton
            @rdlength = @address_pack.size
          end

          def get_data
            @address_pack
          end

      end

    end
  end
end
