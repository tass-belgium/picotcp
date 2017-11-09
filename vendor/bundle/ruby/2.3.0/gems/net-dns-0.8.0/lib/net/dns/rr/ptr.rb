module Net
  module DNS
    class RR

      #
      # = Pointer Record (PTR)
      #
      # Class for DNS Pointer (PTR) resource records.
      #
      # Pointer records are the opposite of A and AAAA RRs 
      # and are used in Reverse Map zone files to map
      # an IP address (IPv4 or IPv6) to a host name.
      #
      class PTR < RR

        # Gets the PTR value.
        #
        # Returns a String.
        def ptrdname
          @ptrdname.to_s
        end

        alias_method :ptr, :ptrdname

        # Gets the standardized value for this record,
        # represented by the value of <tt>ptrdname</tt>.
        #
        # Returns a String.
        def value
          ptrdname.to_s
        end


        private

        def build_pack
          @ptrdname_pack = pack_name(@ptrdname)
          @rdlength = @ptrdname_pack.size
        end

        def get_data
          @ptrdname_pack
        end

        def subclass_new_from_hash(args)
          if args.has_key?(:ptrdname) or args.has_key?(:ptr)
            @ptrdname = args[:ptrdname]
          else
            raise ArgumentError, ":ptrdname or :ptr field is mandatory"
          end
        end

        def subclass_new_from_string(str)
          @ptrdname = check_name(str)
        end

        def subclass_new_from_binary(data, offset)
          @ptrdname, offset = dn_expand(data, offset)
          offset
        end

        private

          def set_type
            @type = Net::DNS::RR::Types.new("PTR")
          end

          def get_inspect
            value
          end


          def check_name(input)
            IPAddr.new(str)
          rescue
            raise ArgumentError, "Invalid PTR Section `#{input}'"
          end

      end

    end
  end
end
