module Net # :nodoc:
  module DNS
    class RR

      #
      # = Name Server Record (NS)
      #
      # Class for DNS NS resource records.
      #
      class NS < RR

        # Gets the name server value.
        #
        # Returns a String.
        def nsdname
          @nsdname
        end

        # Gets the standardized value for this record,
        # represented by the value of <tt>nsdname</tt>.
        #
        # Returns a String.
        def value
          nsdname.to_s
        end


        private

          def subclass_new_from_hash(options)
            if options.has_key?(:nsdname)
              @nsdname = check_name(options[:nsdname])
            else
              raise ArgumentError, ":nsdname field is mandatory"
            end
          end

          def subclass_new_from_string(str)
            @nsdname = check_name(str)
          end

          def subclass_new_from_binary(data, offset)
            @nsdname, offset = dn_expand(data, offset)
            offset
          end


          def set_type
            @type = Net::DNS::RR::Types.new("NS")
          end

          def get_inspect
            value
          end


          def check_name(input)
            name = input.to_s
            unless name =~ /(\w\.?)+\s*$/ and name =~ /[a-zA-Z]/
              raise ArgumentError, "Invalid Name Server `#{name}'"
            end
            name
          end

          def build_pack
            @nsdname_pack = pack_name(@nsdname)
            @rdlength = @nsdname_pack.size
          end

          def get_data
            @nsdname_pack
          end

      end

    end
  end
end
