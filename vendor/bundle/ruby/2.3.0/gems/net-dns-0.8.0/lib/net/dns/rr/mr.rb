module Net # :nodoc:
  module DNS

    class RR

      #
      # = Mail Rename Record (MR)
      #
      # Class for DNS MR resource records.
      #
      class MR < RR

        # Gets the newname value.
        #
        # Returns a String.
        def newname
          @newname
        end

        # Gets the standardized value for this record,
        # represented by the value of <tt>newname</tt>.
        #
        # Returns a String.
        def value
          newname.to_s
        end


        private

          def subclass_new_from_hash(options)
            if options.has_key?(:newname)
              @newname = check_name(options[:newname])
            else
              raise ArgumentError, ":newname field is mandatory"
            end
          end

          def subclass_new_from_string(str)
            @newname = check_name(str)
          end

          def subclass_new_from_binary(data, offset)
            @newname = dn_expand(data,offset)
            offset
          end


          def set_type
            @type = Net::DNS::RR::Types.new("MR")
          end

          def get_inspect
            value
          end


          def check_name(input)
            name = input.to_s
            unless name =~ /(\w\.?)+\s*$/
              raise ArgumentError, "Invalid Domain Name `#{name}'"
            end
            name
          end

          def build_pack
            @newname_pack = pack_name(@newname)
            @rdlength = @newname_pack.size
          end

          def get_data
            @newname_pack
          end

      end

    end
  end
end
