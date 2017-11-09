module Net # :nodoc:
  module DNS
    class RR

      #------------------------------------------------------------
      # RR type NULL
      #------------------------------------------------------------
      class NULL < RR
        attr_reader :null

        private

        def build_pack
          @null_pack = @null
          @rdlength = @null_pack.size
        end

        def get_data
          @null_pack
        end

        def get_inspect
          "#@null"
        end

        def subclass_new_from_hash(args)
          if args.has_key? :null
            @null = args[:null]
          else
            raise ArgumentError, ":null field is mandatory but missing"
          end
        end

        def subclass_new_from_string(str)
          @null = str.strip
        end

        def subclass_new_from_binary(data,offset)
          @null = data[offset..offset+@rdlength]
          return offset + @rdlength
        end

        private

          def set_type
            @type = Net::DNS::RR::Types.new("NULL")
          end

      end

    end
  end
end
