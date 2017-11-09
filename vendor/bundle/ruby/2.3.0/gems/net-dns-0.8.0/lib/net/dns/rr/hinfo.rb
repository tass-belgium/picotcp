module Net # :nodoc:
  module DNS
    class RR

      #
      # = System Information Record (HINFO)
      #
      # Class for DNS HINFO resource records.
      #
      # Allows definition of the Hardware type and Operating System (OS) in use at a host.
      # For security reasons these records are rarely used on public servers.
      # If a space exists in the field it must be enclosed in quotes.
      # Single space between CPU and OS parameters.
      #
      class HINFO < RR

        # Gets the CPU value.
        #
        # Returns a String.
        def cpu
          @cpu
        end

        # Gets the OS value.
        #
        # Returns a String.
        def os
          @os
        end

        # Gets the standardized value for this record,
        # represented by the value of <tt>cpu</tt> and <tt>os</tt>.
        #
        # Returns a String.
        def value
          %Q{"#{cpu}" "#{os}"}
        end


        # Gets a list of all the attributes for this record.
        #
        # Returns an Array of values.
        def to_a
          [nil, nil, cls.to_s, type.to_s, value]
        end


        private

          def subclass_new_from_hash(options)
            if options.has_key?(:cpu) && options.has_key?(:os)
              @cpu = options[:cpu]
              @os  = options[:os]
            else
              raise ArgumentError, ":cpu and :os fields are mandatory"
            end
          end

          def subclass_new_from_string(str)
            @cpu, @os = check_hinfo(str)
          end

          def subclass_new_from_binary(data, offset)
            len  = data.unpack("@#{offset} C").first
            offset += 1
            @cpu = data[offset..(offset + len)]
            offset += len
            
            len  = data.unpack("@#{offset} C").first
            offset += 1
            @os  = data[offset..(offset + len)]
            offset += len
          end


          def set_type
            @type = Net::DNS::RR::Types.new("HINFO")
          end

          def get_inspect
            value
          end


          def check_hinfo(input)
            if input.to_s.strip =~ /^(?:["']?(.*?)["']?)\s+(?:["']?(.*?)["']?)$/
              [$1, $2]
            else
              raise ArgumentError, "Invalid HINFO Section `#{input}'"
            end
          end

          def build_pack
            @hinfo_pack  = ""
            @hinfo_pack += [cpu.size].pack("C") + cpu
            @hinfo_pack += [os.size ].pack("C") + os
            @rdlength = @hinfo_pack.size
          end

          def get_data
            @hinfo_pack
          end

      end

    end
  end
end
