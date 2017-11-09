module Net # :nodoc:
  module DNS

    module HashKeys # :nodoc:

      # Returns an hash with all the
      # keys turned into downcase
      #
      #   hsh = {"Test" => 1, "FooBar" => 2}
      #   hsh.downcase_keys!
      #      #=> {"test"=>1,"foobar"=>2}
      #
      def downcase_keys!
        hsh = Hash.new
        self.each do |key,val|
          hsh[key.downcase] = val
        end
        self.replace(hsh)
      end
      
    end

    module HashOperators # :nodoc:

      # Performs a sort of group difference
      # operation on hashes or arrays
      #
      #   a = {:a=>1,:b=>2,:c=>3}
      #   b = {:a=>1,:b=>2}
      #   c = [:a,:c]
      #   a-b #=> {:c=>3}
      #   a-c #=> {:b=>2}
      #
      def -(other)
        case other
          when Hash
            delete_if { |k,v| other.has_key?(k) }
          when Array
            delete_if { |k,v| other.include?(k) }
        end
      end

    end

  end
end


class Hash # :nodoc:
  include Net::DNS::HashKeys
  include Net::DNS::HashOperators
end