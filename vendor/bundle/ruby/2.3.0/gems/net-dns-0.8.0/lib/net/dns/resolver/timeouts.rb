require 'timeout'

module Net # :nodoc:
  module DNS
    class Resolver

      class DnsTimeout

        attr_reader :seconds


        def initialize(seconds)
          if seconds.is_a? Numeric and seconds >= 0
            @seconds = seconds
          else
            raise ArgumentError, "Invalid value for tcp timeout"
          end
        end

        # Returns a string representation of the timeout corresponding
        # to the number of <tt>@seconds</tt>.
        def to_s
          if @seconds == 0
            @output.to_s
          else
            @seconds.to_s
          end
        end

        def pretty_to_s
          transform(@seconds)
        end

        # Executes the method's block. If the block execution terminates before +sec+
        # seconds has passed, it returns true. If not, it terminates the execution
        # and raises Timeout::Error.
        # If @seconds is 0 or nil, no timeout is set.
        def timeout(&block)
          raise LocalJumpError, "no block given" unless block_given?
          Timeout.timeout(@seconds, &block)
        end


        private

          def transform(secs)
            case secs
              when 0
                to_s
              when 1..59
                "#{secs} seconds"
              when 60..3559
                "#{secs / 60} minutes and #{secs % 60} seconds"
              else
                hours = secs / 3600
                secs -= (hours * 3600)
                "#{hours} hours, #{secs / 60} minutes and #{secs % 60} seconds"
            end
          end

      end

      class TcpTimeout < DnsTimeout
        def initialize(seconds)
          @output = "infinite"
          super
        end
      end

      class UdpTimeout < DnsTimeout
        def initialize(seconds)
          @output = "not defined"
          super
        end
      end

    end
  end
end