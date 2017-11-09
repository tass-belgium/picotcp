module Jekyll
  module Converters
    class CoffeeScript < Converter
      safe true
      priority :low

      def setup
        require "coffee-script"
        @setup = true
      end

      def matches(ext)
        ext.downcase == ".coffee"
      end

      def output_ext(ext)
        ".js"
      end

      def convert(content)
        setup unless @setup
        ::CoffeeScript.compile(content)
      end
    end
  end
end
