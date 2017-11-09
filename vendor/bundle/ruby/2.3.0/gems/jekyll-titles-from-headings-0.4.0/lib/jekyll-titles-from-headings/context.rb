module JekyllTitlesFromHeadings
  class Context
    attr_reader :site

    def initialize(site)
      @site = site
    end

    def registers
      { :site => site }
    end
  end
end
