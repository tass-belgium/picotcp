module JekyllOptionalFrontMatter
  class Generator < Jekyll::Generator
    attr_accessor :site

    safe true
    priority :normal

    def initialize(site)
      @site = site
    end

    def generate(site)
      @site = site
      return if site.config["require_front_matter"]
      site.pages.concat(pages_to_add)
    end

    private

    # An array of Jekyll::Pages to add, *excluding* blacklisted files
    def pages_to_add
      pages.reject { |page| blacklisted?(page) }
    end

    # An array of potential Jekyll::Pages to add, *including* blacklisted files
    def pages
      markdown_files.map { |static_file| page_from_static_file(static_file) }
    end

    # An array of Jekyll::StaticFile's with a site-defined markdown extension
    def markdown_files
      site.static_files.select { |file| markdown_converter.matches(file.extname) }
    end

    # Given a Jekyll::StaticFile, returns the file as a Jekyll::Page
    def page_from_static_file(static_file)
      base = static_file.instance_variable_get("@base")
      dir  = static_file.instance_variable_get("@dir")
      name = static_file.instance_variable_get("@name")
      Jekyll::Page.new(site, base, dir, name)
    end

    # Does the given Jekyll::Page match our filename blacklist?
    def blacklisted?(page)
      return false if whitelisted?(page)
      FILENAME_BLACKLIST.include?(page.basename.upcase)
    end

    def whitelisted?(page)
      return false unless site.config["include"].is_a? Array
      entry_filter.included?(page.path)
    end

    def markdown_converter
      @markdown_converter ||= site.find_converter_instance(Jekyll::Converters::Markdown)
    end

    def entry_filter
      @entry_filter ||= Jekyll::EntryFilter.new(site)
    end
  end
end
