module JekyllTitlesFromHeadings
  class Generator < Jekyll::Generator
    attr_accessor :site

    TITLE_REGEX =
      %r!
        \A\s*                   # Beginning and whitespace
          (?:                   # either
            \#{1,3}\s+(.*)      # atx-style header
            |                   # or
            (.*)\r?\n[-=]+\s*   # Setex-style header
          )$                    # end of line
      !x
    CONVERTER_CLASS = Jekyll::Converters::Markdown
    STRIP_MARKUP_FILTERS = %i[
      markdownify strip_html normalize_whitespace
    ].freeze

    # Regex to strip extra markup still present after markdownify
    # (footnotes at the moment).
    EXTRA_MARKUP_REGEX = %r!\[\^[^\]]*\]!

    safe true
    priority :lowest

    def initialize(site)
      @site = site
    end

    def generate(site)
      @site = site

      site.pages.each do |document|
        next unless should_add_title?(document)
        document.data["title"] = title_for(document)
      end
    end

    def should_add_title?(document)
      markdown?(document) && !title?(document)
    end

    def title?(document)
      !document.data["title"].nil?
    end

    def markdown?(document)
      markdown_converter.matches(document.extname)
    end

    def markdown_converter
      @markdown_converter ||= site.find_converter_instance(CONVERTER_CLASS)
    end

    def title_for(document)
      return document.data["title"] if title?(document)
      matches = document.content.match(TITLE_REGEX)
      strip_markup(matches[1] || matches[2]) if matches
    rescue ArgumentError => e
      raise e unless e.to_s.start_with?("invalid byte sequence in UTF-8")
    end

    private

    def strip_markup(string)
      STRIP_MARKUP_FILTERS.reduce(string) do |memo, method|
        filters.public_send(method, memo)
      end.gsub(EXTRA_MARKUP_REGEX, "")
    end

    def filters
      @filters ||= JekyllTitlesFromHeadings::Filters.new(site)
    end
  end
end
