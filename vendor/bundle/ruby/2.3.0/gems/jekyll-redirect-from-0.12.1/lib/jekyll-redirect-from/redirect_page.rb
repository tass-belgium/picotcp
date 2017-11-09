# Encoding: utf-8
module JekyllRedirectFrom
  # Specialty page which implements the redirect path logic
  class RedirectPage < Jekyll::Page
    # Use Jekyll's native absolute_url filter
    include Jekyll::Filters::URLFilters

    DEFAULT_DATA = {
      "sitemap" => false,
      "layout"  => "redirect"
    }.freeze

    # Creates a new RedirectPage instance from a source path and redirect path
    #
    # site - The Site object
    # from - the (URL) path, relative to the site root to redirect from
    # to   - the relative path or URL which the page should redirect to
    def self.from_paths(site, from, to)
      page = RedirectPage.new(site, site.source, "", "redirect.html")
      page.set_paths(from, to)
      page
    end

    # Creates a new RedirectPage instance from the path to the given doc
    def self.redirect_from(doc, path)
      RedirectPage.from_paths(doc.site, path, doc.url)
    end

    # Creates a new RedirectPage instance from the doc to the given path
    def self.redirect_to(doc, path)
      RedirectPage.from_paths(doc.site, doc.url, path)
    end

    # Overwrite the default read_yaml method since the file doesn't exist
    def read_yaml(_base, _name, _opts = {})
      self.content = self.output = ""
      self.data ||= DEFAULT_DATA.dup
    end

    # Helper function to set the appropriate path metadata
    #
    # from - the relative path to the redirect page
    # to   - the relative path or absolute URL to the redirect target
    def set_paths(from, to)
      @context ||= context
      data.merge!({
        "permalink" => from,
        "redirect"  => {
          "from" => from,
          "to"   => to =~ %r!^https?://! ? to : absolute_url(to)
        }
      })
    end

    private

    def context
      JekyllRedirectFrom::Context.new(site)
    end
  end
end
