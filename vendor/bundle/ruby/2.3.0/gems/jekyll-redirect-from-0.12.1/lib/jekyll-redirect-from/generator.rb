module JekyllRedirectFrom
  class Generator < Jekyll::Generator
    safe true
    attr_reader :site

    def generate(site)
      @site = site

      # Inject our layout, unless the user has already specified a redirect layout'
      unless site.layouts.keys.any? { |name| name == "redirect" }
        site.layouts["redirect"] = JekyllRedirectFrom::Layout.new(site)
      end

      # Must duplicate pages to modify while in loop
      (site.docs_to_write + site.pages.dup).each do |doc|
        next unless JekyllRedirectFrom::CLASSES.include?(doc.class)
        generate_redirect_from(doc)
        generate_redirect_to(doc)
      end
    end

    private

    # For every `redirect_from` entry, generate a redirect page
    def generate_redirect_from(doc)
      doc.redirect_from.each do |path|
        doc.site.pages << RedirectPage.redirect_from(doc, path)
      end
    end

    def generate_redirect_to(doc)
      return unless doc.redirect_to
      redirect_page = RedirectPage.redirect_to(doc, doc.redirect_to)
      doc.data.merge!(redirect_page.data)
      doc.content = doc.output = redirect_page.output
    end
  end
end
