# -*- encoding: utf-8 -*-
# stub: jekyll-relative-links 0.5.1 ruby lib

Gem::Specification.new do |s|
  s.name = "jekyll-relative-links"
  s.version = "0.5.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Ben Balter"]
  s.date = "2017-10-30"
  s.email = ["ben.balter@github.com"]
  s.homepage = "https://github.com/benbalter/jekyll-relative-links"
  s.licenses = ["MIT"]
  s.rubygems_version = "2.5.1"
  s.summary = "A Jekyll plugin to convert relative links to markdown files to their rendered equivalents."

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<jekyll>, ["~> 3.3"])
      s.add_development_dependency(%q<rubocop>, ["~> 0.43"])
      s.add_development_dependency(%q<rspec>, ["~> 3.5"])
    else
      s.add_dependency(%q<jekyll>, ["~> 3.3"])
      s.add_dependency(%q<rubocop>, ["~> 0.43"])
      s.add_dependency(%q<rspec>, ["~> 3.5"])
    end
  else
    s.add_dependency(%q<jekyll>, ["~> 3.3"])
    s.add_dependency(%q<rubocop>, ["~> 0.43"])
    s.add_dependency(%q<rspec>, ["~> 3.5"])
  end
end
