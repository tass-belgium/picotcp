# -*- encoding: utf-8 -*-
# stub: unicode-display_width 1.3.0 ruby lib

Gem::Specification.new do |s|
  s.name = "unicode-display_width"
  s.version = "1.3.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Jan Lelis"]
  s.date = "2017-06-19"
  s.description = "[Unicode 10.0.0] Determines the monospace display width of a string using EastAsianWidth.txt, Unicode general category, and other data."
  s.email = "mail@janlelis.de"
  s.extra_rdoc_files = ["README.md", "MIT-LICENSE.txt", "CHANGELOG.md"]
  s.files = ["CHANGELOG.md", "MIT-LICENSE.txt", "README.md"]
  s.homepage = "http://github.com/janlelis/unicode-display_width"
  s.licenses = ["MIT"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.9.3")
  s.rubygems_version = "2.5.1"
  s.summary = "Determines the monospace display width of a string in Ruby."

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rspec>, ["~> 3.4"])
      s.add_development_dependency(%q<rake>, ["~> 10.4"])
    else
      s.add_dependency(%q<rspec>, ["~> 3.4"])
      s.add_dependency(%q<rake>, ["~> 10.4"])
    end
  else
    s.add_dependency(%q<rspec>, ["~> 3.4"])
    s.add_dependency(%q<rake>, ["~> 10.4"])
  end
end
