# -*- encoding: utf-8 -*-
# stub: jekyll-coffeescript 1.0.2 ruby lib

Gem::Specification.new do |s|
  s.name = "jekyll-coffeescript"
  s.version = "1.0.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Parker Moore"]
  s.date = "2016-12-15"
  s.email = ["parkrmoore@gmail.com"]
  s.homepage = "https://github.com/jekyll/jekyll-coffeescript"
  s.licenses = ["MIT"]
  s.rubygems_version = "2.5.1"
  s.summary = "A CoffeeScript converter for Jekyll."

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<coffee-script-source>, ["~> 1.11.1"])
      s.add_runtime_dependency(%q<coffee-script>, ["~> 2.2"])
      s.add_development_dependency(%q<jekyll>, [">= 2.0"])
      s.add_development_dependency(%q<bundler>, ["~> 1.5"])
      s.add_development_dependency(%q<rake>, [">= 0"])
      s.add_development_dependency(%q<rspec>, [">= 0"])
    else
      s.add_dependency(%q<coffee-script-source>, ["~> 1.11.1"])
      s.add_dependency(%q<coffee-script>, ["~> 2.2"])
      s.add_dependency(%q<jekyll>, [">= 2.0"])
      s.add_dependency(%q<bundler>, ["~> 1.5"])
      s.add_dependency(%q<rake>, [">= 0"])
      s.add_dependency(%q<rspec>, [">= 0"])
    end
  else
    s.add_dependency(%q<coffee-script-source>, ["~> 1.11.1"])
    s.add_dependency(%q<coffee-script>, ["~> 2.2"])
    s.add_dependency(%q<jekyll>, [">= 2.0"])
    s.add_dependency(%q<bundler>, ["~> 1.5"])
    s.add_dependency(%q<rake>, [">= 0"])
    s.add_dependency(%q<rspec>, [">= 0"])
  end
end
