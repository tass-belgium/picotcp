# -*- encoding: utf-8 -*-
# stub: jekyll-swiss 0.4.0 ruby lib

Gem::Specification.new do |s|
  s.name = "jekyll-swiss"
  s.version = "0.4.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["broccolini"]
  s.date = "2016-09-21"
  s.email = ["diana.mounter@gmail.com"]
  s.homepage = "http://broccolini.net/swiss"
  s.licenses = ["MIT"]
  s.rubygems_version = "2.5.1"
  s.summary = "A bold typographic theme for Jekyll, inspired by Swiss design."

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<jekyll>, ["~> 3.2"])
      s.add_development_dependency(%q<bundler>, ["~> 1.12"])
      s.add_development_dependency(%q<rake>, ["~> 10.0"])
    else
      s.add_dependency(%q<jekyll>, ["~> 3.2"])
      s.add_dependency(%q<bundler>, ["~> 1.12"])
      s.add_dependency(%q<rake>, ["~> 10.0"])
    end
  else
    s.add_dependency(%q<jekyll>, ["~> 3.2"])
    s.add_dependency(%q<bundler>, ["~> 1.12"])
    s.add_dependency(%q<rake>, ["~> 10.0"])
  end
end
