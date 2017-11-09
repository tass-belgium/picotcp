# -*- encoding: utf-8 -*-
# stub: minima 2.1.1 ruby lib

Gem::Specification.new do |s|
  s.name = "minima"
  s.version = "2.1.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.metadata = { "plugin_type" => "theme" } if s.respond_to? :metadata=
  s.require_paths = ["lib"]
  s.authors = ["Joel Glovier"]
  s.bindir = "exe"
  s.date = "2017-04-13"
  s.email = ["jglovier@github.com"]
  s.homepage = "https://github.com/jekyll/minima"
  s.licenses = ["MIT"]
  s.rubygems_version = "2.5.1"
  s.summary = "A beautiful, minimal theme for Jekyll."

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<jekyll>, ["~> 3.3"])
      s.add_development_dependency(%q<bundler>, ["~> 1.12"])
    else
      s.add_dependency(%q<jekyll>, ["~> 3.3"])
      s.add_dependency(%q<bundler>, ["~> 1.12"])
    end
  else
    s.add_dependency(%q<jekyll>, ["~> 3.3"])
    s.add_dependency(%q<bundler>, ["~> 1.12"])
  end
end
