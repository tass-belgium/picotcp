# -*- encoding: utf-8 -*-
# stub: jekyll-watch 1.5.0 ruby lib

Gem::Specification.new do |s|
  s.name = "jekyll-watch"
  s.version = "1.5.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Parker Moore"]
  s.date = "2016-07-20"
  s.email = ["parkrmoore@gmail.com"]
  s.homepage = "https://github.com/jekyll/jekyll-watch"
  s.licenses = ["MIT"]
  s.rubygems_version = "2.5.1"
  s.summary = "Rebuild your Jekyll site when a file changes with the `--watch` switch."

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<listen>, ["< 3.1", "~> 3.0"])
      s.add_development_dependency(%q<bundler>, ["~> 1.6"])
      s.add_development_dependency(%q<rubocop>, ["~> 0.35.1"])
      s.add_development_dependency(%q<rake>, [">= 0"])
      s.add_development_dependency(%q<rspec>, ["~> 3.0"])
      s.add_development_dependency(%q<jekyll>, [">= 2.0"])
    else
      s.add_dependency(%q<listen>, ["< 3.1", "~> 3.0"])
      s.add_dependency(%q<bundler>, ["~> 1.6"])
      s.add_dependency(%q<rubocop>, ["~> 0.35.1"])
      s.add_dependency(%q<rake>, [">= 0"])
      s.add_dependency(%q<rspec>, ["~> 3.0"])
      s.add_dependency(%q<jekyll>, [">= 2.0"])
    end
  else
    s.add_dependency(%q<listen>, ["< 3.1", "~> 3.0"])
    s.add_dependency(%q<bundler>, ["~> 1.6"])
    s.add_dependency(%q<rubocop>, ["~> 0.35.1"])
    s.add_dependency(%q<rake>, [">= 0"])
    s.add_dependency(%q<rspec>, ["~> 3.0"])
    s.add_dependency(%q<jekyll>, [">= 2.0"])
  end
end
