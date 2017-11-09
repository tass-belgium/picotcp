# -*- encoding: utf-8 -*-
# stub: jekyll-github-metadata 2.9.3 ruby lib

Gem::Specification.new do |s|
  s.name = "jekyll-github-metadata"
  s.version = "2.9.3"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Parker Moore"]
  s.date = "2017-09-07"
  s.email = ["parkrmoore@gmail.com"]
  s.homepage = "https://github.com/parkr/github-metadata"
  s.licenses = ["MIT"]
  s.rubygems_version = "2.5.1"
  s.summary = "The site.github namespace"

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<octokit>, ["!= 4.4.0", "~> 4.0"])
      s.add_runtime_dependency(%q<jekyll>, ["~> 3.1"])
      s.add_development_dependency(%q<bundler>, ["~> 1.5"])
      s.add_development_dependency(%q<rake>, [">= 0"])
      s.add_development_dependency(%q<netrc>, [">= 0"])
      s.add_development_dependency(%q<rspec>, [">= 0"])
      s.add_development_dependency(%q<rubocop>, ["~> 0.37"])
    else
      s.add_dependency(%q<octokit>, ["!= 4.4.0", "~> 4.0"])
      s.add_dependency(%q<jekyll>, ["~> 3.1"])
      s.add_dependency(%q<bundler>, ["~> 1.5"])
      s.add_dependency(%q<rake>, [">= 0"])
      s.add_dependency(%q<netrc>, [">= 0"])
      s.add_dependency(%q<rspec>, [">= 0"])
      s.add_dependency(%q<rubocop>, ["~> 0.37"])
    end
  else
    s.add_dependency(%q<octokit>, ["!= 4.4.0", "~> 4.0"])
    s.add_dependency(%q<jekyll>, ["~> 3.1"])
    s.add_dependency(%q<bundler>, ["~> 1.5"])
    s.add_dependency(%q<rake>, [">= 0"])
    s.add_dependency(%q<netrc>, [">= 0"])
    s.add_dependency(%q<rspec>, [">= 0"])
    s.add_dependency(%q<rubocop>, ["~> 0.37"])
  end
end
