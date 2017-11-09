# -*- encoding: utf-8 -*-
# stub: net-dns 0.8.0 ruby lib

Gem::Specification.new do |s|
  s.name = "net-dns"
  s.version = "0.8.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib"]
  s.authors = ["Marco Ceresa", "Simone Carletti"]
  s.date = "2013-05-08"
  s.description = "Net::DNS is a pure Ruby DNS library, with a clean OO interface and an extensible API."
  s.email = ["ceresa@gmail.com", "weppos@weppos.net"]
  s.homepage = "http://github.com/bluemonk/net-dns"
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.rubyforge_project = "net-dns"
  s.rubygems_version = "2.5.1"
  s.summary = "Pure Ruby DNS library."

  s.installed_by_version = "2.5.1" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake>, ["~> 10.0"])
      s.add_development_dependency(%q<yard>, [">= 0"])
    else
      s.add_dependency(%q<rake>, ["~> 10.0"])
      s.add_dependency(%q<yard>, [">= 0"])
    end
  else
    s.add_dependency(%q<rake>, ["~> 10.0"])
    s.add_dependency(%q<yard>, [">= 0"])
  end
end
