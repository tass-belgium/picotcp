# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "net-dns"
  s.version = "0.8.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Marco Ceresa", "Simone Carletti"]
  s.date = "2013-05-08"
  s.description = "Net::DNS is a pure Ruby DNS library, with a clean OO interface and an extensible API."
  s.email = ["ceresa@gmail.com", "weppos@weppos.net"]
  s.files = [".gitignore", ".travis.yml", "CHANGELOG.md", "Gemfile", "README.md", "Rakefile", "THANKS.rdoc", "demo/check_soa.rb", "demo/threads.rb", "fixtures/resolv.conf", "lib/net/dns.rb", "lib/net/dns/core_ext.rb", "lib/net/dns/header.rb", "lib/net/dns/names.rb", "lib/net/dns/packet.rb", "lib/net/dns/question.rb", "lib/net/dns/resolver.rb", "lib/net/dns/resolver/socks.rb", "lib/net/dns/resolver/timeouts.rb", "lib/net/dns/rr.rb", "lib/net/dns/rr/a.rb", "lib/net/dns/rr/aaaa.rb", "lib/net/dns/rr/classes.rb", "lib/net/dns/rr/cname.rb", "lib/net/dns/rr/hinfo.rb", "lib/net/dns/rr/mr.rb", "lib/net/dns/rr/mx.rb", "lib/net/dns/rr/ns.rb", "lib/net/dns/rr/null.rb", "lib/net/dns/rr/ptr.rb", "lib/net/dns/rr/soa.rb", "lib/net/dns/rr/srv.rb", "lib/net/dns/rr/txt.rb", "lib/net/dns/rr/types.rb", "lib/net/dns/version.rb", "net-dns.gemspec", "test/header_test.rb", "test/names_test.rb", "test/packet_test.rb", "test/question_test.rb", "test/resolver/timeouts_test.rb", "test/resolver_test.rb", "test/rr/a_test.rb", "test/rr/aaaa_test.rb", "test/rr/classes_test.rb", "test/rr/cname_test.rb", "test/rr/hinfo_test.rb", "test/rr/mr_test.rb", "test/rr/mx_test.rb", "test/rr/ns_test.rb", "test/rr/types_test.rb", "test/rr_test.rb", "test/test_helper.rb"]
  s.homepage = "http://github.com/bluemonk/net-dns"
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.rubyforge_project = "net-dns"
  s.rubygems_version = "2.0.3"
  s.summary = "Pure Ruby DNS library."
  s.test_files = ["test/header_test.rb", "test/names_test.rb", "test/packet_test.rb", "test/question_test.rb", "test/resolver/timeouts_test.rb", "test/resolver_test.rb", "test/rr/a_test.rb", "test/rr/aaaa_test.rb", "test/rr/classes_test.rb", "test/rr/cname_test.rb", "test/rr/hinfo_test.rb", "test/rr/mr_test.rb", "test/rr/mx_test.rb", "test/rr/ns_test.rb", "test/rr/types_test.rb", "test/rr_test.rb", "test/test_helper.rb"]

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
