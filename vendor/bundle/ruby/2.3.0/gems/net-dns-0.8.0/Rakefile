require 'rubygems'
require 'bundler'

$:.unshift(File.dirname(__FILE__) + "/lib")
require 'net/dns'


# Common package properties
PKG_NAME    = ENV['PKG_NAME']    || 'net-dns'
PKG_VERSION = ENV['PKG_VERSION'] || Net::DNS::VERSION


# Run test by default.
task :default => :test


spec = Gem::Specification.new do |s|
  s.name              = PKG_NAME
  s.version           = PKG_VERSION
  s.summary           = "Pure Ruby DNS library."
  s.description       = "Net::DNS is a pure Ruby DNS library, with a clean OO interface and an extensible API."

  s.required_ruby_version = ">= 1.8.7"

  s.authors           = ["Marco Ceresa", "Simone Carletti"]
  s.email             = ["ceresa@gmail.com", "weppos@weppos.net"]
  s.homepage          = "http://github.com/bluemonk/net-dns"
  s.rubyforge_project = "net-dns"

  s.add_development_dependency "rake",  "~> 10.0"
  s.add_development_dependency "yard"

  s.files             = `git ls-files`.split("\n")
  s.test_files        = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.require_paths     = %w( lib )
end


require 'rubygems/package_task'

Gem::PackageTask.new(spec) do |pkg|
  pkg.gem_spec = spec
end

desc "Build the gemspec file #{spec.name}.gemspec"
task :gemspec do
  file = File.dirname(__FILE__) + "/#{spec.name}.gemspec"
  File.open(file, "w") {|f| f << spec.to_ruby }
end


require 'rake/testtask'

# Run all the tests in the /test folder
Rake::TestTask.new do |t|
  t.libs << "test"
  t.test_files = FileList["test/**/*_test.rb"]
  t.verbose = true
end


require 'yard'
require 'yard/rake/yardoc_task'

YARD::Rake::YardocTask.new(:yardoc)


desc "Open an irb session preloaded with this library"
task :console do
  sh "irb -rubygems -I lib -r net/dns.rb"
end
