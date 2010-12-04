$:.unshift "./lib"
require 'rake'
require 'rake/testtask'
require 'rake/gempackagetask'
require 'em-dns-server'

spec = Gem::Specification.new do |s|
  s.name = "em-dns-server"
  s.version = DNSServer::VERSION
  s.author = "David Ricciardi"
  s.email = "nricciar@gmail.com"
  s.homepage = "http://github.com/nricciar/em-dns-server"
  s.platform = Gem::Platform::RUBY
  s.summary = "A DNS Server for EventMachine"
  s.files = FileList["{bin,lib,zones}/**/*"].to_a +
    ["Rakefile","README"]
  s.require_path = "lib"
  s.description = File.read("README")
  s.executables = ['em-dns-server']
  s.has_rdoc = false
  s.extra_rdoc_files = ["README"]
  s.add_dependency("daemons")
  s.add_dependency("eventmachine")
  s.add_dependency("dnsruby")
end

Rake::GemPackageTask.new(spec) do |pkg|
  pkg.need_tar = true
end
