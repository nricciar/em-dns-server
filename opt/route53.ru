require 'rubygems'
require 'em-dns-server'
require 'em-dns-server/api'

DNSServer.init()

run DNSServer::WebAPI
