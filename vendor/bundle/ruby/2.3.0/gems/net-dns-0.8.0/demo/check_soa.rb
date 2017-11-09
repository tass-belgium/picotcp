#!/usr/bin/env ruby 

require 'rubygems' if "#{RUBY_VERSION}" < "1.9.0"
require 'net/dns'


#------------------------------------------------------------------------------
# Get the domain from the command line.
#------------------------------------------------------------------------------

raise ArgumentError, "Usage: check_soa.rb domain\n" unless ARGV.size == 1

domain = ARGV[0]

#------------------------------------------------------------------------------
# Find all the nameservers for the domain.
#------------------------------------------------------------------------------

res = Net::DNS::Resolver.new(:defname => false, :retry => 2)

ns_req = res.query(domain, Net::DNS::NS)
unless ns_req and ns_req.header.anCount > 0
  raise ArgumentError, "No nameservers found for domain: #{res.errorstring}"
end


# Send out non-recursive queries
res.recurse = false
# Do not buffer standard out
#| = 1;


#------------------------------------------------------------------------------
# Check the SOA record on each nameserver.
#------------------------------------------------------------------------------

ns_req.each_nameserver do |ns|
  
  #----------------------------------------------------------------------
  # Set the resolver to query this nameserver.
  #----------------------------------------------------------------------
  
  # In order to lookup the IP(s) of the nameserver, we need a Resolver
  # object that is set to our local, recursive nameserver.  So we create
  # a new object just to do that.
  
  local_res = Net::DNS::Resolver.new
  
  a_req = local_res.query(ns, Net::DNS::A)
  
  
  unless a_req 
    puts "Can not find address for ns: " + res.errorstring + "\n"
    next
  end
  
  
  a_req.each_address do |ip|

    #----------------------------------------------------------------------
    # Ask this IP.
    #----------------------------------------------------------------------
    res.nameservers=ip	
    
    print "#{ns} (#{ip}): "
    
    #----------------------------------------------------------------------
    # Get the SOA record.
    #----------------------------------------------------------------------
    
    soa_req = res.send(domain, Net::DNS::SOA, Net::DNS::IN)
    
    if soa_req == nil
      puts res.errorstring, "\n"
      next
    end
    
    #----------------------------------------------------------------------
    # Is this nameserver authoritative for the domain?
    #----------------------------------------------------------------------
    
    unless soa_req.header.auth? 
      print "isn't authoritative for domain\n"
      next
    end
    
    #----------------------------------------------------------------------
    # We should have received exactly one answer.
    #----------------------------------------------------------------------
    
    unless soa_req.header.anCount == 1 
      print "expected 1 answer, got " + soa_req.header.anCount.to_s + "\n"
      next
    end
    
    #----------------------------------------------------------------------
    # Did we receive an SOA record?
    #----------------------------------------------------------------------
    
    unless soa_req.answer[0].class == Net::DNS::RR::SOA
      print "expected SOA, got " + Net::DNS::RR::RRTypes.to_str(soa_req.answer[0].type) + "\n"
      next
    end
    
    #----------------------------------------------------------------------
    # Print the serial number.
    #----------------------------------------------------------------------
    
    print "has serial number " + soa_req.answer[0].serial.to_s + "\n"
    
  end
end



