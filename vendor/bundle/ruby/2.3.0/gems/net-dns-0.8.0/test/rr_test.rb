require 'test_helper'
require 'net/dns/rr'

class RRTest < Test::Unit::TestCase
  
  def setup
    @rr_name = "example.com."
    @type = "A"
    @cls = "IN"
    @ttl = 10800
    @rdata = "64.233.187.99"

    @defaults = Net::DNS::RR.new(:name => @rr_name,
                                 :rdata => @rdata)
    
    
    @a_hash = Net::DNS::RR.new(:name => @rr_name,
                               :ttl => @ttl,
                               :cls => @cls,
                               :type => @type,
                               :address => @rdata)
    
    @a_string = Net::DNS::RR::A.new("example.com. 10800 IN A 64.233.187.99")
    
    @str = "example.com.            10800   IN      A       64.233.187.99"

    @a     = Net::DNS::RR.new("foo.example.com. 86400 A 10.1.2.3")
    @mx    = Net::DNS::RR.new("example.com. 7200 MX 10 mailhost.example.com.")
    @cname = Net::DNS::RR.new("www.example.com IN CNAME www1.example.com")
    @txt   = Net::DNS::RR.new('baz.example.com 3600 HS TXT "text record"')

    @a_data = @a.data
    @a_binary = Net::DNS::RR.parse(@a_data)
    @mx_data = @mx.data 
    @mx_binary = Net::DNS::RR.parse(@mx_data)

    @array = [@rr_name,@ttl,@cls,@type,@rdata]
  end

  def test_classes
    assert_instance_of Net::DNS::RR::A, @a 
    assert_instance_of Net::DNS::RR::MX, @mx
    assert_instance_of Net::DNS::RR::CNAME, @cname
    assert_instance_of Net::DNS::RR::TXT, @txt
    assert_instance_of Net::DNS::RR::A, @a_binary
    assert_instance_of Net::DNS::RR::MX, @mx_binary
  end

  def test_ttl
    assert_equal @a.ttl, 86400
    assert_equal @mx.ttl, 7200
    assert_equal @cname.ttl, 10800
    assert_equal @txt.ttl, 3600
    assert_equal @a_binary.ttl, 86400
    assert_equal @mx_binary.ttl, 7200    
  end

  def test_types
    assert_equal @a.type, "A"
    assert_equal @mx.type, "MX"
    assert_equal @cname.type, "CNAME"
    assert_equal @txt.type, "TXT"
    assert_equal @a_binary.type, "A"    
    assert_equal @mx_binary.type, "MX"    
  end
  
  def test_cls
    assert_equal @a.cls, "IN"
    assert_equal @mx.cls, "IN"
    assert_equal @cname.cls, "IN"
    assert_equal @txt.cls, "HS"
    assert_equal @a_binary.cls, "IN"    
    assert_equal @mx_binary.cls, "IN"    
  end

  def test_name
    assert_equal @a.name, "foo.example.com."
    assert_equal @mx.name, "example.com."
    assert_equal @cname.name, "www.example.com"
    assert_equal @txt.name, "baz.example.com"
    assert_equal @a_binary.name, "foo.example.com."    
    assert_equal @mx_binary.name, "example.com."    
  end    
  
  def test_rdata
    assert_equal @a.address.to_s, "10.1.2.3"
    assert_equal @mx.preference, 10
    assert_equal @mx.exchange, "mailhost.example.com."
    assert_equal @cname.cname, "www1.example.com"
    assert_equal @txt.txt, '"text record"'
    assert_equal @a_binary.address.to_s, "10.1.2.3"
    assert_equal @mx_binary.preference, 10
    assert_equal @mx_binary.exchange, "mailhost.example.com."
  end
  
  def test_simple
    assert_equal @rr_name,  @defaults.name
    assert_equal @type,  @defaults.type
    assert_equal @cls,   @defaults.cls
    assert_equal @ttl,   @defaults.ttl
    assert_equal @rdata, @defaults.rdata.to_s
    
    assert_equal(@str,@a_hash.inspect)
    assert_equal(@rr_name, @a_hash.name)
    assert_equal(@type, @a_hash.type)
    assert_equal(@cls, @a_hash.cls)
    assert_equal(@ttl, @a_hash.ttl)
    assert_equal(@rdata, @a_hash.address.to_s)

    assert_equal(@str, @a_string.inspect)
    assert_equal(@rr_name, @a_string.name)
    assert_equal(@type, @a_string.type)
    assert_equal(@cls, @a_string.cls)
    assert_equal(@ttl, @a_string.ttl)
    assert_equal(@rdata, @a_string.address.to_s)
    
    assert_equal(@a_data, @a_binary.data)
    assert_equal(@mx_data, @mx_binary.data)

    assert_equal(@str, @a_hash.to_s)
    assert_equal(@array, @a_hash.to_a)
  end

  def test_range
    assert_raises(ArgumentError) do
      Net::DNS::RR.new("google.com. 10800 IM A")
    end
  end

end
    
