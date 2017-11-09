require 'test_helper'
require 'net/dns/rr'

class RRAAAATest < Test::Unit::TestCase

  def setup
    @rr_name    = "www.nic.it."
    @rr_type    = "AAAA"
    @rr_cls     = "IN"
    @rr_ttl     = 60
    @rr_value   = "2a00:d40:1:1::239"
    @rr_address = IPAddr.new(@rr_value)

    @rr_output  = "www.nic.it.             60      IN      AAAA    2a00:d40:1:1::239"

    @rr         = Net::DNS::RR::AAAA.new(:name => @rr_name, :address => @rr_address, :ttl => @rr_ttl)
  end


  def test_initialize_from_hash
    @record = Net::DNS::RR::AAAA.new(:name => @rr_name, :address => @rr_value, :ttl => @rr_ttl)
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_address, @record.address
    assert_equal @rr_value,   @record.value
  end

  def test_initialize_from_string
    @record = Net::DNS::RR::AAAA.new("#{@rr_name} #{@rr_ttl} #{@rr_cls} #{@rr_type} #{@rr_value}")
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_address, @record.address
    assert_equal @rr_value,   @record.value
  end

  def test_parse
    data = "\003www\003nic\002it\000\000\034\000\001\000\000\000<\000\020*\000\r@\000\001\000\001\000\000\000\000\000\000\0029"
    @record = Net::DNS::RR.parse(data)
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_address, @record.address
    assert_equal @rr_value,   @record.value
  end


  InvalidArguments = [
    { :name => "google.com", :address => "2a00" },
    { :name => "google.com" },
    Object.new,
    Array.new(7),
    "10800 IN AAAA",
    # FIXME: "google.com. 10800 IN B",
    # FIXME: "google.com. 10800 IM AAAA",
  ]

  InvalidArguments.each_with_index do |arguments, index|
    define_method "test_initialize_should_raise_with_invalid_arguments_#{index}" do
      assert_raises(ArgumentError) { Net::DNS::RR::AAAA.new(arguments) }
    end
  end


  def test_address_getter
    assert_equal  @rr_address, @rr.address
  end

  def test_address_setter
    assert_raises(ArgumentError) { @rr.address = nil }

    expected = IPAddr.new("2a00:d40:1:1::239")
    assert_equal expected, @rr.address = "2a00:d40:1:1::239"
    assert_equal expected, @rr.address

    expected = IPAddr.new("2a00:d40:1:1::240")
    assert_equal expected, @rr.address = IPAddr.new("2a00:d40:1:1::240")
    assert_equal expected, @rr.address
  end


  def test_value
    assert_equal  @rr_value, @rr.value
  end


  def test_inspect
    assert_equal  "www.nic.it.             60      IN      AAAA    2a00:d40:1:1::239",
                  @rr.inspect
  end

  def test_to_s
    assert_equal  "www.nic.it.             60      IN      AAAA    2a00:d40:1:1::239",
                  @rr.to_s
  end

  def test_to_a
    assert_equal  ["www.nic.it.", 60, "IN", "AAAA", "2a00:d40:1:1::239"],
                  @rr.to_a
  end

end
