require 'test_helper'
require 'net/dns/rr'

class RRCNAMETest < Test::Unit::TestCase

  def setup
    @rr_name    = "www.google.com."
    @rr_type    = "CNAME"
    @rr_cls     = "IN"
    @rr_ttl     = 550317
    @rr_value   = "www.l.google.com."
    @rr_cname   = @rr_value

    @rr_output  = "www.google.com.         550317  IN      CNAME   www.l.google.com."

    @rr         = Net::DNS::RR::CNAME.new(:name => @rr_name, :cname => @rr_cname, :ttl => @rr_ttl)
  end


  def test_initialize_from_hash
    @record = Net::DNS::RR::CNAME.new(:name => @rr_name, :cname => @rr_value, :ttl => @rr_ttl)
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_cname,   @record.cname
    assert_equal @rr_value,   @record.value
  end

  def test_initialize_from_string
    @record = Net::DNS::RR::CNAME.new("#{@rr_name} #{@rr_ttl} #{@rr_cls} #{@rr_type} #{@rr_value}")
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_cname,   @record.cname
    assert_equal @rr_value,   @record.value
  end

  def test_parse
    data = "\003www\006google\003com\000\000\005\000\001\000\be\255\000\022\003www\001l\006google\003com\000"
    @record = Net::DNS::RR.parse(data)
    assert_equal @rr_output,  @record.to_s
    assert_equal @rr_name,    @record.name
    assert_equal @rr_type,    @record.type
    assert_equal @rr_cls,     @record.cls
    assert_equal @rr_ttl,     @record.ttl
    assert_equal @rr_cname,   @record.cname
    assert_equal @rr_value,   @record.value
  end


  InvalidArguments = [
    # FIXME: { :name => "google.com", :cname => "foo___bar" },
    # FIXME: { :name => "google.com", :cname => "foo$bar" },
    { :name => "google.com" },
    Object.new,
    Array.new(7),
    "10800 IN CNAME",
    "google.com. 10800 IN CNAME",
  ]

  InvalidArguments.each_with_index do |arguments, index|
    define_method "test_initialize_should_raise_with_invalid_arguments_#{index}" do
      assert_raises(ArgumentError) { p Net::DNS::RR::CNAME.new(arguments) }
    end
  end


  def test_cname_getter
    assert_equal  @rr_cname, @rr.cname
  end


  def test_value
    assert_equal  @rr_value, @rr.value
  end


  def test_inspect
    assert_equal  "www.google.com.         550317  IN      CNAME   www.l.google.com.",
                  @rr.inspect
  end

  def test_to_s
    assert_equal  "www.google.com.         550317  IN      CNAME   www.l.google.com.",
                  @rr.to_s
  end

  def test_to_a
    assert_equal  ["www.google.com.", 550317, "IN", "CNAME", "www.l.google.com."],
                  @rr.to_a
  end

end
