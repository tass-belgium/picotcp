require 'test_helper'
require 'net/dns/rr'

class RRTypesTest < Test::Unit::TestCase

  def setup
  end
    
  def test_default
    # Default type should be ANY => 255
    instance = Net::DNS::RR::Types.new(nil)
    assert_equal("1", instance.to_str)
    assert_equal("A", instance.to_s)
    
    # Let's change default behaviour
    Net::DNS::RR::Types.default = "A"
    instance = Net::DNS::RR::Types.new(nil)
    assert_equal("1", instance.to_str)
    assert_equal("A", instance.to_s)

    Net::DNS::RR::Types.default = "ANY"
    instance = Net::DNS::RR::Types.new(nil)
    assert_equal("255", instance.to_str)
    assert_equal("ANY", instance.to_s)
  end

  def test_types
    Net::DNS::RR::Types::TYPES.each do |key, num|
      instance_from_string = Net::DNS::RR::Types.new(key)
      instance_from_num = Net::DNS::RR::Types.new(num)
      assert_equal(key, instance_from_string.to_s)
      assert_equal(num.to_s, instance_from_string.to_str)
      assert_equal(key, instance_from_num.to_s)
      assert_equal(num.to_s, instance_from_num.to_str)
    end
    assert_raises(ArgumentError) do
      Net::DNS::RR::Types.new(Hash.new)
    end
  end

  def test_regexp
    pattern = Net::DNS::RR::Types.regexp
    assert_instance_of String, pattern
    Net::DNS::RR::Types::TYPES.each do |key, num|
      assert_match /\|?#{key}\|?/, pattern
    end
  end
  
  def test_valid?
    assert_equal(true,  Net::DNS::RR::Types.valid?("A"))
    assert_equal(true,  Net::DNS::RR::Types.valid?(1))
    assert_equal(false, Net::DNS::RR::Types.valid?("Q"))
    assert_equal(false, Net::DNS::RR::Types.valid?(256))
    assert_raises(ArgumentError) do
      Net::DNS::RR::Types.valid? Hash.new
    end
  end

  def test_to_str
    assert_equal("A", Net::DNS::RR::Types.to_str(1))
    assert_raises(ArgumentError) do
      Net::DNS::RR::Types.to_str(256)
    end
    assert_raises(ArgumentError) do
      Net::DNS::RR::Types.to_str("string")
    end
  end

end
