require 'test_helper'
require 'net/dns/rr'

class RRClassesTest < Test::Unit::TestCase

  def setup
    @classes = {
    }
    @regexp_string = "ANY|CH|HS|IN|NONE"
  end


  StrAndNum = [
      ['IN'   ,   1],
      ['CH'   ,   3],
      ['HS'   ,   4],
      ['NONE' , 254],
      ['ANY'  , 255],
  ]

  StrAndNum.each do |str, num|
    define_method "test_initialize_from_str_#{str}" do
      instance = Net::DNS::RR::Classes.new(str)
      assert_equal str, instance.to_s
      assert_equal num, instance.to_i
    end
    define_method "test_initialize_from_num_#{num}" do
      instance = Net::DNS::RR::Classes.new(num)
      assert_equal str, instance.to_s
      assert_equal num, instance.to_i
    end
  end

  def test_initialize_should_raise_with_invalid_class
    assert_raises(ArgumentError) { Net::DNS::RR::Classes.new(Hash.new) }
  end


  def test_inspect
    assert_equal 1, Net::DNS::RR::Classes.new(1).inspect
    assert_equal 1, Net::DNS::RR::Classes.new("IN").inspect
  end

  def test_to_s
    assert_equal "IN", Net::DNS::RR::Classes.new(1).to_s
    assert_equal "IN", Net::DNS::RR::Classes.new("IN").to_s
  end

  def test_to_i
    assert_equal 1, Net::DNS::RR::Classes.new(1).to_i
    assert_equal 1, Net::DNS::RR::Classes.new("IN").to_i
  end


  def test_self_default
    # Default type should be ANY => 255
    instance = Net::DNS::RR::Classes.new(nil)
    assert_equal 1,    instance.to_i
    assert_equal "IN", instance.to_s

    # Let's change default behaviour
    Net::DNS::RR::Classes.default = "CH"
    instance = Net::DNS::RR::Classes.new(nil)
    assert_equal 3,    instance.to_i
    assert_equal "CH", instance.to_s

    Net::DNS::RR::Classes.default = "IN"
    instance = Net::DNS::RR::Classes.new(nil)
    assert_equal 1,    instance.to_i
    assert_equal "IN", instance.to_s
  end

  def test_self_valid?
    assert  Net::DNS::RR::Classes.valid?("IN")
    assert  Net::DNS::RR::Classes.valid?(1)
    assert !Net::DNS::RR::Classes.valid?("Q")
    assert !Net::DNS::RR::Classes.valid?(256)
    assert_raises(ArgumentError) { Net::DNS::RR::Classes.valid?(Hash.new) }
  end

  def test_self_regexp
    assert_equal @regexp_string, Net::DNS::RR::Classes.regexp
  end

end
