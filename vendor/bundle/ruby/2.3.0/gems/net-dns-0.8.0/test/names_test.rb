require 'test_helper'
require 'net/dns/names'

class NamesTest < Test::Unit::TestCase
  include Net::DNS::Names

  def test_long_names
    assert_nothing_raised do
      pack_name('a' * 63)
    end
    assert_raises ArgumentError do
      pack_name('a' * 64)
    end
    assert_nothing_raised do
      pack_name(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 63].join('.'))
    end
    assert_raises ArgumentError do
      pack_name(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 63, 'e'].join('.'))
    end
  end
end
