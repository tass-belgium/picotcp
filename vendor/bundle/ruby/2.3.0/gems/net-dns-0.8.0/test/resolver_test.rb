require 'test_helper'
require 'net/dns/resolver'

class Net::DNS::Resolver
  attr_reader :config
end


class ResolverTest < Test::Unit::TestCase

  def test_initialize
    assert_nothing_raised { Net::DNS::Resolver.new }
  end

  def test_initialize_with_config
    assert_nothing_raised { Net::DNS::Resolver.new({}) }
  end

  def test_initialize_with_multi_name_servers
    resolver = Net::DNS::Resolver.new({:config_file => 'fixtures/resolv.conf'})
    assert_equal ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4'], resolver.nameservers
  end

  def test_initialize_with_invalid_config_should_raise_argumenterror
    assert_raises(ArgumentError) { Net::DNS::Resolver.new("") }
    assert_raises(ArgumentError) { Net::DNS::Resolver.new(0) }
    assert_raises(ArgumentError) { Net::DNS::Resolver.new(:foo) }
  end

  def test_query_with_no_nameservers_should_raise_resolvererror
    assert_raises(Net::DNS::Resolver::Error) { Net::DNS::Resolver.new(:nameservers => []).query("example.com") }
  end

  # def test_send_to_ipv6_nameserver_should_not_raise_einval
  #   assert_nothing_raised { Net::DNS::Resolver.new(:nameservers => ['2001:4860:4860::8888', '2001:4860:4860::8844']).send('example.com')}
  # end

  # I know private methods are supposed to not be tested directly
  # but since this library lacks unit tests, for now let me test them in this way.

  def _make_query_packet(*args)
    Net::DNS::Resolver.new.send(:make_query_packet, *args)
  end

  def test_make_query_packet_from_ipaddr
    packet = _make_query_packet(IPAddr.new("192.168.1.1"), Net::DNS::A, cls = Net::DNS::IN)
    assert_equal "1.1.168.192.in-addr.arpa",  packet.question.first.qName
    assert_equal Net::DNS::PTR.to_i,          packet.question.first.qType.to_i
    assert_equal Net::DNS::IN.to_i,           packet.question.first.qClass.to_i
  end

  def test_make_query_packet_from_string_like_ipv4
    packet = _make_query_packet("192.168.1.1", Net::DNS::A, cls = Net::DNS::IN)
    assert_equal "1.1.168.192.in-addr.arpa",  packet.question.first.qName
    assert_equal Net::DNS::PTR.to_i,          packet.question.first.qType.to_i
    assert_equal Net::DNS::IN.to_i,           packet.question.first.qClass.to_i
  end

  def test_make_query_packet_from_string_like_ipv6
    packet = _make_query_packet("2001:1ac0::200:0:a5d1:6004:2", Net::DNS::A, cls = Net::DNS::IN)
    assert_equal "2.0.0.0.4.0.0.6.1.d.5.a.0.0.0.0.0.0.2.0.0.0.0.0.0.c.a.1.1.0.0.2.ip6.arpa",  packet.question.first.qName
    assert_equal Net::DNS::PTR.to_i,          packet.question.first.qType.to_i
    assert_equal Net::DNS::IN.to_i,           packet.question.first.qClass.to_i
  end

  def test_make_query_packet_from_string_like_hostname
    packet = _make_query_packet("ns2.google.com", Net::DNS::A, cls = Net::DNS::IN)
    assert_equal "ns2.google.com",            packet.question.first.qName
    assert_equal Net::DNS::A.to_i,            packet.question.first.qType.to_i
    assert_equal Net::DNS::IN.to_i,           packet.question.first.qClass.to_i
  end

  def test_make_query_packet_from_string_like_hostname_with_number
    packet = _make_query_packet("ns.google.com", Net::DNS::A, cls = Net::DNS::IN)
    assert_equal "ns.google.com",             packet.question.first.qName
    assert_equal Net::DNS::A.to_i,            packet.question.first.qType.to_i
    assert_equal Net::DNS::IN.to_i,           packet.question.first.qClass.to_i
  end

  def test_should_return_state_without_exception
    res = Net::DNS::Resolver.new
    assert_nothing_raised {res.state}
  end

  RubyPlatforms = [
    ["darwin9.0", false],   # Mac OS X
    ["darwin", false],      # JRuby on Mac OS X
    ["linux-gnu", false],
    ["mingw32", true],      # ruby 1.8.6 (2008-03-03 patchlevel 114) [i386-mingw32]
    ["mswin32", true],      # ruby 1.8.6 (2008-03-03 patchlevel 114) [i386-mswin32]
    ["mswin32", true],      # ruby 1.8.6 (2008-04-22 rev 6555) [x86-jruby1.1.1]
  ]

  C = Object.const_get(defined?(RbConfig) ? :RbConfig : :Config)::CONFIG

  def test_self_platform_windows_question
    RubyPlatforms.each do |platform, is_windows|
      assert_equal is_windows,
                    override_platform(platform) { Net::DNS::Resolver.platform_windows? },
                    "Expected `#{is_windows}' with platform `#{platform}'"
    end
  end


  private

  def override_platform(new_platform, &block)
    raise LocalJumpError, "no block given" unless block_given?
    old_platform = C["host_os"]
    C["host_os"] = new_platform
    result = yield
  ensure
    C["host_os"] = old_platform
    result
  end

end
