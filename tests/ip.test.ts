import { describe, expect, it } from 'vitest';
import { addressKey, ipAllowed, ipv6ToBigInt } from '../src/core/ip';

describe('addresses', () => {
  it('keys IPv6 by the /64 and leaves IPv4 and garbage alone', () => {
    expect(addressKey('203.0.113.9')).toBe('203.0.113.9');
    expect(addressKey('2600:8800:618b:e000:c8d0:eaa:e91d:aa0b')).toBe('2600:8800:618b:e000::/64');
    expect(addressKey('2600:8800:618b:e000:20d6:f674:41b3:6a3a')).toBe('2600:8800:618b:e000::/64');
    expect(addressKey('2001:db8::1')).toBe('2001:db8:0:0::/64');
    expect(addressKey('::ffff:192.0.2.1')).toBe('0:0:0:0::/64');
    expect(addressKey('2001:db8:0:0::/64')).toBe('2001:db8:0:0::/64'); // already a key
    expect(addressKey('not-an-ip')).toBe('not-an-ip');
    expect(ipv6ToBigInt('2001:db8:::1')).toBeNull();
    expect(ipv6ToBigInt('2001:db8::g')).toBeNull();
  });

  it('allow list: IPv4 literal and CIDR, IPv6 literal (its /64), IPv6 CIDR; keys match too', () => {
    const allow = ['203.0.113.9', '198.51.100.0/24', '2001:db8:1:2::1', '2a00:1450::/32'];
    expect(ipAllowed('203.0.113.9', allow)).toBe(true);
    expect(ipAllowed('203.0.113.10', allow)).toBe(false);
    expect(ipAllowed('198.51.100.77', allow)).toBe(true);
    expect(ipAllowed('2001:db8:1:2:aaaa::1', allow)).toBe(true); // same /64 as the literal
    expect(ipAllowed('2001:db8:1:2::/64', allow)).toBe(true); // the key wicket works with
    expect(ipAllowed('2001:db8:1:3::1', allow)).toBe(false);
    expect(ipAllowed('2a00:1450:4001:80b::200e', allow)).toBe(true);
    expect(ipAllowed('2a01::1', allow)).toBe(false);
    expect(ipAllowed('garbage', allow)).toBe(false);
    expect(ipAllowed('203.0.113.9', ['203.0.113.0/40', 'x/y', ''])).toBe(false);
  });
});
