import { describe, expect, it } from 'vitest';
import { safeEqual, signSession, signUnban, verifySession } from '../src/core/crypto';

const passwords = { owner: 'pw-a', friend: 'pw-b' };

describe('sessions', () => {
  it('round-trips and carries the role', async () => {
    const v = await signSession('s', 'pw-b', 'friend', 1000);
    expect(await verifySession(v, 's', passwords, 1500, 3600)).toEqual({ role: 'friend', issuedAt: 1000 });
  });

  it('rejects tampering, expiry, future issue times and role swaps', async () => {
    const v = await signSession('s', 'pw-a', 'owner', 1000);
    expect(await verifySession(v.replace('owner', 'friend'), 's', passwords, 1500, 3600)).toBeNull();
    expect(await verifySession(`${v}0`, 's', passwords, 1500, 3600)).toBeNull();
    expect(await verifySession(v, 's', passwords, 1000 + 3601, 3600)).toBeNull();
    expect(await verifySession(v, 's', passwords, 900, 3600)).toBeNull();
    expect(await verifySession(v, 'other', passwords, 1500, 3600)).toBeNull();
    expect(await verifySession(undefined, 's', passwords, 1500, 3600)).toBeNull();
    expect(await verifySession('garbage', 's', passwords, 1500, 3600)).toBeNull();
  });

  it('changing one password logs out only that role', async () => {
    const owner = await signSession('s', 'pw-a', 'owner', 1000);
    const friend = await signSession('s', 'pw-b', 'friend', 1000);
    const rotated = { owner: 'pw-a', friend: 'pw-c' };
    expect(await verifySession(owner, 's', rotated, 1500, 3600)).not.toBeNull();
    expect(await verifySession(friend, 's', rotated, 1500, 3600)).toBeNull();
    expect(await verifySession(friend, 's', { owner: 'pw-a', friend: undefined }, 1500, 3600)).toBeNull();
  });
});

describe('safeEqual', () => {
  it('compares content and length', () => {
    expect(safeEqual('abc', 'abc')).toBe(true);
    expect(safeEqual('abc', 'abd')).toBe(false);
    expect(safeEqual('abc', 'abcabc')).toBe(false);
    expect(safeEqual('', '')).toBe(true);
    expect(safeEqual('', 'a')).toBe(false);
  });
});

describe('unban signatures', () => {
  it('bind ip, expiry and the ban timestamp', async () => {
    const sig = await signUnban('s', '1.2.3.4', 99, 5);
    expect(sig).toBe(await signUnban('s', '1.2.3.4', 99, 5));
    expect(sig).not.toBe(await signUnban('s', '1.2.3.5', 99, 5));
    expect(sig).not.toBe(await signUnban('s', '1.2.3.4', 100, 5));
    expect(sig).not.toBe(await signUnban('s', '1.2.3.4', 99, 6));
  });
});
