import type { Env } from '../config/env';
import { DEFAULT_POLICY, mergePolicy, type NotifyPolicy } from '../config/notifications';
import { readNotifySettings } from '../store/settings';

export interface ResolvedPolicy extends NotifyPolicy {
  /** Where the effective values come from: the owner's saved settings win over wicket.yaml. */
  source: 'defaults' | 'config' | 'saved';
}

/** Defaults ← `NOTIFY_POLICY_JSON` (compiled from wicket.yaml) ← the policy saved on the settings page. */
export async function resolvePolicy(env: Env): Promise<ResolvedPolicy> {
  const fromConfig = mergePolicy(DEFAULT_POLICY, env.NOTIFY_POLICY_JSON);
  const saved = await readNotifySettings(env);
  if (saved) return { ...mergePolicy(fromConfig, saved), source: 'saved' };
  return { ...fromConfig, source: env.NOTIFY_POLICY_JSON ? 'config' : 'defaults' };
}
