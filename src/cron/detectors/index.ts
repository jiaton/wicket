import type { Row } from '../../cloudflare/analytics';
import type { PolicyKind } from '../../config/notifications';
import type { Settings } from '../../config/settings';
import type { Severity } from '../../notify';
import type { Address } from '../addresses';
import { appLogins } from './app-logins';
import { credentials } from './credentials';
import { guessing } from './guessing';
import { newCountry } from './new-country';
import { quietHours } from './quiet-hours';
import { scanning } from './scanning';

/** One line in a notification; `key` deduplicates it for an hour. */
export interface Alert {
  key: string;
  text: string;
  severity: Severity;
  /** Which notification policy entry decides its delivery. */
  kind: PolicyKind;
}

/** What every detector may use. Built once per analysis run; the base query is shared. */
export interface DetectorContext {
  cfg: Settings;
  now: number;
  /** The last window folded per address (from the shared base query). */
  addresses: Map<string, Address>;
  /** Runs an extra SQL query against the dataset (`ctx.cfg.analyticsDataset`); `WINDOW` is the window predicate. */
  query: (sql: string) => Promise<Row[]>;
  /** True when the address was banned in this window or earlier: nothing to say about it. */
  alreadyBanned: (ip: string) => Promise<boolean>;
  /** Wrong wicket passwords/tokens counted so far for an address. */
  failureCount: (ip: string) => Promise<number>;
}

/** A detector looks at the window and returns zero or more alerts. It must not send anything itself. */
export interface Detector {
  id: string;
  run: (ctx: DetectorContext) => Promise<Alert[]>;
}

export const WINDOW = "timestamp > NOW() - INTERVAL '5' MINUTE";

/**
 * All detectors, in the order their lines appear. Adding one = one file here, one entry
 * below, one test; nothing else changes. The notification policy decides delivery by `kind`.
 */
export const DETECTORS: Detector[] = [credentials, guessing, appLogins, scanning, newCountry, quietHours];
