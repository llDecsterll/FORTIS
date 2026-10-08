export type ChannelSample = { at?: string | null } & {
  [metric: `nic${string}RxBps` | `nic${string}TxBps` | `nic${string}Mbps`]: number | null | undefined;
};

export interface ChannelHistoryPoint {
  at: number;
  rx: number;
  tx: number;
}

export interface ChannelMetrics {
  rx: number | null;
  tx: number | null;
  capacity: number | null;
  stale: boolean;
  at: number;
  history: ChannelHistoryPoint[];
  util: number | null;
}

export function mbps(value: unknown): number | null;
export function metricTime(value: unknown): number;
export function channelData(
  channels: { now?: ChannelSample | null; history?: ChannelSample[] | null } | null | undefined,
  suffix: string,
  clock?: number,
): ChannelMetrics;
export function chartPath<Key extends 'rx' | 'tx'>(
  history: ({ at: number } & Record<Key, number>)[],
  key: Key,
  ceiling: number,
): string;
