export function startLiveRefresh(
  load: () => unknown | Promise<unknown>,
  options?: {
    env?: Pick<Window, 'setTimeout' | 'clearTimeout' | 'addEventListener' | 'removeEventListener'>;
    interval?: number;
  },
): () => void;

export function checkRelease(options: {
  version?: string;
  fetch?: typeof fetch;
  busy?: () => boolean;
  reload?: () => void;
  notify?: () => void;
}): Promise<void>;

export function watchRelease(): () => void;
