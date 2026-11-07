// Messages between the loader in the host page and the frame on the captcha host.

export interface HostMessage {
  sc: 1;
  type: 'start' | 'finish' | 'reset';
  action?: string;
  cdata?: string;
  behaviour?: unknown;
  artefacts?: string[];
}

export interface FrameMessage {
  sc: 1;
  type: 'ready' | 'collect' | 'pow-ready' | 'token' | 'error' | 'overlay';
  token?: string;
  ttl?: number;
  code?: string;
  on?: boolean;
  page?: string;
  pageSri?: string;
}
