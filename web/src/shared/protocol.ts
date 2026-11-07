// Messages between the loader in the host page and the frame on the captcha host.

export interface HostMessage {
  sc: 1;
  type: 'start' | 'finish' | 'reset' | 'dismiss';
  action?: string;
  cdata?: string;
  behaviour?: unknown;
  artefacts?: string[];
  // True when the visitor caused this, by sending the form or through execute().
  // Only then may a task open on its own.
  user?: boolean;
}

export interface FrameMessage {
  sc: 1;
  type: 'ready' | 'collect' | 'pow-ready' | 'token' | 'error' | 'overlay';
  token?: string;
  ttl?: number;
  code?: string;
  on?: boolean;
  dismissed?: boolean;
  page?: string;
  pageSri?: string;
}
