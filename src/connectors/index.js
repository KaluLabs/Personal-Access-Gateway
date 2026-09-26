function requireText(value, label='text', max=10000) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} must be a non-empty string.`);
  if (value.length > max) throw new Error(`${label} is too long.`);
  return value;
}

export class ConnectorRegistry {
  constructor() {
    this.handlers = new Map();
    this.register('noop.test', { name:'noop', connectionType:null, execute: async ({args}) => ({ ok:true, echo:args }) });
    this.register('x.threads.create', { name:'x-web-intent', connectionType:'x', execute: async ({args}) => {
      const posts = Array.isArray(args.posts) ? args.posts : [args.text];
      if (!posts.length) throw new Error('At least one post is required.');
      const handoffs = posts.map((p, index) => {
        const text = requireText(p, `posts[${index}]`, 25000);
        return { index, url:`https://x.com/intent/tweet?text=${encodeURIComponent(text)}`, text };
      });
      return { mode:'browser_handoff', autonomous:false, handoffs };
    }});
    this.register('linkedin.posts.create', { name:'linkedin-browser-handoff', connectionType:'linkedin', execute: async ({args}) => {
      const text = requireText(args.text, 'text', 30000);
      return { mode:'browser_handoff', autonomous:false, handoffs:[{ url:'https://www.linkedin.com/feed/', text, instruction:'Open LinkedIn, start a post, paste the approved text, and publish manually.' }] };
    }});
  }
  register(capability, handler) { this.handlers.set(capability, handler); }
  get(capability) { return this.handlers.get(capability) || null; }
  list() { return [...this.handlers.entries()].map(([capability,h])=>({capability,connector:h.name,connectionType:h.connectionType||null})); }
}
