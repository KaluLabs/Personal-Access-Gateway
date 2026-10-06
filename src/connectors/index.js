function requireText(value, label='text', max=10000) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} must be a non-empty string.`);
  if (value.length > max) throw new Error(`${label} is too long.`);
  return value;
}

function requireObject(value, label='value') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  return value;
}

function requireEnum(value, allowed, label) {
  if (typeof value !== 'string' || !allowed.includes(value)) throw new Error(`${label} is invalid.`);
  return value;
}

function directActionAuthorizationReceipt(args) {
  const input=requireObject(args,'authorization args');
  const allowedKeys=new Set(['schemaVersion','invocationId','source','actorId','taskId','workspaceId','directCapability','directRisk','directArgs','createdAt']);
  for (const key of Object.keys(input)) if (!allowedKeys.has(key)) throw new Error(`Unsupported authorization field: ${key}.`);
  if (input.schemaVersion!==1) throw new Error('schemaVersion must be 1.');
  const invocationId=requireText(input.invocationId,'invocationId',160).trim();
  const actorId=requireText(input.actorId,'actorId',200).trim();
  const directCapability=requireText(input.directCapability,'directCapability',240).trim();
  const source=requireEnum(input.source,['user','core','agent','automation'],'source');
  const directRisk=requireEnum(input.directRisk,['A0','A1','A2','A3'],'directRisk');
  const directArgs=requireObject(input.directArgs,'directArgs');
  if (!Number.isSafeInteger(input.createdAt) || input.createdAt<0) throw new Error('createdAt must be a non-negative safe integer.');
  for (const optional of ['taskId','workspaceId']) {
    if (input[optional]!==undefined && input[optional]!==null) requireText(input[optional],optional,240);
  }
  return {
    mode:'authorization_receipt',
    authorized:true,
    schemaVersion:1,
    invocationId,
    source,
    actorId,
    taskId:input.taskId??null,
    workspaceId:input.workspaceId??null,
    directCapability,
    directRisk,
    directArgs,
    createdAt:input.createdAt
  };
}

export class ConnectorRegistry {
  constructor() {
    this.handlers = new Map();
    this.register('noop.test', { name:'noop', connectionType:null, execute: async ({args}) => ({ ok:true, echo:args }) });
    this.register('agent-dock.direct-action.authorize', {
      name:'agent-dock-authorization',
      connectionType:null,
      execute: async ({args}) => directActionAuthorizationReceipt(args)
    });
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
