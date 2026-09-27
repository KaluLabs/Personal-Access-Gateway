import { PagClient } from '../src/sdk.js';

const pag = new PagClient({ token: process.env.PAG_ACTOR_TOKEN });
const connectionId = process.env.PAG_X_CONNECTION_ID;
if (!connectionId) throw new Error('PAG_X_CONNECTION_ID is required');

const intent = await pag.createIntentForConnection('x.threads.create', connectionId, {
  posts: [
    'Building in public update: the first post in an approved thread.',
    'Second post: PAG keeps the final account action behind an exact-payload approval.'
  ]
}, { idempotencyKey: `bipai:${process.env.CONTENT_HASH || 'demo'}` });

console.log(JSON.stringify(intent, null, 2));
