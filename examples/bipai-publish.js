import { PagClient } from '../src/sdk.js';

const pag = new PagClient({ token: process.env.PAG_ACTOR_TOKEN });
const intent = await pag.createIntent('x.threads.create', {
  posts: [
    'Building in public update: the first post in an approved thread.',
    'Second post: PAG keeps the final account action behind an exact-payload approval.'
  ]
}, { idempotencyKey: `bipai:${process.env.CONTENT_HASH || 'demo'}` });

console.log(JSON.stringify(intent, null, 2));
