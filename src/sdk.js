export class PagClient {
  constructor({ baseUrl='http://127.0.0.1:8787', token, fetchImpl=globalThis.fetch }={}) {
    if (!token) throw new Error('PAG actor token is required.');
    this.baseUrl=baseUrl.replace(/\/$/,''); this.token=token; this.fetch=fetchImpl;
  }
  async request(path, options={}) {
    const res=await this.fetch(`${this.baseUrl}${path}`,{...options,headers:{authorization:`Bearer ${this.token}`,'content-type':'application/json',...(options.headers||{})}});
    const data=await res.json().catch(()=>({})); if(!res.ok){const e=new Error(data.error||`PAG HTTP ${res.status}`);e.status=res.status;throw e;} return data;
  }
  createIntent(capability,args={}, { idempotencyKey }={}) {
    return this.request('/v1/intents',{method:'POST',headers:idempotencyKey?{'x-pag-idempotency-key':idempotencyKey}:{},body:JSON.stringify({capability,args})});
  }
  createIntentForConnection(capability, connectionId, args={}, options={}) {
    if (!connectionId) throw new Error('connectionId is required.');
    return this.createIntent(capability,{...args,connectionId},options);
  }
  getIntent(id) { return this.request(`/v1/intents/${encodeURIComponent(id)}`); }
}
