import { createHash, randomBytes } from 'node:crypto';
import { encryptSecret, decryptSecret } from './crypto.js';
import { getProvider, normalizeScopes, oauthScopesForProvider } from './providers.js';
import { json, nowIso, parseJson, randomId, sha256 } from './util.js';

function oauthError(message, statusCode=400) {
  const error=new Error(message);
  error.statusCode=statusCode;
  return error;
}
function b64urlSha256(value) {
  return createHash('sha256').update(value).digest('base64url');
}
function safeProviderError(data, fallback) {
  const message=data?.error_description || data?.error || fallback;
  return String(message).slice(0,500);
}
function expiryFrom(data) {
  const seconds=Number(data?.expires_in);
  return Number.isFinite(seconds) && seconds>0 ? new Date(Date.now()+seconds*1000).toISOString() : null;
}
function pickProfile(provider, profile) {
  const config=provider.oauth?.profile || {};
  const id=profile?.[config.idField];
  if(id===undefined || id===null || id==='') throw oauthError(`${provider.name} profile did not include a stable account identifier.`,502);
  let label=null;
  for(const field of config.labelFields||[]) {
    const value=profile?.[field];
    if(value!==undefined && value!==null && String(value).trim()) { label=String(value).trim(); break; }
  }
  const metadata={};
  for(const field of config.metadataFields||[]) {
    const value=profile?.[field];
    if(value!==undefined && value!==null) metadata[field]=value;
  }
  return { externalAccountId:String(id), accountLabel:label || `${provider.name} account`, metadata };
}

export class OAuthManager {
  constructor(db,key,vault,audit,{fetchImpl=globalThis.fetch,flowTtlMinutes=10}={}) {
    this.db=db;
    this.key=key;
    this.vault=vault;
    this.audit=audit;
    this.fetch=fetchImpl;
    this.flowTtlMinutes=Number(flowTtlMinutes)||10;
  }

  configuration(providerId) {
    const provider=getProvider(providerId);
    if(!provider?.oauth) return { supported:false, configured:false, missing:[] };
    const missing=[];
    const clientId=process.env[provider.oauth.clientIdEnv];
    const clientSecret=process.env[provider.oauth.clientSecretEnv];
    if(!clientId) missing.push(provider.oauth.clientIdEnv);
    if(!clientSecret) missing.push(provider.oauth.clientSecretEnv);
    return { supported:true, configured:missing.length===0, missing, clientIdPresent:!!clientId, clientSecretPresent:!!clientSecret };
  }

  _client(providerId) {
    const provider=getProvider(providerId);
    if(!provider?.oauth) throw oauthError(`Provider ${providerId} does not support OAuth.`,404);
    const status=this.configuration(providerId);
    if(!status.configured) throw oauthError(`${provider.name} OAuth is not configured. Missing: ${status.missing.join(', ')}.`,409);
    return {
      provider,
      clientId:process.env[provider.oauth.clientIdEnv],
      clientSecret:process.env[provider.oauth.clientSecretEnv],
    };
  }

  _cleanupExpired() {
    const now=nowIso();
    const expired=this.db.prepare(`SELECT id,provider FROM oauth_flows WHERE expires_at<=?`).all(now);
    for(const flow of expired) this.audit?.append('system','oauth.flow_expired',flow.id,{provider:flow.provider});
    this.db.prepare('DELETE FROM oauth_flows WHERE expires_at<=?').run(now);
  }

  start(providerId,{logicalScopes=null,redirectUri,connectionId=null}={}) {
    if(!redirectUri) throw oauthError('OAuth redirect URI is required.');
    const {provider,clientId}=this._client(providerId);
    const scopes=normalizeScopes(providerId,logicalScopes);
    const requiredOauthScopes=oauthScopesForProvider(providerId,scopes);
    const oauthScopes=[...new Set([...requiredOauthScopes,...(provider.oauth.extraScopes||[])])];
    const id=randomId('oaf_');
    const state=randomBytes(32).toString('base64url');
    const verifier=randomBytes(32).toString('base64url');
    const challenge=b64urlSha256(verifier);
    const encrypted=encryptSecret(this.key,verifier,`pag:v1:oauth-flow:${id}`);
    const created=nowIso();
    const expiresAt=new Date(Date.now()+this.flowTtlMinutes*60_000).toISOString();
    this._cleanupExpired();
    this.db.prepare(`INSERT INTO oauth_flows(id,provider,connection_id,state_hash,verifier_ciphertext,verifier_iv,verifier_tag,requested_scopes_json,redirect_uri,status,created_at,expires_at)
      VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?)`)
      .run(id,providerId,connectionId,sha256(state),encrypted.ciphertext,encrypted.iv,encrypted.tag,json(scopes),redirectUri,created,expiresAt);

    const url=new URL(provider.oauth.authorizationUrl);
    url.searchParams.set('client_id',clientId);
    url.searchParams.set('redirect_uri',redirectUri);
    url.searchParams.set('response_type','code');
    url.searchParams.set('state',state);
    url.searchParams.set('code_challenge',challenge);
    url.searchParams.set('code_challenge_method','S256');
    if(oauthScopes.length) url.searchParams.set('scope',oauthScopes.join(' '));
    for(const [key,value] of Object.entries(provider.oauth.authorizeParams||{})) url.searchParams.set(key,String(value));
    this.audit?.append('local-admin','oauth.flow_started',id,{provider:providerId,connectionId,logicalScopes:scopes,expiresAt});
    return { flowId:id, provider:providerId, authorizationUrl:url.toString(), expiresAt, logicalScopes:scopes };
  }

  async _tokenRequest(providerId,params) {
    const {provider,clientId,clientSecret}=this._client(providerId);
    const form=new URLSearchParams({...params,client_id:clientId,client_secret:clientSecret});
    const response=await this.fetch(provider.oauth.tokenUrl,{
      method:'POST',
      headers:{'content-type':'application/x-www-form-urlencoded','accept':'application/json',...(provider.oauth.tokenHeaders||{})},
      body:form,
    });
    let data={};
    try { data=await response.json(); } catch {}
    if(!response.ok || data.error) throw oauthError(safeProviderError(data,`${provider.name} token exchange failed (${response.status}).`),502);
    if(!data.access_token) throw oauthError(`${provider.name} token response did not include an access token.`,502);
    return data;
  }

  async _profile(providerId,accessToken) {
    const {provider}=this._client(providerId);
    const response=await this.fetch(provider.oauth.userInfoUrl,{
      headers:{authorization:`Bearer ${accessToken}`,accept:'application/json',...(provider.oauth.userInfoHeaders||{})},
    });
    let data={};
    try { data=await response.json(); } catch {}
    if(!response.ok) throw oauthError(safeProviderError(data,`${provider.name} profile request failed (${response.status}).`),502);
    return pickProfile(provider,data);
  }

  async complete(providerId,{state,code,error=null,errorDescription=null}={}) {
    if(!state) throw oauthError('OAuth state is missing.',400);
    this._cleanupExpired();
    const flow=this.db.prepare('SELECT * FROM oauth_flows WHERE state_hash=?').get(sha256(state));
    if(!flow || flow.provider!==providerId) throw oauthError('OAuth state is invalid or expired.',409);
    if(flow.status!=='pending') throw oauthError('OAuth flow has already been consumed.',409);
    const claimed=this.db.prepare(`UPDATE oauth_flows SET status='exchanging' WHERE id=? AND status='pending'`).run(flow.id);
    if(!claimed.changes) throw oauthError('OAuth flow has already been consumed.',409);
    if(error) {
      this.db.prepare('DELETE FROM oauth_flows WHERE id=?').run(flow.id);
      this.audit?.append('oauth','oauth.flow_denied',flow.id,{provider:providerId,error:String(error).slice(0,120)});
      throw oauthError(errorDescription ? String(errorDescription).slice(0,500) : `${providerId} authorization was denied.`,400);
    }
    if(!code) {
      this.db.prepare('DELETE FROM oauth_flows WHERE id=?').run(flow.id);
      throw oauthError('OAuth authorization code is missing.',400);
    }

    let vaultRef=null;
    try {
      const verifier=decryptSecret(this.key,{ciphertext:flow.verifier_ciphertext,iv:flow.verifier_iv,tag:flow.verifier_tag},`pag:v1:oauth-flow:${flow.id}`);
      const token=await this._tokenRequest(providerId,{
        grant_type:'authorization_code',
        code,
        redirect_uri:flow.redirect_uri,
        code_verifier:verifier,
      });
      const logicalScopes=parseJson(flow.requested_scopes_json,[]);
      const requiredOauthScopes=oauthScopesForProvider(providerId,logicalScopes);
      if(token.scope){
        const granted=new Set(String(token.scope).split(/[\s,]+/).map(x=>x.trim()).filter(Boolean));
        const missing=requiredOauthScopes.filter(scope=>!granted.has(scope));
        if(missing.length) throw oauthError(`${providerId} did not grant required OAuth scope(s): ${missing.join(', ')}.`,409);
      }
      const account=await this._profile(providerId,token.access_token);
      const bundle={
        access_token:token.access_token,
        refresh_token:token.refresh_token||null,
        token_type:token.token_type||'Bearer',
        scope:token.scope||null,
        id_token:token.id_token||null,
        expires_at:expiryFrom(token),
        refresh_token_expires_in:token.refresh_token_expires_in||null,
        obtained_at:nowIso(),
      };
      vaultRef=`oauth.${providerId}.${flow.id}`;
      this.vault.put(vaultRef,JSON.stringify(bundle),{
        connector:providerId,
        metadata:{kind:'oauth-token',provider:providerId,logicalScopes,expiresAt:bundle.expires_at},
      });
      this.db.prepare('DELETE FROM oauth_flows WHERE id=?').run(flow.id);
      this.audit?.append('oauth','oauth.flow_completed',flow.id,{provider:providerId,connectionId:flow.connection_id||null,externalAccountId:account.externalAccountId,logicalScopes});
      return { flowId:flow.id, provider:providerId, connectionId:flow.connection_id||null, logicalScopes, vaultRef, account };
    } catch(e) {
      this.db.prepare('DELETE FROM oauth_flows WHERE id=?').run(flow.id);
      this.audit?.append('oauth','oauth.flow_failed',flow.id,{provider:providerId,error:String(e.message||e).slice(0,500)});
      if(vaultRef) this.vault.delete(vaultRef);
      throw e;
    }
  }

  _bundle(connection) {
    if(!connection?.vault_ref) throw oauthError('OAuth credential is missing.',409);
    const raw=this.vault.get(connection.vault_ref);
    if(!raw) throw oauthError('OAuth credential is missing.',409);
    let bundle;
    try { bundle=JSON.parse(raw); } catch { throw oauthError('OAuth credential is invalid.',409); }
    if(!bundle?.access_token) throw oauthError('OAuth credential does not contain an access token.',409);
    return bundle;
  }

  credentialStatus(connection) {
    try {
      const bundle=this._bundle(connection);
      const expired=!!bundle.expires_at && new Date(bundle.expires_at).getTime()<=Date.now();
      return { configured:true, expired, refreshable:!!bundle.refresh_token, expiresAt:bundle.expires_at||null };
    } catch {
      return { configured:false, expired:false, refreshable:false, expiresAt:null };
    }
  }

  async accessToken(connection,{minValiditySeconds=60}={}) {
    if(connection?.auth_method!=='oauth') throw oauthError('Connection does not use OAuth.',409);
    let bundle=this._bundle(connection);
    const expiresMs=bundle.expires_at ? new Date(bundle.expires_at).getTime() : null;
    if(!expiresMs || expiresMs>Date.now()+Number(minValiditySeconds)*1000) return bundle.access_token;
    if(!bundle.refresh_token) throw oauthError('OAuth access token expired and no refresh token is available. Reconnect this account.',409);

    const token=await this._tokenRequest(connection.connector,{
      grant_type:'refresh_token',
      refresh_token:bundle.refresh_token,
    });
    bundle={
      ...bundle,
      access_token:token.access_token,
      refresh_token:token.refresh_token||bundle.refresh_token,
      token_type:token.token_type||bundle.token_type||'Bearer',
      scope:token.scope||bundle.scope||null,
      id_token:token.id_token||bundle.id_token||null,
      expires_at:expiryFrom(token),
      refresh_token_expires_in:token.refresh_token_expires_in||bundle.refresh_token_expires_in||null,
      obtained_at:nowIso(),
    };
    this.vault.put(connection.vault_ref,JSON.stringify(bundle),{
      connector:connection.connector,
      metadata:{kind:'oauth-token',provider:connection.connector,logicalScopes:connection.scopes||[],expiresAt:bundle.expires_at},
    });
    this.audit?.append('oauth','oauth.token_refreshed',connection.id,{provider:connection.connector,expiresAt:bundle.expires_at});
    return bundle.access_token;
  }

  async fetchUserInfo(connection) {
    const provider=getProvider(connection?.connector);
    if(!provider?.oauth) throw oauthError('Connection provider does not support OAuth.',409);
    const token=await this.accessToken(connection);
    const account=await this._profile(connection.connector,token);
    return { provider:connection.connector, id:account.externalAccountId, label:account.accountLabel, ...account.metadata };
  }
}
