'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {sources,root,fixture}=require('./auth-fixture.cjs');
const {buildFlows,httpAuth}=require('../../deployment/docker/orce/viewer-runtime.cjs');

test('packaged runtime connects only the authenticated viewer route to the journey and preserves lifecycle',()=> {
  const flows=buildFlows(path.join(root,'flows')), ids=new Set(flows.map(n=>n.id));
  assert.ok(flows.some(n=>n.type==='http in' && n.url==='/lifecycle'));
  const route=flows.find(n=>n.type==='http in' && n.url==='/dev/ztd/api/journey');
  assert.deepEqual(route.wires,[['facis-native-identity-engine']]);
  assert.ok(!ids.has('interface-journey'));
  assert.equal(flows.find(n=>n.id==='facis-native-identity-engine').initialize,sources.standalone);
  for(const n of flows)for(const id of [...(n.links||[]),...(n.wires||[]).flat()])assert.ok(ids.has(id),'dangling link '+id);
  const image=fs.readFileSync(path.join(root,'deployment/docker/orce/Dockerfile'),'utf8');
  assert.match(image,/buildFlows\("\/opt\/ztd\/flows"\)/);
});

test('OIDC endpoints bypass Basic only on exact routes; lifecycle keeps Basic and fails closed',async()=> {
  const auth=httpAuth('deployer','hash',async(p,h)=>p==='private-password' && h==='hash');
  async function call(method,path,authorization) {
    let next=0;const res={set(){},sendStatus(status){this.status=status;}};
    await auth({method,path,headers:{authorization}},res,()=>next++);
    return {next,status:res.status};
  }
  assert.deepEqual(await call('GET','/dev/ztd/oidc/login'),{next:1,status:undefined});
  assert.deepEqual(await call('POST','/dev/ztd/api/journey'),{next:1,status:undefined});
  for(const p of ['/lifecycle','/dev/ztd/api/journey/','/dev/ztd/api/journey/../lifecycle','/dev/ztd/%61pi/journey']) {
    assert.deepEqual(await call('POST',p),{next:0,status:401});
  }
  assert.deepEqual(await call('GET','/dev/ztd/api/journey'),{next:0,status:401});
  assert.deepEqual(await call('POST','/lifecycle','Bearer anything'),{next:0,status:401});
  assert.deepEqual(await call('POST','/lifecycle','Basic '+Buffer.from('deployer:wrong').toString('base64')),{next:0,status:401});
  assert.deepEqual(await call('POST','/lifecycle','Basic '+Buffer.from('deployer:private-password').toString('base64')),{next:1,status:undefined});
});

test('packaged HTTP adapter keeps the authorization decision ID through the journey reply',async()=> {
  const flows=buildFlows(path.join(root,'flows'));
  const engine=flows.find(n=>n.id==='facis-native-identity-engine');
  assert.equal(engine.func,fs.readFileSync(path.join(root,'flows/demonstrator/identity-on-message.js'),'utf8'));
  const f=fixture(),s=f.session(),req=f.req('start');
  req.route={path:'/dev/ztd/api/journey'};req.method='POST';req.headers['content-type']='application/json';
  const native=new (require('node:events').EventEmitter)();let sent;
  await new Promise(resolve=> {
    new Function('msg','context','node','setTimeout','clearTimeout',engine.func)(
      {req,res:{_res:native}},{_facisAuth:f.a},{send(outputs){sent=outputs[1];},done(){resolve();}},setTimeout,clearTimeout);
  });
  native.emit('finish');
  assert.ok(sent._facisDecisionId);assert.equal(sent.req.facis.subject,s.subject);
  sent.payload={ok:true};
  const reply=new Function('msg',flows.find(n=>n.id==='facis-native-journey-reply').func)(sent);
  assert.equal(reply.headers['X-Request-ID'],sent._facisDecisionId);assert.equal(reply.statusCode,200);
});
