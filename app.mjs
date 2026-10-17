import {PUB,canonical,encode,sha,publicDescriptor,makeReceipt} from './protocol.mjs';
const $=id=>document.getElementById(id);
const DBNAME='srf-phone-custodian-v04';
function dbOpen(){return new Promise((resolve,reject)=>{const r=indexedDB.open(DBNAME,1);r.onupgradeneeded=()=>{r.result.createObjectStore('items')};r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});}
async function get(name){const db=await dbOpen();return new Promise((ok,no)=>{const tx=db.transaction('items','readonly');const r=tx.objectStore('items').get(name);r.onsuccess=()=>ok(r.result);r.onerror=()=>no(r.error);tx.oncomplete=()=>db.close();});}
async function putBatch(entries){const db=await dbOpen();return new Promise((ok,no)=>{const tx=db.transaction('items','readwrite');for(const [k,v] of entries)tx.objectStore('items').put(v,k);tx.oncomplete=()=>{db.close();ok();};tx.onerror=()=>{db.close();no(tx.error);};});}
function info(msg){$('status').textContent=msg;}
function download(text,name){const a=document.createElement('a');const url=URL.createObjectURL(new Blob([text],{type:'application/json;charset=utf-8'}));a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),15000);}
async function doInit(){
  if(await get('key'))throw Error('KEY_ALREADY_EXISTS_DO_NOT_REGENERATE');
  const keys=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const spki=await crypto.subtle.exportKey('spki',keys.publicKey);
  const publicObj=await publicDescriptor(spki);
  await putBatch([['key',keys.privateKey],['public',publicObj],['state',{sequence:0,head:'0'.repeat(64)}]]);
  $('pub').value=canonical(publicObj);info('鍵をスマートフォン内に生成しました。公開鍵指紋を別経路でOwnerに伝えてください。秘密鍵は送らないでください。');
}
async function exportPublic(){const p=await get('public');if(!p)throw Error('GENERATE_KEY_FIRST');$('pub').value=canonical(p);download(canonical(p)+'\n','SRF_PHONE_PUBLIC.json');info('公開鍵ファイル（秘密を含まない）を保存しました。指紋は声など別経路で照合してください。');}
async function sign(){
  const key=await get('key'),publicObj=await get('public'),state=await get('state');
  if(!key||!publicObj||!state)throw Error('NO_KEY_IN_THIS_BROWSER_OR_KEY_LOST');
  const f=$('cipher').files[0];if(!f)throw Error('SELECT_ENCRYPTED_TEST_FILE');
  if(f.size>1048576||f.size<1)throw Error('CIPHERTEXT_SIZE_BOUNDS');
  if(!$('consent').checked)throw Error('CONSENT_REQUIRED');
  const mode=$('cloud').checked?'CLOUD_UPLOAD_SELF_DECLARED':'PHONE_FILE_ONLY';
  const r=await makeReceipt(key,$('challenge').value.trim(),publicObj,await f.arrayBuffer(),state,mode);
  // Updating high-water mark before exposing receipt prevents routine replay after refresh.
  await putBatch([['state',{sequence:r.sequence,head:r.receipt_head}],['last_receipt',r.receipt]]);
  $('receipt').value=canonical(r.receipt)+'\n';info('署名成功。暗号文のサイズとSHAが一致。受領証を保存してOwnerに渡してください。クラウドコピーの実在・復元は別途未実証です。');
}
async function saveReceipt(){const r=await get('last_receipt');if(!r)throw Error('NO_SIGNED_RECEIPT');download(canonical(r)+'\n','SRF_PHONE_RECEIPT.json');}
async function refresh(){const p=await get('public'),s=await get('state'),r=await get('last_receipt');$('pub').value=p?canonical(p):'';$('receipt').value=r?canonical(r):'';$('state').textContent=s?`端末側 Sequence: ${s.sequence} / Head: ${s.head}`:'鍵未登録（ブラウザデータを削除すると鍵は失われます）';}
async function wrap(fn){try{await fn();await refresh();}catch(e){info('拒否: '+(e?.message||String(e)).slice(0,150));}}
if(!globalThis.isSecureContext||!crypto?.subtle||!indexedDB){info('HTTPS/安全なコンテキストまたはWebCrypto/IndexedDBがありません。処理を停止します。');for(const id of ['create','publicBtn','signBtn','receiptBtn'])$(id).disabled=true;}else{for(const [id,fn] of [['create',doInit],['publicBtn',exportPublic],['signBtn',sign],['receiptBtn',saveReceipt]])$(id).addEventListener('click',()=>wrap(fn));wrap(refresh);}
