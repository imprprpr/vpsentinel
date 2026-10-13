const assert = require('node:assert/strict');
const fs = require('node:fs');
const {JSDOM} = require('jsdom');
const acorn = require('acorn');
const source = fs.readFileSync('static/index.html','utf8');
const dom = new JSDOM(source, {url:'https://sentinel.test',runScripts:'outside-only'});
const w = dom.window;
w.eval(fs.readFileSync('static/vendor/purify.min.js','utf8'));
const script = [...source.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m=>m[1]).join('\n');
const tree = acorn.parse(script,{ecmaVersion:'latest'});
for (const name of ['escapeHtml','safeHtml','loadCustomNodes','loadTransits']) {
 const fn=tree.body.find(n=>n.type==='FunctionDeclaration'&&n.id.name===name);
 assert.ok(fn,name);
 w.eval(script.slice(fn.start,fn.end));
}
const handler=tree.body.find(n=>n.type==='ExpressionStatement'&&script.slice(n.start,n.end).startsWith("document.addEventListener('click'"));
w.eval(script.slice(handler.start,handler.end));
let selected=null;
w.toggleCustomNode=(id,enabled)=>selected={id,enabled};
w.deleteCustomNode=()=>{};
const payload=`<button data-action="deleteMeshNode" data-id="victim">malicious</button><img src=x onerror="window.__executed=1"><svg onload="window.__executed=2"></svg>`;
w.fetch=async()=>({json:async()=>[{name:payload,id:"a'\"/><img onerror=alert(1)>",type:'trojan',server:payload,port:443,enabled:true}]});
(async()=>{
 await w.loadCustomNodes();
 const container=w.document.getElementById('custom-nodes-container');
 assert.equal(container.querySelectorAll('[onerror],[onload],[onclick],svg,script').length,0);
 assert.equal(container.querySelectorAll('[data-action="deleteMeshNode"]').length,0);
 assert.equal(w.__executed,undefined);
 const button=container.querySelector('[data-action="toggleCustomNode"]');
 assert.ok(button,'action button preserved');
 button.click();
 assert.deepEqual(selected,{id:"a'\"/><img onerror=alert(1)>",enabled:false});
 const clean=w.safeHtml('<a href="javascript:alert(1)" onclick="alert(1)">unsafe</a><script>alert(1)</script>');
 assert.ok(!clean.includes('javascript:')&&!clean.includes('onclick')&&!clean.includes('<script'));
 assert.ok(!source.includes('/ws/live${tokenParam}') || source.includes("const tokenParam = ''"));
 const assignments=[];
 function walk(n){if(!n||typeof n!=='object')return; if(n.type==='AssignmentExpression'&&n.left.type==='MemberExpression'&&n.left.property.name==='innerHTML')assignments.push(n);for(const v of Object.values(n)){if(Array.isArray(v))v.forEach(walk);else if(v&&typeof v==='object')walk(v);}}
 walk(tree);
 assert.ok(assignments.length>15);
 assert.ok(assignments.every(n=>n.right.type==='CallExpression'&&n.right.callee.name==='safeHtml'));
 console.log(`Frontend security checks passed (${assignments.length} guarded HTML assignments; malicious name/id and action click tested).`);
 dom.window.close();
})().catch(error=>{console.error(error);process.exitCode=1;dom.window.close();});
