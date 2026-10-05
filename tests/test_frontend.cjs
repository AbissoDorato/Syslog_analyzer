/* Logic/DOM-contract checks without a browser; no external packages. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const {execFileSync} = require("node:child_process");
const path = require("node:path");
const root = path.resolve(__dirname, "..");
const python = process.env.PYTHON || (process.platform === "win32" ? "py" : "python3");
const args = process.platform === "win32" && !process.env.PYTHON ? ["-3"] : [];
const input = fs.readFileSync(path.join(root,"examples/demo.csv"),"utf8") +
  '2026-10-05T11:00:00Z,__proto__,daemon,info,"<img src=x onerror=alert(1)>",worker,10.0.0.3\n';
const fixture = JSON.parse(execFileSync(python,[...args,"-c",
  "import sys,json; from analysis import analyze; print(json.dumps(analyze(sys.stdin.read(),'demo.csv')))"],
  {cwd:root,input,encoding:"utf8",maxBuffer:4*1024*1024}));
const unescape = text => text.replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&amp;/g,"&");
class Element {
  constructor(id,tag) { this.id=id;this.tag=tag;this.listeners={};this.value="";this._html="";this.hidden=false;this.textContent="";this.style={};this.classList={add(){},remove(){}}; }
  addEventListener(type,fn) {this.listeners[type]=fn;}
  querySelectorAll() {return [];}
  set innerHTML(html) {
    this._html=html;
    if(this.tag==="select") this.value=unescape(/<option value="([^"]*)"/.exec(html)?.[1] || "");
  }
  get innerHTML() {return this._html;}
  click() {this.listeners.click?.();}
  remove() {}
  focus() {}
  select() {}
}
const elements=new Map();
for(const match of fs.readFileSync(path.join(root,"index.html"),"utf8").matchAll(/<(\w+)[^>]*\bid="([^"]+)"[^>]*>/g)) {
  elements.set("#"+match[2],new Element(match[2],match[1]));
}
const downloads=[];
const context=vm.createContext({
  console,fixture,Intl,Map,Set,Date,Math,Number,String,JSON,Blob,AbortController,TextDecoder,Uint8Array,
  navigator:{clipboard:{writeText:async()=>{}}},
  setTimeout:fn=>fn(),
  URL:{createObjectURL:blob=>{downloads.push(blob);return "blob:test";},revokeObjectURL(){}},
  document:{querySelector:selector=>{assert(elements.has(selector),selector+" is missing from HTML");return elements.get(selector);},
    createElement:()=>new Element("link","a"),body:{append(){}}}
});
vm.runInContext(fs.readFileSync(path.join(root,"app.js"),"utf8"),context);
vm.runInContext("data=fixture;render();",context);
assert(elements.get("#suggestions").innerHTML.includes("80.0%"));
assert(elements.get("#temporalTree").innerHTML.includes("__proto__"));
assert(!elements.get("#temporalTree").innerHTML.includes("<img src=x"));
assert(elements.get("#temporalTree").innerHTML.includes("&lt;img"));
const ticket=elements.get("#ticket");
ticket.value+="\nNota dell'analista conservata.";
ticket.listeners.input();
elements.get("#causeSelect").value="updates";
elements.get("#causeSelect").listeners.change();
assert(ticket.value.includes("scelta manuale"));
assert(ticket.value.includes("Nota dell'analista conservata."));
const selection=elements.get("#incidentSelect");
const original=selection.value;
selection.value=fixture.incidents[1].id;
selection.listeners.change();
selection.value=original;
selection.listeners.change();
assert(ticket.value.includes("Nota dell'analista conservata."));
assert.equal(elements.get("#causeSelect").value,"updates");
elements.get("#downloadTicket").click();
elements.get("#downloadEvidence").click();
(async()=>{
  assert((await downloads[0].text()).includes("Nota dell'analista conservata."));
  const dossier=JSON.parse(await downloads[1].text());
  assert.equal(dossier.selected_cause,"updates");
  assert.equal(dossier.source.sha256,fixture.source.sha256);
  assert(dossier.ticket.includes("Nota dell'analista conservata."));
  console.log("Frontend: rendering, escaping, host speciali, scelta manuale, bozze e export verificati.");
})().catch(error=>{console.error(error);process.exitCode=1;});
