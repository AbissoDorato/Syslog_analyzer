"use strict";
const $ = selector => document.querySelector(selector);
const fmt = value => new Intl.NumberFormat("it-IT", {maximumFractionDigits: 2}).format(value);
const esc = value => String(value ?? "").replace(/[&<>"']/g, c => ({
  "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
})[c]);
const time = value => (value || "senza timestamp").replace("T", " ").replace("Z", " UTC");
let data = null, lastFile = null, active = null, requestId = 0, controller = null;
let importReport = null, importSource = null;
const drafts = new Map();
const choices = new Map();

function error(message) {
  $("#alert").textContent = message;
  $("#alert").style.display = "block";
}
function table(headers, rows) {
  if (!rows.length) return '<div class="empty">Nessun dato disponibile</div>';
  return "<table><thead><tr>" + headers.map(h => "<th>" + esc(h) + "</th>").join("") +
    "</tr></thead><tbody>" + rows.map(r => "<tr>" + r.map(c => "<td>" + c + "</td>").join("") + "</tr>").join("") + "</tbody></table>";
}
function bars(node, rows) {
  if (!rows.length) { node.innerHTML = '<p class="hint">Nessun dato disponibile.</p>'; return; }
  const max = Math.max(...rows.map(r => r.count), 1);
  node.innerHTML = rows.map(r => '<div class="barrow"><span class="barname" title="' + esc(r.label || r.name) +
    '">' + esc(r.label || r.name) + '</span><div class="track"><div class="fill" style="width:' +
    (r.count / max * 100) + '%"></div></div><span class="num" title="' + esc(r.percent ?? "") + '%">' +
    fmt(r.count) + '</span></div><div class="hint">' + fmt(r.percent ?? 0) + "%</div>").join("");
}

function updateHistoryControls() {
  const enabled = $("#useHistory").checked;
  $("#threshold").disabled = !enabled;
  $("#methodHint").textContent = enabled ?
    "Storico: fino a 12 finestre precedenti dello stesso host nel file caricato, almeno 3. Premi Ricalcola per applicare le modifiche." :
    "Storico escluso: ogni finestra è valutata sul solo Min. eventi. Non dimostra uno spike rispetto al passato. Premi Ricalcola per applicare le modifiche.";
}

function renderImportReport(report) {
  importReport = report;
  $("#quality").hidden = false;
  $("#importStatus").textContent = ({
    ok:"Import riuscito", warning:"Import riuscito con segnalazioni",
    partial:"Import parziale", blocked:"Import bloccato", empty:"Nessun evento importato"
  })[report.status] || report.status;
  $("#importStatus").className = "import-status " + report.status;
  const s = report.summary;
  const number = n => n === null || n === undefined ? "—" : fmt(n);
  $("#qualitySummary").innerHTML = [
    ["Record esaminati",s.records_read,s.complete ? "lettura completata" : "lettura non completata"],
    ["Record analizzati",s.analyzed_records,"inclusi nei risultati"],
    ["Record esclusi",s.skipped_records,"struttura CSV incoerente"],
    ["Utilizzabili nelle finestre",s.usable_for_windows,"timestamp e host utilizzabili"]
  ].map(([label,n,note])=>'<div class="metric"><label>'+esc(label)+"</label><b>"+number(n)+"</b><span>"+esc(note)+"</span></div>").join("");
  const sep = {",":"virgola",";":"punto e virgola","\t":"tabulazione","|":"pipe"}[report.format.delimiter] || "non applicabile / non rilevato";
  $("#importFormat").textContent = "Formato: " + report.format.type + " · separatore: " + sep +
    " · codifica: " + (importSource?.encoding || "testo UTF-8 analizzato") + " · record con segnalazioni: " +
    number(s.records_with_issues) + ". Più segnalazioni possono riguardare lo stesso record." +
    (s.parsed_before_block ? " Prima del blocco erano stati letti " + s.parsed_before_block + " record: non sono stati analizzati." : "");
  const mapping = Object.entries(report.mapping || {});
  $("#columnMapping").innerHTML = "<p>Intestazioni: " + esc((report.columns || []).join(" | ") || "nessuna intestazione CSV") + "</p>" +
    table(["Campo","Colonna / alias prioritario"],mapping.map(([field,column])=>[esc(field),esc(column || "assente")]));
  renderDiagnosticIssues();
}

function renderDiagnosticIssues() {
  if (!importReport) return;
  const level = $("#diagnosticFilter").value;
  const labels = {error:"Errore",warning:"Avviso",info:"Informazione"};
  const issues = importReport.diagnostics.filter(d => !level || d.level === level);
  $("#qualityBody").innerHTML = issues.map(d => '<details class="import-issue '+esc(d.level)+'"' +
    (d.level === "error" ? " open" : "") + '><summary><b>'+esc(labels[d.level])+" · "+esc(d.title)+"</b> · "+fmt(d.count)+
    '</summary><p><b>Effetto:</b> '+esc(d.impact)+'</p><p><b>Come correggere:</b> '+esc(d.action)+
    '</p><div class="tablewrap">'+table(["Record","Righe fisiche","Colonna","Valore / dettaglio originale"],
      d.examples.map(x=>[x.record == null ? "File / intestazione" : "#"+fmt(x.record),
        x.line_start == null ? "—" : fmt(x.line_start)+(x.line_end !== x.line_start ? "–"+fmt(x.line_end) : ""),
        esc(x.column || "struttura del file"),'<span class="event-text">'+esc(x.value || "(vuoto)")+"</span>"]))+
    '</div><p class="hint">Esempi '+d.examples.length+" su "+d.count+" segnalazioni; valori mostrati fino a 240 caratteri.</p></details>").join("") ||
    '<p class="hint">Nessuna segnalazione '+(level ? "per questo filtro." : "di importazione.")+"</p>";
}

function clientImportFailure(code, title, detail, action) {
  renderImportReport({status:"blocked",format:{type:"file",delimiter:null},columns:[],mapping:{},
    counts:{[code]:1},summary:{records_read:null,analyzed_records:0,skipped_records:null,
      usable_for_windows:0,records_with_issues:0,complete:false},
    diagnostics:[{code,level:"error",title,impact:detail,action,count:1,
      examples:[{record:null,line_start:null,line_end:null,column:"file",value:importSource?.filename || ""}]}]});
  error(title + ". " + action);
  $("#fileline").textContent = "Import bloccato: " + (importSource?.filename || "");
}

async function loadFile(file) {
  controller?.abort();
  const id = ++requestId;
  controller = new AbortController();
  $("#alert").style.display = "none";
  $("#results").hidden = true;
  $("#quality").hidden = true;
  $("#diagnosticFilter").value = "";
  $("#reanalyze").disabled = true;
  importReport = null;
  importSource = {filename:file.name,bytes:file.size};
  active = null;
  data = null;
  drafts.clear();
  choices.clear();
  if (file.size > 30 * 1024 * 1024) {
    clientImportFailure("file_size","Il file supera 30 MB","Nessun record è stato letto.","Suddividi l'export in file più piccoli."); return;
  }
  if (!/\.(csv|txt|log)$/i.test(file.name)) {
    clientImportFailure("file_type","Formato non supportato","Nessun record è stato letto.","Esporta un CSV, TXT o LOG; un file XLSX non è un CSV."); return;
  }
  lastFile = file;
  $("#reanalyze").disabled = true;
  $("#fileline").textContent = "Analisi locale di " + file.name + "…";
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (id !== requestId) return;
    const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? "utf-16le" :
      bytes[0] === 0xfe && bytes[1] === 0xff ? "utf-16be" : "utf-8";
    importSource.encoding = encoding;
    let content;
    try { content = new TextDecoder(encoding, {fatal:true}).decode(bytes); }
    catch {
      clientImportFailure("encoding","Codifica del file non riconosciuta","Il testo non può essere decodificato senza perdere caratteri.",
        "Esporta il file in UTF-8 o UTF-16 con BOM.");
      $("#fileline").textContent = "Import bloccato durante la lettura del file.";
      return;
    }
    if (id !== requestId) return;
    const response = await fetch("/api/analyze", {
      method:"POST", signal:controller.signal, headers:{"Content-Type":"application/json"},
      body:JSON.stringify({filename:file.name, content, window:Number($("#window").value),
        threshold:Number($("#threshold").value), min_events:Number($("#minEvents").value),
        naive_offset:$("#offset").value.trim(), date_order:$("#dateOrder").value,
        use_history:$("#useHistory").checked,
        delimiter:$("#delimiter").value === "tab" ? "\t" : $("#delimiter").value})
    });
    const result = await response.json();
    if (id !== requestId) return;
    if (!response.ok) {
      if (result.quality) renderImportReport(result.quality);
      throw new Error(result.error || "Analisi non riuscita");
    }
    data = result;
    render();
    $("#fileline").textContent = file.name + " · " + fmt(data.total) + " eventi · catalogo " + data.catalog_version;
    $("#results").hidden = false;
  } catch (e) {
    if (e.name !== "AbortError" && id === requestId) {
      error(e.message);
      $("#fileline").textContent = "Analisi non completata.";
    }
  } finally {
    if (id === requestId) $("#reanalyze").disabled = false;
  }
}

function render() {
  $("#total").textContent = fmt(data.total);
  $("#processCount").textContent = fmt(data.process_count);
  $("#spikeCount").textContent = fmt(data.flagged_window_count);
  $("#spikeLabel").textContent = data.parameters.use_history ? "Finestre con spike" : "Finestre a soglia assoluta";
  $("#spikeHint").textContent = data.parameters.use_history ? "confronto con lo storico" : "storico escluso";
  $("#timed").textContent = (data.total ? fmt(100 * data.with_timestamp / data.total) : "0") + "%";
  renderImportReport(data.quality);
  $("#analysisNotes").textContent = (data.analysis_warnings || []).join(" ");
  $("#hostFilter").innerHTML = '<option value="">Tutti gli host</option>' +
    [...new Set(data.incidents.map(i => i.host))].map(host => '<option value="' + esc(host) + '">' + esc(host) + "</option>").join("");
  $("#incidentCount").textContent = fmt(data.incidents.length) + " / " + fmt(data.incident_count) + " finestre";
  chooseHost();
  drawChart();
  renderProcesses();
  $("#messageTableWrap").innerHTML = messageTable(data.messages);
  for (const [id, values] of [["severityList",data.severities],["hostList",data.hosts],["facilityList",data.facilities],["hostIpList",data.host_ips]]) {
    bars($("#" + id), values);
  }
  renderCorrelations();
  renderTree();
}

function chooseHost() {
  const host = $("#hostFilter").value;
  const rows = data.incidents.filter(i => !host || i.host === host);
  $("#incidentSelect").innerHTML = rows.map(i => '<option value="' + esc(i.id) + '">' + esc(
    time(i.time) + " · " + i.host + " · " + i.count + " eventi · " + i.kind) + "</option>").join("");
  $("#incidentEmpty").hidden = rows.length > 0;
  $("#incidentBody").hidden = !rows.length;
  $("#incidentSelect").disabled = !rows.length;
  if (rows.length) selectIncident();
}

function selectIncident() {
  active = data.incidents.find(i => i.id === $("#incidentSelect").value);
  if (!active) return;
  $("#ticketStatus").textContent = "";
  const ratio = active.ratio === null ? "rapporto non disponibile" : fmt(active.ratio) + "× rispetto alla baseline host";
  const reference = active.use_history ?
    ratio + "<br>Baseline host: " + fmt(active.baseline) + " eventi su " + active.baseline_windows +
      " finestre precedenti. Soglia host: " + fmt(active.cutoff) + " eventi." +
      (active.baseline_windows < 3 ? "<br>Storico insufficiente per dimostrare uno spike." : "") +
      "<br>Gli intervalli senza log valgono zero: verificare la continuità della raccolta." :
    "Storico escluso: soglia assoluta di " + fmt(active.cutoff) + " eventi. Nessun confronto con il passato; non dimostra uno spike relativo.";
  $("#incidentSummary").innerHTML = "<b>" + esc(active.host) + "</b> · " + esc(time(active.time)) + " → " + esc(time(active.end)) +
    "<br><b>" + fmt(active.count) + " eventi</b> · " + esc(active.kind) + "<br>" + reference;
  bars($("#categoryList"), active.categories);
  $("#contributorList").innerHTML = table(["Processo","Eventi","Quota",active.use_history ? "Baseline / anomalia" : "Soglia assoluta"], active.processes.slice(0,30).map(p => [
    esc(p.name), fmt(p.count), fmt(p.percent) + "%", active.use_history ?
      fmt(p.baseline) + (p.detected ? " · spike" : "") : fmt(p.cutoff) + (p.flagged ? " · raggiunta" : "")
  ])) + (active.processes.length > 30 ? '<p class="hint">Mostrati i primi 30 processi; elenco completo nel dossier JSON.</p>' : "");
  $("#suggestions").innerHTML = "<h4>Possibili cause dal catalogo locale</h4>" + (active.suggestions.length ?
    active.suggestions.map(s => '<article class="suggestion"><h4>' + esc(s.title) + '</h4><span class="badge">' + esc(s.kind) +
      '</span><span class="badge">' + esc(s.support) + "</span><p>" + esc(s.reason) + "</p>" +
      (s.delta_pp !== null ? '<p class="hint">Prima: ' + fmt(s.baseline_percent) + "%; variazione " +
        (s.delta_pp >= 0 ? "+" : "") + fmt(s.delta_pp) + " punti percentuali.</p>" : '<p class="hint">' +
          (active.use_history ? "Nessun evento precedente per confrontare la composizione." : "Confronto storico disattivato; quota riferita solo alla finestra selezionata.") + "</p>") +
      "<ul>" + s.checks.map(check => "<li>" + esc(check) + "</li>").join("") + "</ul>" +
      s.mitre_refs.map(ref => '<p>Riferimento MITRE da validare: <a href="' + esc(ref.url) + '" target="_blank" rel="noopener noreferrer">' +
        esc(ref.id + " · " + ref.name) + "</a><br><span class=\"hint\">" + esc(ref.condition) + "</span></p>").join("") +
      '<p class="hint">Record di supporto: ' + s.evidence_rows.map(fmt).join(", ") + ".</p></article>").join("") :
      '<p class="notice">Nessuna regola supera le soglie del catalogo. La causa resta da determinare.</p>');
  const net = active.network;
  $("#incidentContext").innerHTML = messageTable(active.messages) +
    table(["Facility","Eventi","Quota"], active.facilities.map(x => [esc(x.name),fmt(x.count),fmt(x.percent)+"%"])) +
    table(["Livello","Eventi","Quota"], active.severities.map(x => [esc(x.name),fmt(x.count),fmt(x.percent)+"%"])) +
    "<p>Eventi con endpoint espliciti: " + fmt(net.with_endpoints) + ". Destinazioni distinte: " +
    fmt(net.distinct_destinations) + "; porte distinte: " + fmt(net.distinct_ports) + ".</p>" +
    table(["Direzione ricavabile","Eventi","% degli eventi con endpoint"], net.directions.map(x => [esc(
      {outbound:"Uscita",inbound:"Ingresso",unknown:"Non determinabile"}[x.name]),fmt(x.count),fmt(x.percent)+"%"])) +
    table(["IP sorgente (esplicito)","Eventi"], net.sources.map(x=>[esc(x.name),fmt(x.count)])) +
    table(["IP destinazione (esplicito)","Eventi"], net.destinations.map(x=>[esc(x.name),fmt(x.count)]));
  $("#sequences").innerHTML = active.sequences.length ? "<h4>Sequenze da verificare</h4>" + active.sequences.map(s =>
    '<p class="notice"><b>' + esc(s.label) + "</b> · " + esc(s.source) + " · " + esc(s.user) + " · " +
    s.failures + " fallimenti<br>" + esc(s.note) + "<br>Record: " + s.rows.map(fmt).join(", ") + "</p>").join("") : "";
  $("#evidence").innerHTML = '<p class="hint">Campione di ' + active.evidence.length + "/" + active.count +
    " eventi. Testi fino a 2000 caratteri; riferimenti a record e riga finale nel file.</p><div class=\"tablewrap\">" +
    evidenceTable(active.evidence) + "</div>";
  const suggested = new Set(active.suggestions.map(s => s.id));
  $("#causeSelect").innerHTML = data.cause_catalog.map(c => '<option value="' + esc(c.id) + '">' +
    esc((suggested.has(c.id) ? "Suggerita: " : "") + c.title) + "</option>").join("");
  $("#causeSelect").value = choices.get(active.id) || "unknown";
  $("#ticket").value = drafts.get(active.id) || active.ticket;
  updateCause();
}

function updateCause() {
  if (!active) return;
  const cause = data.cause_catalog.find(c => c.id === $("#causeSelect").value);
  if (!cause) return;
  choices.set(active.id, cause.id);
  const suggested = active.suggestions.some(s => s.id === cause.id);
  const status = cause.id === "unknown" ? "da determinare" :
    suggested ? "ipotesi suggerita dalla regola, da verificare" : "scelta manuale, soglie della regola non soddisfatte";
  $("#causeNote").textContent = status + ". " + cause.checks.join(" ");
  const line = "Causa selezionata: " + cause.title + " (" + status + ")";
  const ticket = $("#ticket").value;
  $("#ticket").value = /^Causa selezionata:.*$/m.test(ticket) ?
    ticket.replace(/^Causa selezionata:.*$/m, () => line) : line + "\n\n" + ticket;
  drafts.set(active.id, $("#ticket").value);
}

function evidenceTable(events) {
  return table(["Record / UTC","Processo · facility · livello","Messaggio originale"], events.map(e => [
    "#" + fmt(e.row) + " (riga " + fmt(e.line) + ")<br>" + esc(time(e.time)),
    esc(e.process) + (e.pid ? " [" + esc(e.pid) + "]" : "") + "<br>" + esc(e.facility) + " · " + esc(e.severity),
    '<div class="event-text">' + esc(e.raw) + (e.text_truncated ? " … [testo troncato]" : "") + "</div>"
  ]));
}
function messageTable(rows) {
  return table(["Messaggio / modello","Eventi"], rows.map(m => [
    '<span class="mono">' + esc(m.message) + "</span>", fmt(m.count) + (m.percent !== undefined ? " · " + fmt(m.percent) + "%" : "")
  ]));
}
function renderProcesses() {
  if (!data) return;
  const query = $("#procSearch").value.toLowerCase();
  $("#procTableWrap").innerHTML = table(["Processo","Eventi","Quota"], data.processes.filter(p => p.name.toLowerCase().includes(query)).map(p => [
    '<button class="procbtn" data-proc="' + esc(p.name) + '">' + esc(p.name) + "</button>", fmt(p.count), fmt(p.percent) + "%"
  ]));
  $("#procTableWrap").querySelectorAll("[data-proc]").forEach(button => button.addEventListener("click", () => {
    const proc = data.processes.find(p => p.name === button.dataset.proc);
    $("#messageTableWrap").innerHTML = "<p>Messaggi di " + esc(proc.name) + " nell'intero file</p>" + messageTable(proc.messages);
  }));
}
function renderCorrelations() {
  const c = data.correlations, rows = [];
  for (const [key,label] of [["process_facility","Facility"],["process_severity","Livello"],["process_host_ip","IP"]]) {
    for (const item of c[key]) rows.push([esc(item.host), esc(item.process + " → " + item.value),label,fmt(item.count),fmt(item.process_share)+"%"]);
  }
  for (const item of c.process_cooccurrence) rows.push([
    esc(item.host),esc(item.first+" + "+item.second),"Finestre condivise",fmt(item.shared_windows),"Jaccard "+fmt(item.jaccard)
  ]);
  $("#correlationTableWrap").innerHTML = table(["Host","Elementi","Relazione","Eventi / finestre","Quota / indice"], rows);
}
function renderTree() {
  if (!data) return;
  const query = $("#treeSearch").value.toLowerCase();
  const groups = new Map();
  for (const item of data.temporal_tree) {
    if (!(item.host + " " + item.process + " " + item.target).toLowerCase().includes(query)) continue;
    const key = item.host === "unknown" ? item.host_ip : item.host;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(item);
  }
  $("#treeCaption").textContent = data.temporal_tree.length + "/" + data.temporal_tree_total + " osservazioni";
  $("#temporalTree").innerHTML = [...groups.entries()].map(([host, items]) => '<details open class="treehost"><summary><b>' +
    esc(host) + "</b> · " + items.length + "</summary>" + items.map(s => '<details class="treebranch"><summary><span class="mono">' +
      esc(time(s.time)) + "</span> · <b>" + esc(s.target) + "</b> · " + esc(s.status) +
      '</summary><p class="hint">Registrato da ' + esc(s.process) + (s.pid ? " PID " + esc(s.pid) : "") +
      ". Eventi successivi per nome/PID compatibile: " + s.process_events.length + "/" + s.process_events_total +
      '.</p><p class="event-text">' + esc(s.raw) + '</p><div class="tablewrap">' + evidenceTable(s.process_events) +
      '</div><details><summary>Eventi vicini di altri processi (' + s.nearby_events.length + ")</summary>" +
      (s.nearby_scan_limited ? '<p class="hint">Ricerca vicinanze limitata a 2000 record.</p>' : "") +
      s.nearby_events.map(e => '<p class="event-text"><b>' + esc(e.process) + "</b> · " + (e.delta_seconds >= 0 ? "+" : "") +
        e.delta_seconds + " s · record " + e.row + " · " + esc(e.relation) + "<br>" + esc(e.raw) + "</p>").join("") +
      "</details></details>").join("") + "</details>").join("") || '<p class="hint">Nessuna osservazione con host, processo e timestamp utilizzabili per questo filtro.</p>';
}

function drawChart() {
  const points = data.chart;
  $("#chart").hidden = !points.length;
  $("#chartEmpty").hidden = !!points.length;
  if (!points.length) { $("#chartCaption").textContent = ""; return; }
  const max = Math.max(...points.map(p => p.count), 1);
  const width=1000, height=220, left=55, top=10, plotHeight=175, step=(width-left-10)/points.length;
  const peakTimes = data.incidents.filter(i => i.flagged).map(i=>Date.parse(i.time));
  let svg = "";
  for (let tick=0;tick<=4;tick++) {
    const y=top+plotHeight*tick/4;
    svg += '<line class="gridline" x1="'+left+'" y1="'+y+'" x2="990" y2="'+y+'"/><text x="45" y="'+(y+4)+'" text-anchor="end">'+fmt(Math.round(max*(4-tick)/4))+"</text>";
  }
  points.forEach((point,i) => {
    const t=Date.parse(point.time), hot=peakTimes.some(peak => peak>=t && peak<t+data.chart_seconds*1000);
    const x=left+i*step, h=point.count/max*plotHeight;
    svg += '<rect class="bar'+(hot?" spike":"")+'" x="'+x+'" y="'+(top+plotHeight-h)+'" width="'+Math.max(.5,step*.8)+'" height="'+h+'"><title>'+
      esc(time(point.time))+" · "+fmt(point.count)+" eventi</title></rect>";
    if(i % Math.max(1,Math.ceil(points.length/8)) === 0) svg += '<text x="'+x+'" y="'+height+'">'+esc(point.time.slice(5,16).replace("T"," "))+"</text>";
  });
  $("#chart").innerHTML=svg;
  $("#chartCaption").textContent=fmt(data.chart_seconds/60)+" min per barra · tutti gli host · UTC";
}
function download(text, name, type) {
  const url=URL.createObjectURL(new Blob([text], {type}));
  const link=document.createElement("a");
  link.href=url; link.download=name; document.body.append(link); link.click(); link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
$("#choose").addEventListener("click",()=>$("#file").click());
$("#file").addEventListener("change",event=>event.target.files[0] && loadFile(event.target.files[0]));
$("#reanalyze").addEventListener("click",()=>lastFile && loadFile(lastFile));
$("#useHistory").addEventListener("change",updateHistoryControls);
$("#diagnosticFilter").addEventListener("change",renderDiagnosticIssues);
$("#downloadImport").addEventListener("click",()=>{
  if(importReport) download(JSON.stringify({source:importSource,quality:importReport},null,2),
    "diagnosi-import.json","application/json;charset=utf-8");
});
for(const name of ["dragenter","dragover"]) $("#drop").addEventListener(name,event=>{event.preventDefault();$("#drop").classList.add("drag");});
for(const name of ["dragleave","drop"]) $("#drop").addEventListener(name,event=>{event.preventDefault();$("#drop").classList.remove("drag");});
$("#drop").addEventListener("drop",event=>event.dataTransfer.files[0] && loadFile(event.dataTransfer.files[0]));
$("#hostFilter").addEventListener("change",chooseHost);
$("#incidentSelect").addEventListener("change",selectIncident);
$("#causeSelect").addEventListener("change",updateCause);
$("#ticket").addEventListener("input",()=>{if(active) drafts.set(active.id,$("#ticket").value);});
$("#procSearch").addEventListener("input",renderProcesses);
$("#treeSearch").addEventListener("input",renderTree);
$("#copyTicket").addEventListener("click",async()=>{
  if(!active) return;
  try { await navigator.clipboard.writeText($("#ticket").value); $("#ticketStatus").textContent="Ticket copiato."; }
  catch { $("#ticket").focus(); $("#ticket").select(); $("#ticketStatus").textContent="Testo selezionato: premi Ctrl+C per copiarlo."; }
});
$("#downloadTicket").addEventListener("click",()=>{
  if(active) download($("#ticket").value,"ticket-"+active.id+".md","text/markdown;charset=utf-8");
});
$("#downloadEvidence").addEventListener("click",()=>{
  if(!active) return;
  download(JSON.stringify({source:data.source,parameters:data.parameters,quality:data.quality,catalog_version:data.catalog_version,
    selected_cause:choices.get(active.id),...active,ticket:$("#ticket").value},null,2),
    "dossier-"+active.id+".json","application/json;charset=utf-8");
});
updateHistoryControls();
