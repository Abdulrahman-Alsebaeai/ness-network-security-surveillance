window.NESS_LAB = {
  topology:null,
  lab:null,
  nodeMap:{},
  busy:false,
  esc(v){return window.NESS?.escape?NESS.escape(v):String(v??'').replace(/[&<>"']/g,'')},
  async get(path){return window.NESS_API?NESS_API.get(path):(await fetch(path)).json()},
  async post(path,body={}){return window.NESS_API?NESS_API.post(path,body):(await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})).json()},
  iconText(kind){return ({pc:'PC',attacker:'TEST',switch:'SW',shield:'NESS',server:'WEB',database:'DB'})[kind]||'NET'},
  async refreshAll(){
    if(document.body.dataset.page!=='network-topology.html')return;
    try{
      const [st,tp,sc,rev]=await Promise.all([this.get('/api/lab/status'),this.get('/api/lab/topology'),this.get('/api/lab/scenarios'),this.get('/api/ui-revision')]);
      this.lab=st.lab||{}; this.topology=tp.topology||{nodes:[],links:[]}; this.renderStatus(st.backend||{}); this.renderTopology(); this.renderScenarios(sc.scenarios||[],sc.runs||[]); this.renderIntegration(rev||{});
    }catch(e){ NESS.toast(e.message||String(e),'danger'); }
  },
  renderIntegration(data){
    const t=data.tables||{}; const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=Number(v||0).toLocaleString();};
    set('labTotalIncidents',t.incidents?.count);set('labTotalAlerts',t.alerts?.count);set('labTotalEvidence',t.digital_evidence?.count);set('labTotalAI',t.ai_analysis?.count);set('labTotalINTS',t.ints_tracking?.count);set('labTotalLogs',t.system_logs?.count);set('labTotalFlows',t.network_flows?.count);set('labTotalRuns',t.lab_scenario_runs?.count);
  },
  renderStatus(backend){
    const l=this.lab||{}; const set=(id,v)=>{const el=document.getElementById(id);if(el)el.textContent=v??'—'};
    set('labState',l.running?'Running':(l.backendReady?'Stopped':'Setup Required'));
    set('labMode',l.mode||'Integrated cyber lab'); set('labSensorState',l.sensorState||'Unknown'); set('labLastPacket',l.lastPacketAt?`Last packet: ${l.lastPacketAt}`:(l.sensorMessage||'No packet yet'));
    set('labDevicesOnline',l.devicesOnline||0); set('labTrafficCounter',`${Number(l.packetsCaptured||0).toLocaleString()} packets • ${NESS_API?.formatBytes?NESS_API.formatBytes(l.bytesCaptured||0):(l.bytesCaptured||0)+' B'}`);
    set('labBackendText',backend.ready?`Integrated lab ready • no VM / WSL / Docker required`:(backend.error||l.sensorMessage||'Backend not ready'));
    const setup=document.getElementById('labSetupPanel'); if(setup)setup.style.display='none'; set('labSetupError',backend.error||'');
    const start=document.getElementById('labStartBtn');const stop=document.getElementById('labStopBtn'); if(start)start.disabled=this.busy||!!l.running||!backend.ready;if(stop)stop.disabled=this.busy||!l.running;
  },
  renderTopology(){
    const svg=document.getElementById('labTopologySvg'); const linksG=document.getElementById('labTopologyLinks'); const nodesG=document.getElementById('labTopologyNodes'); if(!svg||!linksG||!nodesG)return;
    const nodes=this.topology?.nodes||[]; const links=this.topology?.links||[]; this.nodeMap=Object.fromEntries(nodes.map(n=>[n.id,n]));
    linksG.innerHTML=links.map(l=>{const a=this.nodeMap[l.source],b=this.nodeMap[l.target];if(!a||!b)return'';const online=a.status==='Online'&&b.status==='Online';const mx=(Number(a.x)+Number(b.x))/2,my=(Number(a.y)+Number(b.y))/2;return `<g data-link="${this.esc(l.source)}:${this.esc(l.target)}"><line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" class="topology-link ${online?'':'offline'}"/><text x="${mx}" y="${my-8}" class="topology-link-label">${this.esc(l.label||'')}</text></g>`}).join('');
    nodesG.innerHTML=nodes.map(n=>{const status=(n.status||'Offline').toLowerCase();const w=n.kind==='shield'?180:152,h=n.kind==='shield'?106:94,x=Number(n.x)-w/2,y=Number(n.y)-h/2;return `<g class="topology-node ${status}" data-node-id="${this.esc(n.id)}" transform="translate(${x},${y})"><rect class="topology-node-card" width="${w}" height="${h}" rx="15"/><circle class="topology-node-icon-bg" cx="${w/2}" cy="27" r="19"/><text class="topology-node-icon" x="${w/2}" y="33" style="font-size:${n.kind==='shield'?'12':'10'}px">${this.esc(this.iconText(n.kind))}</text><text class="topology-node-title" x="${w/2}" y="60">${this.esc(n.label)}</text><text class="topology-node-subtitle" x="${w/2}" y="78">${this.esc(n.ip||'')}</text>${n.kind==='shield'?`<text class="topology-node-subtitle" x="${w/2}" y="94">Gateway + IDS Sensor</text>`:''}</g>`}).join('');
    [...nodesG.querySelectorAll('[data-node-id]')].forEach(el=>el.addEventListener('click',()=>this.inspectNode(el.dataset.nodeId)));
  },
  inspectNode(id){
    const n=this.nodeMap[id];const box=document.getElementById('labNodeInspector');if(!n||!box)return;
    const role=n.role||({client:'Employee workstation',attacker:'Controlled security test host',gateway:'NESS gateway and IDS sensor',web:'Training web server',db:'Training data service','sw-users':'Virtual users switch','sw-dmz':'Virtual DMZ switch','sw-data':'Virtual data switch'}[id]||'Network node');
    const segment=n.segment||({client:'Users',attacker:'Users',gateway:'All Segments',web:'DMZ',db:'Data','sw-users':'Users','sw-dmz':'DMZ','sw-data':'Data'}[id]||'—');
    const services=(n.services||[]).map(x=>`<span class="mini-chip">${this.esc(x)}</span>`).join(' ')||'—';
    box.innerHTML=`<div class="node-detail-grid"><div style="text-align:center;margin-bottom:8px"><div class="metric-icon icon-primary" style="margin:0 auto 10px"><i class="fa-solid ${id==='gateway'?'fa-shield-halved':id.startsWith('sw-')?'fa-network-wired':id==='db'?'fa-database':'fa-computer'}"></i></div><strong style="font-size:17px">${this.esc(n.label)}</strong><div style="margin-top:6px"><span class="node-status-badge ${(n.status||'Offline').toLowerCase()}">${this.esc(n.status)}</span></div></div><div class="node-detail-row"><span>Logical Address</span><strong>${this.esc(n.ip||'—')}</strong></div><div class="node-detail-row"><span>Role</span><strong>${this.esc(role)}</strong></div><div class="node-detail-row"><span>Segment</span><strong>${this.esc(segment)}</strong></div><div class="node-detail-row"><span>Services</span><strong>${services}</strong></div>${n.runtime?`<div class="node-detail-row"><span>Local Runtime</span><strong>${this.esc(n.runtime)}</strong></div>`:''}<div class="node-detail-row"><span>Implementation</span><strong>NESS integrated virtual device</strong></div></div>`;
  },
  renderScenarios(scenarios,runs){
    const grid=document.getElementById('labScenarioGrid'); if(grid){grid.innerHTML=scenarios.map(s=>{const security=s.category==='Security';const desc={ping_web:'Client performs a four-step connectivity test to the Web Server. Reachability uses real local sockets while the topology records logical echo traffic.',normal_http:'Client sends a real HTTP request to the integrated Web Server and NESS records the logical route.',send_message:'Client sends a real HTTP message to Web Server; Web Server stores it through a real local TCP connection to the DB service.',sql_injection:'Test host exploits the intentionally vulnerable lab login endpoint.',xss:'Test host sends a reflected XSS payload to the isolated training web app.',traversal:'Test host reads the disposable lab secret using a traversal flaw.',port_scan:'Test host probes a fixed set of TCP ports on the lab web server.',auth_burst:'Test host sends repeated failed logins to trigger rate detection.',icmp_burst:'Test host generates a bounded ICMP burst inside the lab.',host_sweep:'Test host probes a bounded set of DMZ addresses.'}[s.key]||'';return `<div class="scenario-card ${security?'security':'normal'}"><strong>${this.esc(s.name)}</strong><p>${this.esc(desc)}</p><div><span class="badge ${security?'badge-warning':'badge-active'}">${this.esc(s.category)}</span></div><button class="button ${security?'button-secondary':'button-primary'} button-small" ${this.lab?.running?'':'disabled'} onclick="NESS_LAB.runScenario('${this.esc(s.key)}',this)"><i class="fa-solid fa-play"></i> Run</button></div>`}).join('')}
    const tb=document.getElementById('labScenarioHistory');if(tb){tb.innerHTML=(runs||[]).map(r=>`<tr><td>${this.esc(r.started_at||'—')}</td><td><strong>${this.esc(r.scenario_name)}</strong></td><td>${r.category==='Security'?'<span class="badge badge-warning">Security</span>':'<span class="badge badge-active">Normal</span>'}</td><td><code>${this.esc(r.source_ip||'—')}</code></td><td><code>${this.esc(r.target_ip||'—')}</code></td><td>${window.NESS_DATA?.statusBadge?NESS_DATA.statusBadge(r.status):this.esc(r.status)}</td><td>${r.incident_code?`<a href="incident-details.html?id=${encodeURIComponent(r.incident_id)}"><strong>${this.esc(r.incident_code)}</strong></a>`:'—'}</td><td style="max-width:340px"><small>${this.esc((r.result_summary||'').slice(0,260))}</small></td></tr>`).join('')||'<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:24px">No scenario runs yet.</td></tr>'}
  },
  async action(kind){
    if(this.busy)return;this.busy=true;try{NESS.toast(`${kind[0].toUpperCase()+kind.slice(1)} cyber range...`,'info');const r=await this.post(`/api/lab/${kind}`,{});NESS.toast(`Cyber range: ${r.lab?.running?'Running':'Stopped'}`,'success');await this.refreshAll();}catch(e){NESS.toast(e.message,'danger');await this.refreshAll();}finally{this.busy=false;}
  },
  async runScenario(key,btn){
    if(this.busy||!this.lab?.running)return;this.busy=true; const result=document.getElementById('labScenarioResult');const old=btn?.innerHTML;if(btn){btn.disabled=true;btn.innerHTML='<i class="fa-solid fa-spinner fa-spin"></i> Running'};if(result)result.textContent=`Running ${key} inside the integrated local lab...`;
    try{const r=await this.post(`/api/lab/scenario/${encodeURIComponent(key)}`,{});const o=r.result?.output||r.result?.error||'Scenario completed';const x=r.result?.integration||{};const tr=(v)=>window.NESS_I18N?.t(v)||v;const sync=`${tr('Incidents')}: ${x.incidents??0} | ${tr('Alerts')}: ${x.alerts??0} | ${tr('Evidence')}: ${x.evidence??0} | ${tr('AI Analysis')}: ${x.aiAnalyses??0} | INTS: ${x.intsEvents??0} | ${tr('Logs')}: ${x.logs??0} | ${tr('Flows')}: ${x.flows??0}`;if(result)result.textContent=`${tr('Scenario')}: ${key}\n${tr('Result')}: ${o}\n\n${tr('Live integration after this run')}:\n${sync}`;NESS.toast(tr('Scenario completed and synchronized across NESS'),'success');if(window.NESS_API?.refreshCurrentView)await NESS_API.refreshCurrentView('scenario-completed');setTimeout(()=>this.refreshAll(),300);}catch(e){if(result)result.textContent=`Scenario failed: ${e.message}`;NESS.toast(e.message,'danger');}finally{this.busy=false;if(btn){btn.disabled=false;btn.innerHTML=old||'Run'}}
  },
  appendLiveEvent(type,payload={}){
    const box=document.getElementById('labLiveEvents');if(!box)return;
    const ts=new Date().toLocaleTimeString();let text='';
    if(type==='lab.packet') text=`${payload.protocol||'IP'} ${payload.source_ip||'?'}${payload.source_port?':'+payload.source_port:''} → ${payload.destination_ip||'?'}${payload.destination_port?':'+payload.destination_port:''} • ${payload.bytes||0} B`;
    else if(type==='lab.threat.detected'||type==='lab.http.threat') text=`THREAT • ${payload.attack_type||'Detected'} • ${payload.source_ip||'?'} → ${payload.destination_ip||payload.target||'?'} • ${payload.severity||''}`;
    else if(type==='lab.http') text=`HTTP ${payload.method||'GET'} ${payload.source_ip||'?'} → ${payload.destination_ip||'10.10.20.20'} ${payload.path||'/'}`;
    else if(type==='lab.db.event') text=`DB • ${payload.operation||payload.event||'event'} • ${payload.source_ip||''} → ${payload.destination_ip||''}`;
    else if(type?.startsWith('lab.scenario.')) text=`SCENARIO • ${payload.name||payload.key||''} • ${payload.status||type.split('.').pop()}`;
    else return;
    const row=document.createElement('div');row.className=`lab-event-row ${(type.includes('threat'))?'threat':''}`;row.innerHTML=`<span>${this.esc(ts)}</span><code>${this.esc(text)}</code>`;box.prepend(row);while(box.children.length>40)box.lastElementChild.remove();
  },
  animatePacket(payload,threat=false){
    const src=payload?.source_ip,dst=payload?.destination_ip;if(!src||!dst)return;
    const hostByIp={
      '10.10.10.11':'client','10.10.10.40':'attacker',
      '10.10.10.1':'gateway','10.10.20.1':'gateway','10.10.30.1':'gateway',
      '10.10.20.20':'web','10.10.30.30':'db'
    };
    const sId=hostByIp[src],dId=hostByIp[dst];if(!sId||!dId)return;
    const route=(a,b)=>{
      if(a===b)return [a];
      const users=new Set(['client','attacker']);
      if(users.has(a)&&users.has(b))return [a,'sw-users',b];
      if(users.has(a)&&b==='web')return [a,'sw-users','gateway','sw-dmz','web'];
      if(users.has(a)&&b==='db')return [a,'sw-users','gateway','sw-data','db'];
      if(a==='web'&&users.has(b))return ['web','sw-dmz','gateway','sw-users',b];
      if(a==='db'&&users.has(b))return ['db','sw-data','gateway','sw-users',b];
      if(a==='web'&&b==='db')return ['web','sw-dmz','gateway','sw-data','db'];
      if(a==='db'&&b==='web')return ['db','sw-data','gateway','sw-dmz','web'];
      if(a==='gateway'&&b==='web')return ['gateway','sw-dmz','web'];
      if(a==='gateway'&&b==='db')return ['gateway','sw-data','db'];
      if(a==='gateway'&&users.has(b))return ['gateway','sw-users',b];
      if(users.has(a)&&b==='gateway')return [a,'sw-users','gateway'];
      if(a==='web'&&b==='gateway')return ['web','sw-dmz','gateway'];
      if(a==='db'&&b==='gateway')return ['db','sw-data','gateway'];
      return [a,b];
    };
    const ids=route(sId,dId).filter(id=>this.nodeMap[id]);if(ids.length<2)return;
    const pts=ids.map(id=>this.nodeMap[id]);const layer=document.getElementById('labPacketLayer');if(!layer)return;
    const ns='http://www.w3.org/2000/svg',c=document.createElementNS(ns,'circle');c.setAttribute('r','6');c.setAttribute('class',`topology-packet ${threat?'threat':''}`);c.setAttribute('cx',pts[0].x);c.setAttribute('cy',pts[0].y);layer.appendChild(c);
    const segMs=220,total=Math.max(300,segMs*(pts.length-1)),start=performance.now();
    const tick=t=>{const elapsed=Math.min(total,t-start),u=elapsed/total,scaled=u*(pts.length-1),i=Math.min(pts.length-2,Math.floor(scaled)),q=Math.min(1,scaled-i),e=1-Math.pow(1-q,3),a=pts[i],b=pts[i+1];c.setAttribute('cx',Number(a.x)+(Number(b.x)-Number(a.x))*e);c.setAttribute('cy',Number(a.y)+(Number(b.y)-Number(a.y))*e);if(elapsed<total)requestAnimationFrame(tick);else setTimeout(()=>c.remove(),140)};requestAnimationFrame(tick);
    if(threat){const srcNode=document.querySelector(`[data-node-id="${sId}"]`),gateway=document.querySelector('[data-node-id="gateway"]');[srcNode,gateway].filter(Boolean).forEach(el=>{el.classList.add('threat');setTimeout(()=>el.classList.remove('threat'),1800)})}
  },
  bind(){
    if(document.body.dataset.page!=='network-topology.html')return;document.getElementById('labStartBtn')?.addEventListener('click',()=>this.action('start'));document.getElementById('labStopBtn')?.addEventListener('click',()=>this.action('stop'));document.getElementById('labResetBtn')?.addEventListener('click',()=>this.action('reset'));
    window.addEventListener('ness:realtime',e=>{const m=e.detail||{};this.appendLiveEvent(m.type,m.payload||{});if(m.type==='lab.packet')this.animatePacket(m.payload,false);if(m.type==='lab.threat.detected'||m.type==='lab.http.threat')this.animatePacket(m.payload,true);if(m.type?.startsWith('lab.')&&['lab.status','lab.started','lab.stopped','lab.reset','lab.devices.updated','lab.scenario.completed'].includes(m.type))setTimeout(()=>this.refreshAll(),250)});
    this.refreshAll();this.timer=setInterval(()=>this.refreshAll(),5000);
  }
};
document.addEventListener('DOMContentLoaded',()=>NESS_LAB.bind());
