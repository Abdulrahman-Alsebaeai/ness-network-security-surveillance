document.addEventListener('DOMContentLoaded', async()=>{
  if(typeof Chart === 'undefined') return;
  const tr = (s)=>window.NESS_I18N ? window.NESS_I18N.t(s) : s;
  Chart.defaults.font.family = 'Inter, Cairo, Segoe UI, Arial';
  Chart.defaults.color = '#64748b';

  let live = {attackTypes:[], severities:[], trend:[]};
  const instances = {};
  async function fetchLive(){
    try{
      const res = await fetch('/api/dashboard/charts',{credentials:'same-origin',cache:'no-store'});
      const data = await res.json();
      if(data.ok){ live = data; return true; }
    }catch(e){}
    return false;
  }
  await fetchLive();

  const destroy = key => { if(instances[key]){ instances[key].destroy(); instances[key]=null; } };
  const localized = items => (items||[]).map(x => tr(x.label));

  function render(){
    const attackLabels = live.attackTypes.length ? localized(live.attackTypes) : [tr('No live incidents')];
    const attackValues = live.attackTypes.length ? live.attackTypes.map(x=>x.value) : [0];
    const severityLabels = live.severities.length ? localized(live.severities) : [tr('No live incidents')];
    const severityValues = live.severities.length ? live.severities.map(x=>x.value) : [1];
    const trendLabels = live.trend.length ? live.trend.map(x=>x.label) : [tr('Now')];
    const trendValues = live.trend.length ? live.trend.map(x=>x.value) : [0];

    const attack=document.getElementById('attackChart');
    if(attack){
      destroy('attack');
      instances.attack = new Chart(attack,{type:'bar',data:{labels:attackLabels,datasets:[{label:tr('Events'),data:attackValues,backgroundColor:'#0284c7',borderRadius:8,maxBarThickness:42}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false}},y:{beginAtZero:true,grid:{color:'#e2e8f0'},ticks:{precision:0}}}}});
    }
    const severity=document.getElementById('severityChart');
    if(severity){
      destroy('severity');
      instances.severity = new Chart(severity,{type:'doughnut',data:{labels:severityLabels,datasets:[{data:severityValues,backgroundColor:['#dc2626','#d97706','#0284c7','#94a3b8'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,cutout:'72%',plugins:{legend:{position:'bottom',labels:{usePointStyle:true,boxWidth:8,padding:18}}}}});
    }
    const trend=document.getElementById('incidentTrendChart');
    if(trend){
      destroy('trend');
      instances.trend = new Chart(trend,{type:'line',data:{labels:trendLabels,datasets:[{label:tr('Incidents'),data:trendValues,borderColor:'#0284c7',backgroundColor:'rgba(2,132,199,.12)',fill:true,tension:.35,pointRadius:3}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{grid:{display:false}},y:{beginAtZero:true,grid:{color:'#e2e8f0'},ticks:{precision:0}}}}});
    }
  }

  render();
  window.addEventListener('ness:languageChanged', render);
  let chartRefreshBusy=false;
  const refreshCharts=async()=>{ if(chartRefreshBusy)return; chartRefreshBusy=true; try{if(await fetchLive())render();}finally{chartRefreshBusy=false;} };
  window.addEventListener('ness:dataChanged', refreshCharts);
  window.addEventListener('ness:realtime', e=>{ const t=e.detail?.type||''; if(t==='data.changed'||t==='incident.created'||t==='analysis.created'||t==='alert.created'||t.startsWith('lab.')) refreshCharts(); });
});
