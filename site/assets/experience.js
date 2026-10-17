
(function(){
  'use strict';
  const root=document.querySelector('[data-fasp-lab]');
  if(!root||root.dataset.ready==='1')return;
  root.dataset.ready='1';
  const q=(s)=>root.querySelector(s), qa=(s)=>Array.from(root.querySelectorAll(s));
  const cases={
    fleet:{peer:'Robot B',adapter:'Fleet adapter',cap:'fleet.assign_route',task:'Reserve loading-bay corridor',note:'A robot asks a fleet coordinator to schedule a route. Local motion remains with the robot.'},
    agents:{peer:'Agent B',adapter:'Task adapter',cap:'agent.delegate_task',task:'Delegate a research task',note:'An AI agent delegates bounded work. The receiver decides whether the peer has the required grant.'},
    industry:{peer:'Edge gateway',adapter:'Workcell adapter',cap:'workcell.schedule_job',task:'Schedule packaging work',note:'An industrial gateway requests a production task. Local safety controllers stay independent.'}
  };
  const faults={
    none:{description:'A permitted capability crosses the coordination boundary and reaches the local adapter.',at:null,title:'Request accepted',detail:'All checks passed. Local adapter dispatch simulated.'},
    signature:{description:'Tamper with the signed envelope. The receiver must reject it before authorization.',at:'signature',title:'Signature rejected',detail:'Envelope integrity cannot be established.'},
    pairing:{description:'Use a peer the receiving node has not explicitly authorized.',at:'pairing',title:'Unknown peer denied',detail:'An unpaired identity cannot cross this trust boundary.'},
    scope:{description:'Ask for a capability missing from the peer’s scoped grant.',at:'scope',title:'Capability denied',detail:'The requested operation is not within the authorized scope.'},
    layer:{description:'Try to request safety.estop.clear over the network. The safety boundary refuses it.',at:'layer',title:'Safety boundary enforced',detail:'Hard real-time safety functions are outside network authority.'},
    journal:{description:'Reuse an already-seen request identifier. Dispatch must not run again.',at:'journal',title:'Replay blocked',detail:'The idempotency journal detects an already-seen request.'}
  };
  const gates=['signature','pairing','scope','layer','journal','dispatch'];
  const info={
    peer:'Requesting peer: owns its own identity and policy. It may propose a signed request, not command the receiver.',
    core:'Receiving FASP node: checks the envelope, pairing, scoped grant, layer boundary and idempotency before local dispatch.',
    adapter:'Local adapter: installed and configured by the receiving system. Network data cannot select executable code.',
  };
  const elements={fault:q('#r2r-fault'),explain:q('[data-fault-explain]'),verdict:q('[data-verdict]'),log:q('[data-events]'),run:q('[data-run]'),reset:q('[data-reset]'),payload:q('[data-payload]'),nodeInfo:q('[data-node-info]')};
  const state={scenario:'fleet',sent:0,passed:0,denied:0,busy:false,timers:[],sequence:0};
  const later=(callback,delay)=>{const timer=setTimeout(callback,delay);state.timers.push(timer)};
  function addLog(message,kind){
    const li=document.createElement('li');
    const stamp=document.createElement('time');
    stamp.textContent=String(state.sequence++).padStart(3,'0');
    const span=document.createElement('span');span.textContent=message;
    li.append(stamp,span);if(kind)li.dataset.kind=kind;
    elements.log.prepend(li);
    while(elements.log.children.length>9)elements.log.lastElementChild.remove();
  }
  function counters(){for(const name of ['sent','passed','denied'])q('[data-count="'+name+'"]').textContent=String(state[name]).padStart(2,'0')}
  function verdict(kind,title,description){
    if(kind)elements.verdict.dataset.state=kind;else delete elements.verdict.dataset.state;
    elements.verdict.querySelector('.r2r-verdict-icon').textContent=kind==='passed'?'✓':kind==='failed'?'×':'◇';
    elements.verdict.querySelector('strong').textContent=title;
    elements.verdict.querySelector('small').textContent=description;
  }
  function clearGates(){
    qa('[data-gate]').forEach((row)=>{delete row.dataset.state;row.querySelector('.r2r-gate-status').textContent='READY'});
  }
  function mark(gate,status){
    const row=q('[data-gate="'+gate+'"]');
    if(!row)return;row.dataset.state=status;
    row.querySelector('.r2r-gate-status').textContent=status==='passed'?'PASS':status==='failed'?'DENY':'CHECK';
  }
  function payload(){
    const item=cases[state.scenario];const problem=faults[elements.fault.value]||faults.none;
    const envelope={
      protocol:'fasp/1.0',envelope_type:'task.request',sender:item.peer,
      recipient:'Node A',capability:problem.at==='layer'?'safety.estop.clear':item.cap,
      request_id:problem.at==='journal'?'previously-seen-id':'example-request-id',
      payload:{intent:item.task},
      signature:problem.at==='signature'?'INVALID (demo)':'<Ed25519 signature in real FASP>'
    };
    elements.payload.textContent=JSON.stringify(envelope,null,2);
    elements.explain.textContent=problem.description;
  }
  function selectScenario(name){
    if(state.busy||!cases[name])return;state.scenario=name;
    qa('[data-scenario]').forEach((b)=>{const active=b.dataset.scenario===name;b.classList.toggle('is-selected',active);b.setAttribute('aria-pressed',String(active))});
    q('[data-node-label="peer"]').textContent=cases[name].peer;
    q('[data-node-label="adapter"]').textContent=cases[name].adapter;
    clearGates();payload();
    verdict(null,'Scenario: '+(name==='fleet'?'Robot fleet':name==='agents'?'AI agents':'Industrial edge'),'Choose a condition and transmit to see the gates.');
    addLog('Loaded '+name+' scenario. '+cases[name].cap+'.');
  }
  function finish(result){
    state.busy=false;elements.run.disabled=false;elements.fault.disabled=false;
    qa('[data-scenario]').forEach((b)=>b.disabled=false);
    if(result==='none'){state.passed++;verdict('passed',faults.none.title,faults.none.detail);addLog('ACCEPTED → '+cases[state.scenario].adapter,'ok')}
    else{state.denied++;verdict('failed',faults[result].title,faults[result].detail);addLog('DENIED → '+faults[result].at+' gate; adapter not invoked','deny')}
    counters();
  }
  function send(){
    if(state.busy)return;state.busy=true;state.sent++;counters();
    elements.run.disabled=true;elements.fault.disabled=true;
    qa('[data-scenario]').forEach((b)=>b.disabled=true);
    clearGates();
    const problem=elements.fault.value in faults?elements.fault.value:'none';
    const gateToFail=faults[problem].at;
    verdict(null,'Verifying request…','Locally simulating policy checks, not sending a network request.');
    addLog('Envelope received: '+cases[state.scenario].cap);
    const reduced=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const delay=reduced?0:250;
    gates.forEach((gate,index)=>{
      later(()=>{mark(gate,'running');addLog('Checking '+gate+'…')},delay*index*2);
      later(()=>{if(gateToFail===gate){mark(gate,'failed');finish(problem)}else if(!gateToFail||index<gates.indexOf(gateToFail)){mark(gate,'passed');if(index===gates.length-1)finish('none')}},delay*(index*2+1));
    });
  }
  function reset(){
    state.timers.forEach(clearTimeout);state.timers=[];state.busy=false;state.sent=0;state.passed=0;state.denied=0;state.sequence=0;
    elements.run.disabled=false;elements.fault.disabled=false;qa('[data-scenario]').forEach((b)=>b.disabled=false);
    elements.fault.value='none';clearGates();counters();payload();
    elements.log.replaceChildren();verdict(null,'Awaiting transmission','Choose a condition and send an envelope.');
    addLog('Simulator reset. No live packets are sent.');
  }
  qa('[data-scenario]').forEach((b)=>b.addEventListener('click',()=>selectScenario(b.dataset.scenario)));
  qa('[data-node]').forEach((b)=>b.addEventListener('click',()=>{
    qa('[data-node]').forEach((item)=>item.classList.toggle('is-active',item===b));
    elements.nodeInfo.textContent=info[b.dataset.node]||info.core;
  }));
  elements.fault.addEventListener('change',()=>{if(state.busy)return;payload();clearGates();verdict(null,'Condition updated','Transmit to inspect the new outcome.')});
  elements.run.addEventListener('click',send);
  elements.reset.addEventListener('click',reset);
  payload();counters();
})();
