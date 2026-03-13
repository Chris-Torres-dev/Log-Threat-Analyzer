import { useState, useRef, useEffect, useCallback } from "react";

const WS_URL = "ws://localhost:8765";

// ── Severity styling ──
const SEV = {
  CRITICAL:{ bg:"#ff2d2d14",border:"#ff2d2d",text:"#ff6b6b",dot:"#ff2d2d",badge:{bg:"#ff2d2d",fg:"#fff"} },
  HIGH:    { bg:"#ff8c0014",border:"#ff8c00",text:"#ffaa44",dot:"#ff8c00",badge:{bg:"#ff8c00",fg:"#fff"} },
  MEDIUM:  { bg:"#ffd70014",border:"#ffd700",text:"#ffd700",dot:"#ffd700",badge:{bg:"#ffd700",fg:"#000"} },
  LOW:     { bg:"#00aaff14",border:"#00aaff",text:"#44bbff",dot:"#00aaff",badge:{bg:"#00aaff",fg:"#fff"} },
  NONE:    { bg:"#ffffff08",border:"#30363d",text:"#8b949e",dot:"#30363d",badge:{bg:"#30363d",fg:"#fff"} },
};
const sev = (s) => SEV[s] || SEV.NONE;

const VERDICT = {
  IMMEDIATE_ACTION:{ color:"#ff2d2d", icon:"🚨" },
  INVESTIGATE:     { color:"#ff8c00", icon:"🔍" },
  MONITOR:         { color:"#ffd700", icon:"👁" },
  LIKELY_FP:       { color:"#00ff88", icon:"✓" },
};

// ── Shared styles ──
const mono = "'IBM Plex Mono','Courier New',monospace";
const display = "'Orbitron',monospace";

function Badge({ label, bg="#21262d", fg="#8b949e", pulse=false }) {
  return (
    <span style={{ background:bg, color:fg, padding:"2px 8px", fontSize:9,
      fontWeight:700, letterSpacing:1.5, display:"inline-block",
      animation: pulse ? "pulse 1.5s infinite" : "none" }}>
      {label}
    </span>
  );
}

function SevDot({ s, size=7 }) {
  const c = sev(s);
  return <span style={{ width:size, height:size, borderRadius:"50%", background:c.dot,
    display:"inline-block", flexShrink:0,
    animation: s==="CRITICAL" ? "pulse 1.5s infinite" : "none" }} />;
}

function CppEventRow({ e }) {
  const c = sev(e.severity);
  return (
    <div style={{ display:"flex", alignItems:"flex-start", gap:8, padding:"7px 0",
      borderBottom:"1px solid #0d1117", animation:"fadeIn .2s ease" }}>
      <SevDot s={e.severity} />
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:2 }}>
          <span style={{ color:c.text, fontSize:11, fontWeight:600 }}>{e.type}</span>
          {e.ip && <span style={{ fontSize:10, color:"#ffaa44" }}>{e.ip}</span>}
          <span style={{ marginLeft:"auto", fontSize:9, color:"#30363d" }}>score:{e.score}</span>
        </div>
        <div style={{ fontSize:10, color:"#8b949e", whiteSpace:"nowrap", overflow:"hidden",
          textOverflow:"ellipsis" }}>{e.line}</div>
      </div>
    </div>
  );
}

function AiResultCard({ r }) {
  const v = VERDICT[r.verdict] || VERDICT.MONITOR;
  const [open, setOpen] = useState(false);
  return (
    <div style={{ border:`1px solid ${v.color}44`, borderLeft:`3px solid ${v.color}`,
      padding:"12px 14px", marginBottom:8, animation:"fadeIn .3s ease", background:"#0a0e14" }}>
      <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8, cursor:"pointer" }}
           onClick={() => setOpen(o=>!o)}>
        <span style={{ fontSize:14 }}>{v.icon}</span>
        <span style={{ color:v.color, fontSize:12, fontWeight:700, letterSpacing:1 }}>{r.verdict}</span>
        <span style={{ fontSize:10, color:"#8b949e" }}>confidence: <b style={{color:"#c9d1d9"}}>{r.confidence}%</b></span>
        <span style={{ fontSize:10, color:"#8b949e", marginLeft:"auto" }}>{r.analyzed_events} events analyzed</span>
        <span style={{ fontSize:10, color:"#30363d" }}>{open?"▲":"▼"}</span>
      </div>
      <p style={{ fontSize:11, color:"#c9d1d9", margin:"0 0 8px 22px", lineHeight:1.6,
        fontStyle:"italic" }}>{r.pattern}</p>
      {open && (
        <div style={{ marginLeft:22, display:"flex", flexDirection:"column", gap:8 }}>
          {r.kill_chain_stage && r.kill_chain_stage !== "None" && (
            <div><span style={{fontSize:10,color:"#8b949e"}}>KILL CHAIN: </span>
              <span style={{fontSize:10,color:"#ff8c00",fontWeight:600}}>{r.kill_chain_stage}</span></div>
          )}
          {r.priority_threat && (
            <div style={{background:"#ff2d2d0a",border:"1px solid #ff2d2d22",padding:"8px 10px"}}>
              <div style={{fontSize:9,color:"#8b949e",letterSpacing:2,marginBottom:4}}>PRIORITY THREAT</div>
              <div style={{fontSize:11,color:"#ff6b6b"}}>{r.priority_threat}</div>
            </div>
          )}
          {r.response_actions?.length > 0 && (
            <div>
              <div style={{fontSize:9,color:"#8b949e",letterSpacing:2,marginBottom:6}}>RESPONSE ACTIONS</div>
              {r.response_actions.map((a,i) => (
                <div key={i} style={{fontSize:11,color:"#a8ff78",marginBottom:4}}>
                  <span style={{color:"#30363d"}}>{i+1}. </span>{a}
                </div>
              ))}
            </div>
          )}
          {r.false_positives?.length > 0 && (
            <div>
              <div style={{fontSize:9,color:"#8b949e",letterSpacing:2,marginBottom:4}}>LIKELY FALSE POSITIVES</div>
              {r.false_positives.map((fp,i) => (
                <div key={i} style={{fontSize:10,color:"#8b949e"}}>• {fp}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Settings toggle ──
function Toggle({ value, onChange, label }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
      <div onClick={() => onChange(!value)} style={{
        width:36, height:18, borderRadius:9, cursor:"pointer", position:"relative",
        background: value ? "#00ff88" : "#21262d", transition:"background .2s",
        border: value ? "1px solid #00ff88" : "1px solid #30363d"
      }}>
        <div style={{ position:"absolute", top:2, left: value ? 18 : 2, width:12, height:12,
          borderRadius:"50%", background: value ? "#000" : "#8b949e", transition:"left .2s" }}/>
      </div>
      <span style={{ fontSize:11, color:"#c9d1d9" }}>{label}</span>
    </div>
  );
}

function Slider({ label, value, min, max, step=1, unit="", onChange }) {
  return (
    <div style={{ marginBottom:14 }}>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:5 }}>
        <span style={{ fontSize:10, color:"#8b949e", letterSpacing:1 }}>{label}</span>
        <span style={{ fontSize:10, color:"#00ff88" }}>{value}{unit}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value}
        onChange={e => onChange(Number(e.target.value))}
        style={{ width:"100%", accentColor:"#00ff88", height:3 }} />
    </div>
  );
}

function Select({ label, value, options, onChange }) {
  return (
    <div style={{ marginBottom:14 }}>
      <div style={{ fontSize:10, color:"#8b949e", letterSpacing:1, marginBottom:5 }}>{label}</div>
      <div style={{ display:"flex", gap:6 }}>
        {options.map(o => (
          <button key={o} onClick={() => onChange(o)} style={{
            padding:"4px 12px", fontSize:10, cursor:"pointer", fontFamily:mono,
            background: value===o ? "#00ff88" : "#161b22",
            color: value===o ? "#000" : "#8b949e",
            border: `1px solid ${value===o ? "#00ff88" : "#30363d"}`,
            letterSpacing:1, fontWeight: value===o ? 700 : 400
          }}>{o}</button>
        ))}
      </div>
    </div>
  );
}

// ============================================================
//  MAIN APP
// ============================================================
export default function App() {
  const [tab, setTab] = useState("monitor"); // monitor | ai | settings
  const [wsStatus, setWsStatus] = useState("disconnected");
  const [cppEvents, setCppEvents] = useState([]);
  const [aiResults, setAiResults] = useState([]);
  const [config, setConfig] = useState({
    ai_enabled: true,
    ai_batch_interval: 15,
    ai_sensitivity: "medium",
    cpp_bf_threshold: 5,
    cpp_bf_window: 60,
    ai_max_batch: 30,
  });
  const [localConfig, setLocalConfig] = useState(config); // editable copy
  const [stats, setStats] = useState({ cpp_events:0, cpp_threats:0, ai_runs:0 });
  const [aiError, setAiError] = useState(null);
  const [sevFilter, setSevFilter] = useState("ALL");
  const wsRef = useRef(null);
  const feedRef = useRef(null);

  useEffect(() => {
    feedRef.current?.scrollTo({ top: feedRef.current.scrollHeight, behavior:"smooth" });
  }, [cppEvents]);

  const connect = useCallback(() => {
    if (wsRef.current) wsRef.current.close();
    setWsStatus("connecting");
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    ws.onopen = () => setWsStatus("connected");
    ws.onclose = () => setWsStatus("disconnected");
    ws.onerror = () => setWsStatus("error");
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === "cpp_event") {
          setCppEvents(p => [...p, msg.event].slice(-500));
          if (msg.event.severity !== "NONE" && msg.event.severity !== "LOW") {
            setStats(s => ({ ...s, cpp_events: s.cpp_events+1, cpp_threats: s.cpp_threats+1 }));
          } else {
            setStats(s => ({ ...s, cpp_events: s.cpp_events+1 }));
          }
        } else if (msg.type === "ai_analysis") {
          setAiResults(p => [msg.result, ...p].slice(0, 30));
          setStats(s => ({ ...s, ai_runs: s.ai_runs+1 }));
          setAiError(null);
        } else if (msg.type === "ai_error") {
          setAiError(msg.message);
        } else if (msg.type === "init") {
          setConfig(msg.config || {});
          setLocalConfig(msg.config || {});
          setStats(msg.stats || {});
          if (msg.recent_events) setCppEvents(msg.recent_events.slice(-200));
          if (msg.recent_ai) setAiResults(msg.recent_ai);
        } else if (msg.type === "config_update") {
          setConfig(msg.config);
          setLocalConfig(msg.config);
        }
      } catch {}
    };
  }, []);

  const disconnect = useCallback(() => {
    wsRef.current?.close();
    setWsStatus("disconnected");
  }, []);

  const saveSettings = () => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type:"update_settings", settings: localConfig }));
    }
    setConfig(localConfig);
  };

  const triggerAI = () => {
    if (wsRef.current?.readyState === 1) {
      wsRef.current.send(JSON.stringify({ type:"trigger_ai" }));
    }
  };

  const clearAll = () => {
    setCppEvents([]); setAiResults([]);
    if (wsRef.current?.readyState === 1) wsRef.current.send(JSON.stringify({ type:"clear" }));
  };

  const wsColor = { disconnected:"#8b949e", connecting:"#ffd700", connected:"#00ff88", error:"#ff6b6b" }[wsStatus];
  const filtered = sevFilter === "ALL" ? cppEvents : cppEvents.filter(e => e.severity === sevFilter);

  return (
    <div style={{ minHeight:"100vh", background:"#080c10", color:"#c9d1d9", fontFamily:mono }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=Orbitron:wght@700;900&display=swap');
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
        @keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
        @keyframes spin{to{transform:rotate(360deg)}}
        ::-webkit-scrollbar{width:4px}::-webkit-scrollbar-track{background:#0a0e14}
        ::-webkit-scrollbar-thumb{background:#21262d}
        input[type=range]{cursor:pointer}
        * { box-sizing:border-box }
      `}</style>

      {/* ── HEADER ── */}
      <div style={{ background:"#0d1117", borderBottom:"1px solid #21262d",
        display:"flex", alignItems:"center", padding:"0 24px", height:52 }}>
        <div style={{ fontFamily:display, fontSize:14, fontWeight:900,
          color:"#00ff88", letterSpacing:4, marginRight:12 }}>THREATSCOPE</div>
        <div style={{ fontSize:9, color:"#30363d", letterSpacing:2, marginRight:24 }}>v2.0</div>

        {/* Tabs */}
        {[["monitor","◈ ENGINE FEED"],["ai","⬡ AI ANALYSIS"],["settings","⚙ SETTINGS"]].map(([t,label]) => (
          <button key={t} onClick={() => setTab(t)} style={{
            background:"none", border:"none", fontFamily:mono, cursor:"pointer",
            padding:"0 16px", height:"100%", fontSize:10, letterSpacing:2,
            color: tab===t ? "#00ff88" : "#8b949e",
            borderBottom: tab===t ? "2px solid #00ff88" : "2px solid transparent",
          }}>{label}</button>
        ))}

        {/* Status bar */}
        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:16 }}>
          {/* Stats */}
          <span style={{ fontSize:9, color:"#8b949e" }}>
            C++ <span style={{ color:"#c9d1d9" }}>{stats.cpp_events||0}</span> events·
            <span style={{ color:"#ff8c00" }}>{stats.cpp_threats||0}</span> threats
          </span>
          <span style={{ fontSize:9, color:"#8b949e" }}>
            AI runs <span style={{ color:"#44bbff" }}>{stats.ai_runs||0}</span>
          </span>
          {/* WS connect */}
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ width:6, height:6, borderRadius:"50%", background:wsColor,
              display:"inline-block", animation:wsStatus==="connected"?"pulse 2s infinite":"none" }}/>
            <span style={{ fontSize:9, color:wsColor, letterSpacing:1 }}>{wsStatus.toUpperCase()}</span>
            {wsStatus !== "connected"
              ? <button onClick={connect} style={{ background:"#00ff88", color:"#000",
                  border:"none", padding:"3px 10px", fontSize:9, fontWeight:700,
                  fontFamily:mono, cursor:"pointer", letterSpacing:1 }}>CONNECT</button>
              : <button onClick={disconnect} style={{ background:"#21262d", color:"#8b949e",
                  border:"1px solid #30363d", padding:"3px 10px", fontSize:9,
                  fontFamily:mono, cursor:"pointer", letterSpacing:1 }}>DISC.</button>
            }
          </div>
        </div>
      </div>

      {/* ── MONITOR TAB ── */}
      {tab === "monitor" && (
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", height:"calc(100vh - 52px)" }}>
          {/* Left: C++ raw event stream */}
          <div style={{ borderRight:"1px solid #21262d", display:"flex", flexDirection:"column" }}>
            <div style={{ padding:"10px 16px", borderBottom:"1px solid #21262d",
              display:"flex", alignItems:"center", gap:8 }}>
              <span style={{ fontSize:9, color:"#8b949e", letterSpacing:2, flex:1 }}>
                ◈ C++ ENGINE — LIVE FEED <span style={{ color:"#30363d" }}>(&lt;1ms detection)</span>
              </span>
              <button onClick={clearAll} style={{ background:"none", border:"1px solid #21262d",
                color:"#8b949e", padding:"2px 8px", fontSize:9, fontFamily:mono, cursor:"pointer" }}>
                CLEAR
              </button>
            </div>

            {/* Severity filter */}
            <div style={{ padding:"6px 14px", borderBottom:"1px solid #0d1117",
              display:"flex", gap:5 }}>
              {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(f => {
                const c = sev(f);
                return (
                  <button key={f} onClick={() => setSevFilter(f)} style={{
                    padding:"2px 8px", fontSize:8, letterSpacing:1, cursor:"pointer",
                    fontFamily:mono, border:`1px solid ${sevFilter===f?(f==="ALL"?"#00ff88":c.border):"#21262d"}`,
                    background: sevFilter===f ? (f==="ALL"?"#00ff8818":c.bg) : "transparent",
                    color: sevFilter===f ? (f==="ALL"?"#00ff88":c.text) : "#8b949e"
                  }}>{f}</button>
                );
              })}
              <span style={{ marginLeft:"auto", fontSize:9, color:"#30363d" }}>
                {filtered.length} events
              </span>
            </div>

            {/* Event feed */}
            <div ref={feedRef} style={{ flex:1, overflowY:"auto", padding:"4px 14px" }}>
              {wsStatus !== "connected" && cppEvents.length === 0 ? (
                <div style={{ textAlign:"center", color:"#21262d", marginTop:48 }}>
                  <div style={{ fontSize:9, letterSpacing:3, marginBottom:12 }}>C++ ENGINE OFFLINE</div>
                  <div style={{ fontSize:9, color:"#30363d", lineHeight:2 }}>
                    Compile: <span style={{color:"#a8ff78"}}>g++ -std=c++17 -O3 engine.cpp -o engine</span><br/>
                    Run: <span style={{color:"#a8ff78"}}>./engine --demo | python3 bridge.py</span>
                  </div>
                </div>
              ) : filtered.length === 0 ? (
                <div style={{ color:"#21262d", fontSize:10, textAlign:"center", marginTop:40, letterSpacing:2 }}>
                  NO EVENTS MATCHING FILTER
                </div>
              ) : (
                filtered.map((e, i) => <CppEventRow key={i} e={e} />)
              )}
            </div>

            {/* Layer info bar */}
            <div style={{ padding:"6px 14px", borderTop:"1px solid #0d1117",
              display:"flex", gap:16, fontSize:9, color:"#30363d" }}>
              <span>RADIX SORT ✓</span>
              <span>SLIDING WINDOW ✓</span>
              <span>HASH TABLE ✓</span>
              <span style={{ marginLeft:"auto", color:"#8b949e" }}>
                BF: {localConfig.cpp_bf_threshold} hits/{localConfig.cpp_bf_window}s
              </span>
            </div>
          </div>

          {/* Right: AI summaries (live) */}
          <div style={{ display:"flex", flexDirection:"column", overflow:"hidden" }}>
            <div style={{ padding:"10px 16px", borderBottom:"1px solid #21262d",
              display:"flex", alignItems:"center", gap:8 }}>
              <span style={{ fontSize:9, color:"#8b949e", letterSpacing:2, flex:1 }}>
                ⬡ AI LAYER — PATTERN ANALYSIS <span style={{ color:"#30363d" }}>({localConfig.ai_batch_interval}s intervals)</span>
              </span>
              <button onClick={triggerAI} style={{
                background: config.ai_enabled ? "#00aaff22" : "#21262d",
                border: `1px solid ${config.ai_enabled ? "#00aaff" : "#30363d"}`,
                color: config.ai_enabled ? "#44bbff" : "#30363d",
                padding:"2px 10px", fontSize:9, fontFamily:mono, cursor:"pointer", letterSpacing:1
              }}>RUN NOW</button>
            </div>

            <div style={{ flex:1, overflowY:"auto", padding:"10px 14px" }}>
              {!config.ai_enabled && (
                <div style={{ background:"#ffd70010", border:"1px solid #ffd70044",
                  padding:"10px 14px", marginBottom:10, fontSize:10, color:"#ffd700" }}>
                  ⚠ AI analysis disabled — enable in Settings
                </div>
              )}
              {aiError && (
                <div style={{ background:"#ff2d2d10", border:"1px solid #ff2d2d44",
                  padding:"10px 14px", marginBottom:10, fontSize:10, color:"#ff6b6b" }}>
                  AI error: {aiError}
                </div>
              )}
              {aiResults.length === 0 ? (
                <div style={{ color:"#21262d", fontSize:10, textAlign:"center", marginTop:40, letterSpacing:2, lineHeight:2 }}>
                  {config.ai_enabled
                    ? `WAITING FOR FIRST AI RUN\nNext run after ${localConfig.ai_batch_interval}s of data`
                    : "AI DISABLED"}
                </div>
              ) : (
                aiResults.map((r, i) => <AiResultCard key={i} r={r} />)
              )}
            </div>

            <div style={{ padding:"6px 14px", borderTop:"1px solid #0d1117",
              display:"flex", gap:16, fontSize:9, color:"#30363d" }}>
              <span>SENSITIVITY: <span style={{color:"#8b949e"}}>{localConfig.ai_sensitivity.toUpperCase()}</span></span>
              <span>BATCH: <span style={{color:"#8b949e"}}>{localConfig.ai_max_batch} events</span></span>
              <span style={{marginLeft:"auto",color:"#8b949e"}}>AI runs: {stats.ai_runs||0}</span>
            </div>
          </div>
        </div>
      )}

      {/* ── AI TAB (full AI history) ── */}
      {tab === "ai" && (
        <div style={{ height:"calc(100vh - 52px)", overflow:"hidden", display:"flex", flexDirection:"column" }}>
          <div style={{ padding:"12px 20px", borderBottom:"1px solid #21262d",
            display:"flex", alignItems:"center", gap:10 }}>
            <span style={{ fontSize:9, color:"#8b949e", letterSpacing:2 }}>
              AI ANALYSIS HISTORY — {aiResults.length} runs
            </span>
            <button onClick={triggerAI} style={{
              marginLeft:"auto", background:"#00aaff22", border:"1px solid #00aaff66",
              color:"#44bbff", padding:"5px 16px", fontSize:10, fontFamily:mono,
              cursor:"pointer", letterSpacing:1
            }}>⬡ RUN AI NOW</button>
          </div>
          <div style={{ flex:1, overflowY:"auto", padding:"16px 20px", maxWidth:860, width:"100%" }}>
            {aiResults.length === 0 ? (
              <div style={{ color:"#21262d", textAlign:"center", marginTop:60, fontSize:10, letterSpacing:2 }}>
                NO AI ANALYSES YET<br/>
                <span style={{fontSize:9,color:"#30363d"}}>Connect to backend and wait for first analysis run</span>
              </div>
            ) : (
              aiResults.map((r, i) => <AiResultCard key={i} r={r} />)
            )}
          </div>
        </div>
      )}

      {/* ── SETTINGS TAB ── */}
      {tab === "settings" && (
        <div style={{ height:"calc(100vh - 52px)", overflowY:"auto", padding:"24px" }}>
          <div style={{ maxWidth:640, margin:"0 auto", display:"grid",
            gridTemplateColumns:"1fr 1fr", gap:20 }}>

            {/* C++ Engine settings */}
            <div style={{ background:"#0d1117", border:"1px solid #21262d", padding:20 }}>
              <div style={{ fontFamily:display, fontSize:11, color:"#00ff88",
                letterSpacing:3, marginBottom:16 }}>◈ C++ ENGINE</div>
              <div style={{ fontSize:9, color:"#30363d", marginBottom:16, lineHeight:1.7 }}>
                These control the fast detection layer. Changes apply on next restart of the engine binary.
              </div>

              <Slider label="BRUTE FORCE THRESHOLD" value={localConfig.cpp_bf_threshold}
                min={2} max={20} unit=" failures"
                onChange={v => setLocalConfig(c=>({...c, cpp_bf_threshold:v}))} />
              <Slider label="BRUTE FORCE WINDOW" value={localConfig.cpp_bf_window}
                min={10} max={300} step={10} unit="s"
                onChange={v => setLocalConfig(c=>({...c, cpp_bf_window:v}))} />

              <div style={{ fontSize:9, color:"#8b949e", marginTop:16, lineHeight:2 }}>
                <div>Compile flags:</div>
                <div style={{color:"#a8ff78",fontSize:9}}>g++ -std=c++17 -O3 -march=native engine.cpp</div>
                <div style={{marginTop:8}}>Run:</div>
                <div style={{color:"#a8ff78",fontSize:9}}>./engine --demo | python3 bridge.py</div>
              </div>
            </div>

            {/* AI settings */}
            <div style={{ background:"#0d1117", border:"1px solid #21262d", padding:20 }}>
              <div style={{ fontFamily:display, fontSize:11, color:"#44bbff",
                letterSpacing:3, marginBottom:16 }}>⬡ AI LAYER</div>

              <Toggle label="AI Analysis Enabled" value={localConfig.ai_enabled}
                onChange={v => setLocalConfig(c=>({...c, ai_enabled:v}))} />

              <Slider label="BATCH INTERVAL" value={localConfig.ai_batch_interval}
                min={5} max={120} step={5} unit="s"
                onChange={v => setLocalConfig(c=>({...c, ai_batch_interval:v}))} />
              <Slider label="MAX EVENTS PER BATCH" value={localConfig.ai_max_batch}
                min={5} max={100} step={5}
                onChange={v => setLocalConfig(c=>({...c, ai_max_batch:v}))} />

              <Select label="AI SENSITIVITY (minimum severity to analyze)"
                value={localConfig.ai_sensitivity}
                options={["low","medium","high"]}
                onChange={v => setLocalConfig(c=>({...c, ai_sensitivity:v}))} />

              <div style={{ fontSize:9, color:"#30363d", marginTop:8, lineHeight:1.8 }}>
                <b style={{color:"#8b949e"}}>low</b> = analyze everything including LOW sev<br/>
                <b style={{color:"#8b949e"}}>medium</b> = only MEDIUM+ events (recommended)<br/>
                <b style={{color:"#8b949e"}}>high</b> = only HIGH/CRITICAL (fewest AI calls)
              </div>
            </div>

            {/* Connection info */}
            <div style={{ background:"#0d1117", border:"1px solid #21262d", padding:20,
              gridColumn:"1/-1" }}>
              <div style={{ fontFamily:display, fontSize:11, color:"#8b949e",
                letterSpacing:3, marginBottom:14 }}>◉ ARCHITECTURE</div>
              <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
                {[
                  { layer:"LAYER 1", lang:"C++", color:"#ff8c00",
                    desc:"Radix sort · Sliding window BF · Hash map scoring",
                    speed:"< 1ms per line", detail:"Pure arrays, no AI, no allocations in hot path" },
                  { layer:"LAYER 2", lang:"Python", color:"#44bbff",
                    desc:"Batches C++ events · Sends to AI · WebSocket server",
                    speed:"~15s intervals", detail:"AI sees pre-sorted, pre-flagged data — faster + cheaper" },
                  { layer:"LAYER 3", lang:"React", color:"#00ff88",
                    desc:"Live C++ feed · AI results · Settings interface",
                    speed:"Real-time WS", detail:"Settings apply to both layers without restart" },
                ].map(l => (
                  <div key={l.layer} style={{ background:"#080c10", padding:14,
                    border:`1px solid ${l.color}33` }}>
                    <div style={{ fontSize:9, color:l.color, fontWeight:700,
                      letterSpacing:2, marginBottom:4 }}>{l.layer} · {l.lang}</div>
                    <div style={{ fontSize:10, color:"#c9d1d9", marginBottom:6 }}>{l.desc}</div>
                    <div style={{ fontSize:9, color:l.color, marginBottom:4 }}>⚡ {l.speed}</div>
                    <div style={{ fontSize:9, color:"#30363d" }}>{l.detail}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Save button */}
            <div style={{ gridColumn:"1/-1", display:"flex", justifyContent:"flex-end", gap:10 }}>
              <button onClick={() => setLocalConfig(config)} style={{
                background:"#161b22", border:"1px solid #30363d", color:"#8b949e",
                padding:"8px 20px", fontSize:10, fontFamily:mono, cursor:"pointer", letterSpacing:1
              }}>RESET</button>
              <button onClick={saveSettings} style={{
                background:"#00ff88", color:"#000", border:"none",
                padding:"8px 24px", fontSize:11, fontFamily:mono,
                cursor:"pointer", letterSpacing:2, fontWeight:700
              }}>SAVE SETTINGS</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}