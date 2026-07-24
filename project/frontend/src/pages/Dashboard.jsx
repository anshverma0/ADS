import React from 'react';
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, 
  BarChart, Bar, PieChart, Pie, Cell, Legend, LineChart, Line
} from 'recharts';
import { 
  ShieldCheck, ShieldAlert, Cpu, Activity, Award, Radio, 
  CheckCircle2, AlertTriangle, Layers, Server, TrendingUp, Info
} from 'lucide-react';

export default function Dashboard({ stats = {}, timeline = [], protocols = [], attacks = [], topSrcIps = [], topDstIps = [] }) {
  
  // Custom colors for clear visual hierarchy
  const COLOR_SAFE = '#10b981';     // Emerald Green for Safe Normal Traffic
  const COLOR_ATTACK = '#f43f5e';   // Rose Red for Attacks & Threats
  const COLOR_CYAN = '#06b6d4';     // Cyber Cyan for Network Telemetry
  const COLOR_AMBER = '#f59e0b';    // Amber for Warnings
  const COLOR_BLUE = '#3b82f6';     // Blue for Protocols

  const PROTOCOL_COLORS = [COLOR_CYAN, COLOR_BLUE, COLOR_AMBER];

  // Derived safety metrics
  const totalFlows = stats.total_flows || 0;
  const normalFlows = stats.normal_flows || 0;
  const attackFlows = stats.attack_flows || 0;
  const attackRatio = stats.detection_rate !== undefined ? stats.detection_rate : (totalFlows ? ((attackFlows / totalFlows) * 100).toFixed(1) : 0);
  const safetyPct = (100 - attackRatio).toFixed(1);
  const isHealthy = attackFlows === 0 || attackRatio < 5;

  // Donut chart data for Traffic Safety Breakdown
  const safetyDonutData = [
    { name: 'Normal Safe Traffic', value: normalFlows || (totalFlows ? totalFlows - attackFlows : 100), color: COLOR_SAFE },
    { name: 'Malicious Attacks', value: attackFlows || 0, color: COLOR_ATTACK },
  ].filter(d => d.value > 0);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-geist text-2xl font-bold text-white tracking-tight">IDS Real-Time Monitoring Console</h1>
            <p className="text-xs text-gray-400 mt-0.5">Live visual summary of network security, traffic health, and AI threat detection.</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-gray-950 border border-white/10 text-xs font-mono text-gray-400 self-start md:self-auto">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span>Auto-Refreshes Live (30s)</span>
        </div>
      </div>

      {/* 1. Overall System Health Status Banner (User-Friendly Summary) */}
      <div className={`p-5 rounded-2xl border transition-all duration-300 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
        isHealthy 
          ? 'bg-emerald-500/10 border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.15)]' 
          : 'bg-rose-500/10 border-rose-500/30 shadow-[0_0_20px_rgba(244,63,94,0.15)]'
      }`}>
        <div className="flex items-start gap-4">
          <div className={`p-3 rounded-xl border shrink-0 ${
            isHealthy ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-400' : 'bg-rose-500/20 border-rose-500/40 text-rose-400'
          }`}>
            {isHealthy ? <CheckCircle2 className="w-7 h-7" /> : <ShieldAlert className="w-7 h-7 animate-pulse" />}
          </div>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className={`font-geist text-lg font-bold ${isHealthy ? 'text-emerald-400' : 'text-rose-400'}`}>
                {isHealthy ? 'System Health Optimal — Network Protected' : 'Active Threat Bursts Identified'}
              </h2>
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold uppercase border ${
                isHealthy ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
              }`}>
                {isHealthy ? 'Normal' : 'Critical Threat'}
              </span>
            </div>
            <p className="text-xs text-gray-300 mt-1 leading-relaxed max-w-3xl">
              {isHealthy ? (
                <>AI detection models confirm <span className="font-bold text-emerald-400">{safetyPct}%</span> of active traffic is safe and benign. No active intrusion attempts require intervention.</>
              ) : (
                <>AI models flagged <span className="font-bold text-rose-400">{attackFlows} malicious flows</span> ({attackRatio}% threat ratio) out of {totalFlows} total network flows.</>
              )}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono shrink-0 pt-3 md:pt-0 border-t md:border-t-0 border-white/10 w-full md:w-auto justify-between md:justify-end">
          <div>
            <span className="text-gray-400 block text-[10px] uppercase">Safety Score</span>
            <span className="text-emerald-400 font-bold text-base">{safetyPct}%</span>
          </div>
          <div className="h-8 w-px bg-white/10" />
          <div>
            <span className="text-gray-400 block text-[10px] uppercase">Blocked Threats</span>
            <span className="text-rose-400 font-bold text-base">{attackFlows}</span>
          </div>
        </div>
      </div>

      {/* 2. Visual KPI Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Packets */}
        <div className="glass-panel p-5 space-y-2 hover:border-cyan-500/40 transition group">
          <div className="flex justify-between items-center text-xs font-mono text-gray-400">
            <span className="uppercase tracking-wider">Total Packets Ingested</span>
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Radio className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="font-geist text-3xl font-bold text-white tracking-tight">{(stats.total_packets || 0).toLocaleString()}</span>
            <span className="text-xs font-mono text-cyan-400 font-semibold">Live Sniffer</span>
          </div>
          <p className="text-[11px] text-gray-400 pt-1 border-t border-white/5">Raw network packets captured by sniffer</p>
        </div>

        {/* Normal Safe Traffic */}
        <div className="glass-panel p-5 space-y-2 hover:border-emerald-500/40 transition group">
          <div className="flex justify-between items-center text-xs font-mono text-gray-400">
            <span className="uppercase tracking-wider">Normal Safe Traffic</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="font-geist text-3xl font-bold text-emerald-400 tracking-tight">{normalFlows.toLocaleString()}</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              {safetyPct}% Safe
            </span>
          </div>
          <p className="text-[11px] text-gray-400 pt-1 border-t border-white/5">Verified benign flows matching baseline</p>
        </div>

        {/* Attacks Flagged */}
        <div className="glass-panel p-5 space-y-2 hover:border-rose-500/40 transition group">
          <div className="flex justify-between items-center text-xs font-mono text-gray-400">
            <span className="uppercase tracking-wider">Attacks & Threats</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="font-geist text-3xl font-bold text-rose-400 tracking-tight">{attackFlows.toLocaleString()}</span>
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
              attackFlows > 0 ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
            }`}>
              {attackRatio}% Threat
            </span>
          </div>
          <p className="text-[11px] text-gray-400 pt-1 border-t border-white/5">Malicious anomaly bursts detected</p>
        </div>

        {/* AI Confidence Index */}
        <div className="glass-panel p-5 space-y-2 hover:border-purple-500/40 transition group">
          <div className="flex justify-between items-center text-xs font-mono text-gray-400">
            <span className="uppercase tracking-wider">AI Safety Confidence</span>
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400 border border-purple-500/20">
              <Award className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="font-geist text-3xl font-bold text-white tracking-tight">{((1 - (stats.ensemble_score || 0.07)) * 100).toFixed(1)}%</span>
            <span className="text-xs font-mono text-purple-300 font-semibold">Ensemble AI</span>
          </div>
          <p className="text-[11px] text-gray-400 pt-1 border-t border-white/5">Model confidence in traffic safety</p>
        </div>
      </div>

      {/* 3. Main Charts Section (Clear & Intuitive Visuals) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Real-Time Safety & Threat Timeline (Area Chart) */}
        <div className="lg:col-span-8 glass-panel p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-white/10 pb-3">
            <div>
              <h3 className="font-geist text-base font-bold text-white flex items-center gap-2">
                <Activity className="w-5 h-5 text-cyan-400" />
                <span>Live Traffic Safety vs Threat Timeline</span>
              </h3>
              <p className="text-xs text-gray-400 mt-0.5">Real-time comparison between Safe Traffic (Green) and Flagged Attacks (Red)</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Safe Traffic
              </span>
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Attacks
              </span>
            </div>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorSafeTraffic" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLOR_SAFE} stopOpacity={0.35}/>
                    <stop offset="95%" stopColor={COLOR_SAFE} stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorAttackTraffic" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLOR_ATTACK} stopOpacity={0.35}/>
                    <stop offset="95%" stopColor={COLOR_ATTACK} stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <YAxis stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '12px' }} />
                <Area type="monotone" dataKey="normal" stroke={COLOR_SAFE} strokeWidth={2.5} fillOpacity={1} fill="url(#colorSafeTraffic)" name="Normal Safe Traffic" />
                <Area type="monotone" dataKey="attacks" stroke={COLOR_ATTACK} strokeWidth={2.5} fillOpacity={1} fill="url(#colorAttackTraffic)" name="Malicious Attacks" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Traffic Safety Breakdown (Donut Chart) */}
        <div className="lg:col-span-4 glass-panel p-6 flex flex-col justify-between">
          <div>
            <h3 className="font-geist text-base font-bold text-white mb-1">Traffic Safety Ratio</h3>
            <p className="text-xs text-gray-400 mb-4">Overall proportion of safe vs threat traffic</p>
          </div>

          <div className="h-52 relative flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={safetyDonutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {safetyDonutData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.5)" strokeWidth={2} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="font-geist text-2xl font-bold text-emerald-400">{safetyPct}%</span>
              <span className="text-[10px] font-mono text-gray-400 uppercase font-bold">Safe Traffic</span>
            </div>
          </div>

          <div className="space-y-2 pt-3 border-t border-white/5 text-xs font-mono">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-gray-300">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Normal Safe Traffic
              </span>
              <span className="font-bold text-emerald-400">{normalFlows.toLocaleString()}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 text-gray-300">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Malicious Threats
              </span>
              <span className="font-bold text-rose-400">{attackFlows.toLocaleString()}</span>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Sub-Distributions Section */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
        {/* Protocol Share */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <h3 className="font-geist text-base font-bold text-white mb-1">Network Protocol Share</h3>
          <p className="text-xs text-gray-400 mb-3">Traffic volume divided by TCP, UDP, and ICMP protocols</p>
          <div className="h-44 relative flex items-center justify-center">
            {protocols.length === 0 ? (
              <div className="text-gray-500 italic text-xs font-mono">No protocol metrics</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={protocols}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {protocols.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PROTOCOL_COLORS[index % PROTOCOL_COLORS.length]} stroke="rgba(0,0,0,0.5)" />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                  <Legend layout="vertical" verticalAlign="middle" align="right" wrapperStyle={{ fontSize: '11px', fontFamily: 'Space Mono' }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Attack Category Breakdown */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <h3 className="font-geist text-base font-bold text-white mb-1">Detected Attack Types</h3>
          <p className="text-xs text-gray-400 mb-3">Breakdown of specific attack signatures identified</p>
          <div className="h-44 flex items-center justify-center">
            {attacks.length === 0 ? (
              <div className="p-4 text-center">
                <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-1" />
                <span className="text-xs font-mono text-gray-400">No Attack Signatures Flagged</span>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={attacks} layout="vertical" margin={{ top: 5, right: 10, left: 10, bottom: 5 }}>
                  <XAxis type="number" stroke="#6b7280" fontSize={9} />
                  <YAxis dataKey="name" type="category" stroke="#6b7280" fontSize={9} width={80} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                  <Bar dataKey="value" fill={COLOR_ATTACK} radius={[0, 4, 4, 0]} name="Count" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Suspicious Source IPs */}
        <div className="glass-panel p-6 flex flex-col justify-between">
          <h3 className="font-geist text-base font-bold text-white mb-1">Top Active Hosts (Source IP)</h3>
          <p className="text-xs text-gray-400 mb-3">Primary IP addresses streaming network traffic</p>
          <div className="h-44 flex flex-col justify-center space-y-3 font-mono text-xs">
            {topSrcIps.length === 0 ? (
              <div className="text-gray-500 italic text-center text-xs font-mono">No host IPs recorded</div>
            ) : (
              topSrcIps.slice(0, 4).map((item, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-white font-bold">{item.ip}</span>
                    <span className="text-cyan-400 font-bold">{item.count} flows</span>
                  </div>
                  <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-cyan-400 h-full shadow-glow-cyan"
                      style={{ width: `${(item.count / (topSrcIps[0]?.count || 1)) * 100}%` }}
                    />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
