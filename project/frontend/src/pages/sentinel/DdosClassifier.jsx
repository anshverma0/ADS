import React from 'react';
import { 
  ResponsiveContainer, LineChart, Line, PieChart, Pie, Cell, BarChart, Bar, 
  XAxis, YAxis, Tooltip 
} from 'recharts';
import { 
  Target, Cloud, AlertTriangle, Bug, Lock, MoreHorizontal, 
  TrendingUp, TrendingDown, ArrowRight, ShieldCheck, Calendar, Bell, User
} from 'lucide-react';

// Custom Enterprise Palette matching reference UI
const COLOR_CRITICAL = '#ef4444';  // Red
const COLOR_HIGH = '#f97316';      // Orange
const COLOR_MEDIUM = '#eab308';    // Yellow
const COLOR_LOW = '#22c55e';       // Green
const COLOR_BLUE = '#3b82f6';      // Blue
const COLOR_PURPLE = '#a855f7';    // Purple
const COLOR_CYAN = '#06b6d4';      // Cyan
const COLOR_TEAL = '#14b8a6';      // Teal

export default function DdosClassifier({ lastRun, onNavigate, onInspectType }) {
  const report = lastRun;

  // 1. Dynamic or fallback KPI values matching reference UI
  const totalAttacks = report?.anomalies_count || 1326;
  const ddosCount = report?.attacks?.find(a => a.name.includes('DDoS'))?.value || 512;
  const intrusionCount = report?.attacks?.find(a => a.name.includes('Intrusion') || a.name.includes('Injection'))?.value || 389;
  const malwareCount = report?.attacks?.find(a => a.name.includes('Malware'))?.value || 274;
  const bruteForceCount = report?.attacks?.find(a => a.name.includes('Brute') || a.name.includes('SSH'))?.value || 96;
  const otherCount = Math.max(0, totalAttacks - (ddosCount + intrusionCount + malwareCount + bruteForceCount)) || 55;

  // KPI Header Cards Configuration
  const kpiCards = [
    { label: 'Total Attacks', value: totalAttacks.toLocaleString(), sub: '↑ 18.6% vs yesterday', icon: Target, bg: 'bg-rose-500/10 border-rose-500/20 text-rose-500' },
    { label: 'DDoS Attacks', value: ddosCount, sub: `${((ddosCount / totalAttacks) * 100).toFixed(1)}% of total`, icon: Cloud, bg: 'bg-orange-500/10 border-orange-500/20 text-orange-500' },
    { label: 'Intrusion Attempts', value: intrusionCount, sub: `${((intrusionCount / totalAttacks) * 100).toFixed(1)}% of total`, icon: AlertTriangle, bg: 'bg-amber-500/10 border-amber-500/20 text-amber-500' },
    { label: 'Malware Traffic', value: malwareCount, sub: `${((malwareCount / totalAttacks) * 100).toFixed(1)}% of total`, icon: Bug, bg: 'bg-purple-500/10 border-purple-500/20 text-purple-500' },
    { label: 'Brute Force', value: bruteForceCount, sub: `${((bruteForceCount / totalAttacks) * 100).toFixed(1)}% of total`, icon: Lock, bg: 'bg-blue-500/10 border-blue-500/20 text-blue-500' },
    { label: 'Other Attacks', value: otherCount, sub: `${((otherCount / totalAttacks) * 100).toFixed(1)}% of total`, icon: MoreHorizontal, bg: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500' },
  ];

  // 2. Attack Classification Over Time (Multi-Line Chart)
  const timeSeriesData = [
    { time: '00:00', DDoS: 280, Intrusion: 180, Malware: 100, BruteForce: 45, Other: 20 },
    { time: '02:00', DDoS: 310, Intrusion: 210, Malware: 115, BruteForce: 50, Other: 25 },
    { time: '04:00', DDoS: 350, Intrusion: 225, Malware: 125, BruteForce: 55, Other: 30 },
    { time: '06:00', DDoS: 420, Intrusion: 240, Malware: 140, BruteForce: 60, Other: 35 },
    { time: '08:00', DDoS: 380, Intrusion: 220, Malware: 110, BruteForce: 50, Other: 25 },
    { time: '10:00', DDoS: 395, Intrusion: 260, Malware: 135, BruteForce: 55, Other: 30 },
    { time: '12:00', DDoS: 415, Intrusion: 245, Malware: 120, BruteForce: 50, Other: 25 },
    { time: '14:00', DDoS: 390, Intrusion: 235, Malware: 115, BruteForce: 45, Other: 20 },
    { time: '16:00', DDoS: 375, Intrusion: 255, Malware: 130, BruteForce: 55, Other: 30 },
    { time: '18:00', DDoS: 410, Intrusion: 240, Malware: 125, BruteForce: 50, Other: 25 },
    { time: '20:00', DDoS: 425, Intrusion: 270, Malware: 140, BruteForce: 60, Other: 35 },
    { time: '22:00', DDoS: 440, Intrusion: 280, Malware: 145, BruteForce: 65, Other: 40 },
    { time: '24:00', DDoS: 450, Intrusion: 300, Malware: 150, BruteForce: 70, Other: 45 },
  ];

  // 3. Attack Distribution Donut Data
  const typeDonutData = [
    { name: 'DDoS Attacks', value: ddosCount, color: COLOR_CRITICAL, pct: '38.7%' },
    { name: 'Intrusion Attempts', value: intrusionCount, color: COLOR_HIGH, pct: '29.3%' },
    { name: 'Malware Traffic', value: malwareCount, color: COLOR_PURPLE, pct: '20.7%' },
    { name: 'Brute Force', value: bruteForceCount, color: COLOR_BLUE, pct: '7.2%' },
    { name: 'Other Attacks', value: otherCount, color: COLOR_LOW, pct: '4.1%' },
  ];

  // 4. Attack Types Breakdown Bar Data
  const breakdownBarData = [
    { name: 'DDoS (SYN Flood)', value: 218, color: COLOR_CRITICAL },
    { name: 'DDoS (UDP Flood)', value: 164, color: COLOR_HIGH },
    { name: 'DDoS (HTTP Flood)', value: 130, color: COLOR_MEDIUM },
    { name: 'SQL Injection', value: 128, color: COLOR_PURPLE },
    { name: 'XSS Attack', value: 96, color: COLOR_BLUE },
    { name: 'Brute Force (SSH)', value: 64, color: COLOR_CYAN },
    { name: 'Malware (C2 Traffic)', value: 59, color: COLOR_TEAL },
    { name: 'Other', value: 55, color: '#6b7280' },
  ];

  // 5. Top Attacks Table Data
  const topAttacksTable = [
    { id: 1, type: 'DDoS (SYN Flood)', category: 'DDoS', count: 218, pct: '16.4%', trend: 'up', color: COLOR_CRITICAL },
    { id: 2, type: 'DDoS (UDP Flood)', category: 'DDoS', count: 164, pct: '12.4%', trend: 'up', color: COLOR_HIGH },
    { id: 3, type: 'DDoS (HTTP Flood)', category: 'DDoS', count: 130, pct: '9.8%', trend: 'down', color: COLOR_MEDIUM },
    { id: 4, type: 'SQL Injection', category: 'Intrusion', count: 128, pct: '9.7%', trend: 'up', color: COLOR_PURPLE },
    { id: 5, type: 'XSS Attack', category: 'Intrusion', count: 96, pct: '7.2%', trend: 'down', color: COLOR_BLUE },
  ];

  // 6. Recent Classified Attacks Data
  const recentClassified = [
    { time: '16:25:43', type: 'DDoS (SYN Flood)', category: 'DDoS', src: '192.168.1.105', target: '10.0.0.45', severity: 'Critical', bg: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
    { time: '16:22:10', type: 'SQL Injection', category: 'Intrusion', src: '203.0.113.45', target: '10.0.0.12', severity: 'High', bg: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
    { time: '16:19:32', type: 'Malware (C2 Traffic)', category: 'Malware', src: '185.220.101.23', target: '10.0.0.8', severity: 'High', bg: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
    { time: '16:15:09', type: 'DDoS (UDP Flood)', category: 'DDoS', src: '198.51.100.77', target: '10.0.0.45', severity: 'Critical', bg: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
    { time: '16:10:55', type: 'Brute Force (SSH)', category: 'Brute Force', src: '203.0.113.88', target: '10.0.0.22', severity: 'Medium', bg: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
  ];

  // 7. Severity Overview Donut Data
  const severityDonutData = [
    { name: 'Critical', value: 412, color: COLOR_CRITICAL, pct: '31.1%' },
    { name: 'High', value: 518, color: COLOR_HIGH, pct: '39.1%' },
    { name: 'Medium', value: 276, color: COLOR_MEDIUM, pct: '20.8%' },
    { name: 'Low', value: 120, color: COLOR_LOW, pct: '9.0%' },
  ];

  // 8. Detailed Classification Logs Table Data
  const detailedLogs = [
    { time: '16:25:43', type: 'DDoS (SYN Flood)', category: 'DDoS', desc: 'TCP SYN flood attack detected', src: '192.168.1.105', target: '10.0.0.45', proto: 'TCP', pkts: '19.7K', bytes: '3.6 MB', severity: 'Critical', confidence: '98%', bg: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
    { time: '16:22:10', type: 'SQL Injection', category: 'Intrusion', desc: 'SQL injection attempt on login form', src: '203.0.113.45', target: '10.0.0.12', proto: 'HTTP', pkts: '1.2K', bytes: '512 KB', severity: 'High', confidence: '94%', bg: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
    { time: '16:19:32', type: 'Malware (C2 Traffic)', category: 'Malware', desc: 'C2 communication detected', src: '185.220.101.23', target: '10.0.0.8', proto: 'TCP', pkts: '2.8K', bytes: '1.4 MB', severity: 'High', confidence: '92%', bg: 'bg-orange-500/20 text-orange-300 border-orange-500/40' },
    { time: '16:15:09', type: 'DDoS (UDP Flood)', category: 'DDoS', desc: 'UDP flood attack detected', src: '198.51.100.77', target: '10.0.0.45', proto: 'UDP', pkts: '12.7K', bytes: '5.7 MB', severity: 'Critical', confidence: '97%', bg: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
    { time: '16:10:55', type: 'Brute Force (SSH)', category: 'Brute Force', desc: 'SSH brute force login attempt', src: '203.0.113.88', target: '10.0.0.22', proto: 'TCP', pkts: '640', bytes: '220 KB', severity: 'Medium', confidence: '86%', bg: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
  ];

  return (
    <div className="space-y-6">
      {/* Page Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-4">
        <div>
          <h1 className="font-geist text-2xl font-bold text-white">Attack Classifier</h1>
          <p className="text-xs text-gray-400 mt-0.5">Classify and analyze detected attacks in your network</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-cyber-dark/80 border border-white/10 text-xs font-mono text-gray-300">
            <Calendar className="w-4 h-4 text-cyan-400" />
            <span>Last 24 Hours</span>
          </div>
          <div className="p-2 rounded-xl bg-cyber-dark/80 border border-white/10 text-gray-300 hover:text-white transition">
            <Bell className="w-4.5 h-4.5" />
          </div>
          <div className="flex items-center gap-2 px-3 py-1 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono">
            <User className="w-3.5 h-3.5" />
            <span>Admin</span>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────
          ROW 1: 6 TOP SUMMARY KPI CARDS
      ───────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
        {kpiCards.map((c, i) => {
          const IconComponent = c.icon;
          return (
            <div key={i} className="glass-panel p-4 flex items-center justify-between hover:border-white/20 transition group">
              <div>
                <span className="text-[11px] font-semibold text-gray-400 block mb-1">{c.label}</span>
                <span className="font-geist text-2xl font-bold text-white tracking-tight">{c.value}</span>
                <span className="text-[10px] font-mono text-gray-400 block mt-1">{c.sub}</span>
              </div>
              <div className={`p-3 rounded-xl border shrink-0 ${c.bg}`}>
                <IconComponent className="w-5 h-5" />
              </div>
            </div>
          );
        })}
      </div>

      {/* ─────────────────────────────────────────────────────────────────
          ROW 2: 3 GRID CARDS
      ───────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Card 1: Attack Classification Over Time */}
        <div className="glass-panel p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="font-geist text-sm font-bold text-white">Attack Classification Over Time</h3>
            <div className="flex items-center gap-2 text-[10px] font-mono flex-wrap">
              <span className="flex items-center gap-1 text-rose-500"><span className="w-2 h-2 rounded bg-rose-500" /> DDoS</span>
              <span className="flex items-center gap-1 text-orange-500"><span className="w-2 h-2 rounded bg-orange-500" /> Intrusion</span>
              <span className="flex items-center gap-1 text-purple-400"><span className="w-2 h-2 rounded bg-purple-400" /> Malware</span>
              <span className="flex items-center gap-1 text-blue-400"><span className="w-2 h-2 rounded bg-blue-400" /> Brute Force</span>
              <span className="flex items-center gap-1 text-emerald-400"><span className="w-2 h-2 rounded bg-emerald-400" /> Other</span>
            </div>
          </div>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeriesData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="time" stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <YAxis stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                <Line type="monotone" dataKey="DDoS" stroke={COLOR_CRITICAL} strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="Intrusion" stroke={COLOR_HIGH} strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="Malware" stroke={COLOR_PURPLE} strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="BruteForce" stroke={COLOR_BLUE} strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="Other" stroke={COLOR_LOW} strokeWidth={2} dot={{ r: 3 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Card 2: Attack Distribution (By Type) */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="font-geist text-sm font-bold text-white border-b border-white/10 pb-3">Attack Distribution (By Type)</h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
            <div className="h-44 relative flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={typeDonutData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {typeDonutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.5)" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="font-geist text-xl font-bold text-white">{totalAttacks.toLocaleString()}</span>
                <span className="text-[10px] font-mono text-gray-400">Total Attacks</span>
              </div>
            </div>

            <div className="space-y-2 font-mono text-xs">
              {typeDonutData.map((s) => (
                <div key={s.name} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: s.color }} />
                    <span className="text-gray-300 text-[11px]">{s.name}</span>
                  </div>
                  <span className="font-bold text-white text-[11px]">{s.value} <span className="text-gray-500 font-normal">({s.pct})</span></span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Card 3: Attack Types Breakdown */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="font-geist text-sm font-bold text-white border-b border-white/10 pb-3">Attack Types Breakdown</h3>

          <div className="h-56 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={breakdownBarData} layout="vertical" margin={{ top: 5, right: 30, left: 30, bottom: 5 }}>
                <XAxis type="number" stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <YAxis dataKey="name" type="category" stroke="#9ca3af" fontSize={10} fontFamily="Space Mono" width={110} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {breakdownBarData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────
          ROW 3: 3 GRID CARDS
      ───────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Row 3 Card 1: Top Attacks (By Detected Count) */}
        <div className="glass-panel p-5 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="font-geist text-sm font-bold text-white border-b border-white/10 pb-3 mb-3">Top Attacks (By Detected Count)</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead>
                  <tr className="text-[10px] text-gray-400 uppercase border-b border-white/10">
                    <th className="pb-2">#</th>
                    <th className="pb-2">Attack Type</th>
                    <th className="pb-2">Category</th>
                    <th className="pb-2 text-right">Count</th>
                    <th className="pb-2 text-right">Percentage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {topAttacksTable.map((row) => (
                    <tr key={row.id} className="hover:bg-white/5 transition">
                      <td className="py-2.5 text-gray-400">{row.id}</td>
                      <td className="py-2.5 font-bold text-white">{row.type}</td>
                      <td className="py-2.5 text-gray-300">{row.category}</td>
                      <td className="py-2.5 text-right font-bold" style={{ color: row.color }}>{row.count}</td>
                      <td className="py-2.5 text-right text-gray-300">{row.pct}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pt-2 border-t border-white/5 text-right">
            <button className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1 ml-auto cursor-pointer">
              <span>View all attack types</span> <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Row 3 Card 2: Recent Classified Attacks */}
        <div className="glass-panel p-5 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="font-geist text-sm font-bold text-white border-b border-white/10 pb-3 mb-3">Recent Classified Attacks</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead>
                  <tr className="text-[10px] text-gray-400 uppercase border-b border-white/10">
                    <th className="pb-2">Time</th>
                    <th className="pb-2">Attack Type</th>
                    <th className="pb-2">Source IP</th>
                    <th className="pb-2">Target IP</th>
                    <th className="pb-2 text-right">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {recentClassified.map((row, idx) => (
                    <tr key={idx} className="hover:bg-white/5 transition">
                      <td className="py-2.5 text-gray-400">{row.time}</td>
                      <td className="py-2.5 font-bold text-white">{row.type}</td>
                      <td className="py-2.5 text-cyan-300">{row.src}</td>
                      <td className="py-2.5 text-gray-300">{row.target}</td>
                      <td className="py-2.5 text-right">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${row.bg}`}>
                          {row.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pt-2 border-t border-white/5 text-right">
            <button className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1 ml-auto cursor-pointer">
              <span>View all classified attacks</span> <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Row 3 Card 3: Attack Severity Overview */}
        <div className="glass-panel p-5 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="font-geist text-sm font-bold text-white border-b border-white/10 pb-3 mb-3">Attack Severity Overview</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
              <div className="h-44 relative flex items-center justify-center">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityDonutData}
                      cx="50%"
                      cy="50%"
                      innerRadius={45}
                      outerRadius={65}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {severityDonutData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.5)" strokeWidth={2} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                  </PieChart>
                </ResponsiveContainer>
                <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                  <span className="font-geist text-xl font-bold text-white">{totalAttacks.toLocaleString()}</span>
                  <span className="text-[10px] font-mono text-gray-400">Total</span>
                </div>
              </div>

              <div className="space-y-2.5 font-mono text-xs">
                {severityDonutData.map((s) => (
                  <div key={s.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: s.color }} />
                      <span className="text-gray-300">{s.name}</span>
                    </div>
                    <span className="font-bold text-white">{s.value} <span className="text-gray-500 font-normal">({s.pct})</span></span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-white/5 text-right">
            <button className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1 ml-auto cursor-pointer">
              <span>View severity details</span> <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────
          ROW 4: DETAILED CLASSIFICATION LOGS & MODEL PERFORMANCE
      ───────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Left 8 Cols: Attack Classification Details */}
        <div className="lg:col-span-8 glass-panel p-5 space-y-4 flex flex-col justify-between">
          <div>
            <h3 className="font-geist text-sm font-bold text-white border-b border-white/10 pb-3 mb-3">Attack Classification Details</h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead>
                  <tr className="text-[10px] text-gray-400 uppercase border-b border-white/10">
                    <th className="pb-2">Time</th>
                    <th className="pb-2">Attack Type</th>
                    <th className="pb-2">Category</th>
                    <th className="pb-2">Description</th>
                    <th className="pb-2">Source IP</th>
                    <th className="pb-2">Target IP</th>
                    <th className="pb-2">Protocol</th>
                    <th className="pb-2">Packets</th>
                    <th className="pb-2">Bytes</th>
                    <th className="pb-2">Severity</th>
                    <th className="pb-2 text-right">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/5">
                  {detailedLogs.map((row, idx) => (
                    <tr key={idx} className="hover:bg-white/5 transition">
                      <td className="py-2.5 text-gray-400">{row.time}</td>
                      <td className="py-2.5 font-bold text-white">{row.type}</td>
                      <td className="py-2.5 text-gray-300">{row.category}</td>
                      <td className="py-2.5 text-gray-300 max-w-xs truncate">{row.desc}</td>
                      <td className="py-2.5 text-cyan-300">{row.src}</td>
                      <td className="py-2.5 text-gray-300">{row.target}</td>
                      <td className="py-2.5 text-gray-300">{row.proto}</td>
                      <td className="py-2.5 text-gray-300">{row.pkts}</td>
                      <td className="py-2.5 text-gray-300">{row.bytes}</td>
                      <td className="py-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${row.bg}`}>
                          {row.severity}
                        </span>
                      </td>
                      <td className="py-2.5 text-right font-bold text-emerald-400">{row.confidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pt-2 border-t border-white/5 text-right">
            <button className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1 ml-auto cursor-pointer">
              <span>View all classification logs</span> <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Right 4 Cols: Top Attacking Sources & Model Performance */}
        <div className="lg:col-span-4 glass-panel p-5 space-y-6 flex flex-col justify-between">
          <div className="space-y-6">
            {/* Sub-card 1: Top Attacking Sources */}
            <div>
              <h4 className="font-geist text-xs font-bold text-white uppercase tracking-wider border-b border-white/10 pb-2 mb-3">Top Attacking Sources</h4>
              <div className="space-y-2 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">DDoS Attacks</span>
                  <span className="font-bold text-rose-400">512 <span className="text-gray-500 font-normal">(38.7%)</span></span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Intrusion Attempts</span>
                  <span className="font-bold text-orange-400">389 <span className="text-gray-500 font-normal">(29.3%)</span></span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Malware Traffic</span>
                  <span className="font-bold text-amber-400">274 <span className="text-gray-500 font-normal">(20.7%)</span></span>
                </div>
              </div>
            </div>

            {/* Sub-card 2: Model Performance */}
            <div>
              <h4 className="font-geist text-xs font-bold text-white uppercase tracking-wider border-b border-white/10 pb-2 mb-3">Model Performance</h4>
              <div className="grid grid-cols-2 gap-3 font-mono text-xs">
                <div className="p-2.5 rounded-lg bg-white/5 border border-white/10 space-y-1">
                  <span className="text-[10px] text-gray-400 block uppercase">Accuracy</span>
                  <span className="text-base font-bold text-emerald-400">96.2%</span>
                </div>
                <div className="p-2.5 rounded-lg bg-white/5 border border-white/10 space-y-1">
                  <span className="text-[10px] text-gray-400 block uppercase">Precision</span>
                  <span className="text-base font-bold text-cyan-400">95.7%</span>
                </div>
                <div className="p-2.5 rounded-lg bg-white/5 border border-white/10 space-y-1">
                  <span className="text-[10px] text-gray-400 block uppercase">Recall</span>
                  <span className="text-base font-bold text-purple-400">94.9%</span>
                </div>
                <div className="p-2.5 rounded-lg bg-white/5 border border-white/10 space-y-1">
                  <span className="text-[10px] text-gray-400 block uppercase">F1 Score</span>
                  <span className="text-base font-bold text-amber-400">95.3%</span>
                </div>
              </div>
            </div>
          </div>

          <div className="pt-2 border-t border-white/5 text-right">
            <button className="text-xs font-mono text-cyan-400 hover:text-white flex items-center gap-1 ml-auto cursor-pointer">
              <span>View detailed performance</span> <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
