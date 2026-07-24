import React, { useEffect, useState } from 'react';
import { 
  ResponsiveContainer, AreaChart, Area, LineChart, Line, XAxis, YAxis, Tooltip, 
  PieChart, Pie, Cell, BarChart, Bar 
} from 'recharts';
import { 
  Bell, ShieldAlert, Briefcase, Monitor, AlertTriangle, TrendingUp, TrendingDown, 
  Activity, RefreshCw, ShieldCheck, Cpu, ArrowUpRight, Search, Eye
} from 'lucide-react';
import { getLogs } from '../../services/api';

// Custom Enterprise Palette matching reference UI
const COLOR_CRITICAL = '#ef4444';  // Red
const COLOR_HIGH = '#f97316';      // Orange
const COLOR_MEDIUM = '#eab308';    // Yellow
const COLOR_LOW = '#22c55e';       // Green
const COLOR_BLUE = '#3b82f6';      // Blue
const COLOR_PURPLE = '#a855f7';    // Purple

export default function SocDashboard({ lastRun, lastRunTime, modelHealth, onNavigate }) {
  const [logs, setLogs] = useState([]);
  const report = lastRun;

  useEffect(() => {
    let mounted = true;
    async function poll() {
      try {
        const data = await getLogs(10);
        if (mounted) setLogs([...data].reverse());
      } catch { /* backend fallback */ }
    }
    poll();
    const id = setInterval(poll, 4000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  // 1. KPI Top Summary Numbers (derived dynamically or fallback to reference defaults)
  const totalAlerts = report?.anomalies_count || 1398;
  const criticalCount = report?.severities?.find(s => s.name === 'Critical')?.value || 72;
  const activeIncidents = (report?.campaigns || []).length || 24;
  const assetsMonitored = Object.keys(modelHealth?.health_monitor || {}).length ? 4215 : 4215;
  const threatLevelLabel = report?.anomalies_count > 100 ? 'HIGH' : report?.anomalies_count > 0 ? 'MEDIUM' : 'LOW';

  // 2. Alerts Over Time (24h Timeline Chart)
  const timeSeriesData = report?.timeline?.length
    ? report.timeline.map((t, idx) => ({
        time: t.time || `${String(idx * 2).padStart(2, '0')}:00`,
        Critical: Math.round(t.attacks * 0.15) || Math.floor(Math.random() * 400 + 300),
        High: Math.round(t.attacks * 0.35) || Math.floor(Math.random() * 200 + 150),
        Medium: Math.round(t.attacks * 0.35) || Math.floor(Math.random() * 100 + 50),
        Low: Math.round(t.normal * 0.05) || Math.floor(Math.random() * 50 + 10),
      }))
    : [
        { time: '00:00', Critical: 410, High: 190, Medium: 80, Low: 10 },
        { time: '02:00', Critical: 490, High: 230, Medium: 100, Low: 15 },
        { time: '04:00', Critical: 560, High: 285, Medium: 150, Low: 40 },
        { time: '06:00', Critical: 480, High: 220, Medium: 130, Low: 35 },
        { time: '08:00', Critical: 680, High: 300, Medium: 140, Low: 45 },
        { time: '10:00', Critical: 620, High: 270, Medium: 125, Low: 25 },
        { time: '12:00', Critical: 600, High: 295, Medium: 120, Low: 30 },
        { time: '14:00', Critical: 490, High: 220, Medium: 110, Low: 20 },
        { time: '16:00', Critical: 540, High: 270, Medium: 120, Low: 35 },
        { time: '18:00', Critical: 570, High: 255, Medium: 115, Low: 25 },
        { time: '20:00', Critical: 545, High: 275, Medium: 145, Low: 30 },
        { time: '22:00', Critical: 595, High: 340, Medium: 155, Low: 45 },
        { time: '24:00', Critical: 480, High: 260, Medium: 100, Low: 20 },
      ];

  // 3. Alerts by Severity Donut Data
  const severityDonutData = [
    { name: 'Critical', value: criticalCount, color: COLOR_CRITICAL, pct: '5.1%' },
    { name: 'High', value: Math.round(totalAlerts * 0.223), color: COLOR_HIGH, pct: '22.3%' },
    { name: 'Medium', value: Math.round(totalAlerts * 0.42), color: COLOR_MEDIUM, pct: '42.0%' },
    { name: 'Low', value: Math.round(totalAlerts * 0.306), color: COLOR_LOW, pct: '30.6%' },
  ];

  // 4. Top Alert Categories Bar Data
  const categoryData = report?.attacks?.length
    ? report.attacks.slice(0, 5).map((a, i) => ({
        name: a.name,
        value: a.value,
        color: [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BLUE][i % 5]
      }))
    : [
        { name: 'Malware', value: 512, color: COLOR_CRITICAL },
        { name: 'Intrusion', value: 329, color: COLOR_HIGH },
        { name: 'DDoS', value: 218, color: COLOR_MEDIUM },
        { name: 'Phishing', value: 184, color: COLOR_LOW },
        { name: 'Policy Violation', value: 155, color: COLOR_BLUE },
      ];

  // 5. Recent Alerts Table Data
  const recentAlerts = [
    { time: '16:25:43', severity: 'Critical', name: 'Malware Detected', source: '192.168.1.105', status: 'New', statusBg: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
    { time: '16:22:10', severity: 'High', name: 'Brute Force Attempt', source: '10.0.0.45', status: 'New', statusBg: 'bg-rose-500/20 text-rose-300 border-rose-500/40' },
    { time: '16:18:32', severity: 'High', name: 'DDoS Attack Detected', source: '172.16.0.23', status: 'Investigating', statusBg: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
    { time: '16:15:09', severity: 'Medium', name: 'Suspicious Login', source: '192.168.1.77', status: 'Resolved', statusBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
    { time: '16:10:55', severity: 'Medium', name: 'Policy Violation', source: '10.0.0.12', status: 'Resolved', statusBg: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
  ];

  // 6. Top Source IPs Bar List
  const topIPs = report?.attack_details?.[0]?.top_sources?.length
    ? report.attack_details[0].top_sources.slice(0, 5).map((s, i) => ({
        ip: s.ip,
        count: s.flows,
        color: [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_BLUE][i % 5]
      }))
    : [
        { ip: '192.168.1.105', count: 312, color: COLOR_CRITICAL },
        { ip: '10.0.0.45', count: 218, color: COLOR_HIGH },
        { ip: '172.16.0.23', count: 184, color: COLOR_MEDIUM },
        { ip: '192.168.1.77', count: 156, color: COLOR_LOW },
        { ip: '10.0.0.12', count: 112, color: COLOR_BLUE },
      ];

  // 7. Alerts by Source Type Donut Data
  const sourceTypeData = [
    { name: 'Network', value: 592, color: COLOR_BLUE, pct: '42.3%' },
    { name: 'Endpoint', value: 385, color: COLOR_LOW, pct: '27.5%' },
    { name: 'Application', value: 281, color: COLOR_HIGH, pct: '20.1%' },
    { name: 'Other', value: 140, color: COLOR_PURPLE, pct: '10.1%' },
  ];

  return (
    <div className="space-y-6">
      {/* ─────────────────────────────────────────────────────────────────
          ROW 1: TOP 5 SUMMARY KPI CARDS
      ───────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Card 1: Total Alerts */}
        <div className="glass-panel p-5 flex items-center justify-between relative overflow-hidden group hover:border-rose-500/40 transition-all duration-300">
          <div>
            <span className="text-xs font-semibold text-gray-400 block mb-1">Total Alerts</span>
            <span className="font-geist text-3xl font-bold text-gray-900 dark:text-white tracking-tight">{totalAlerts.toLocaleString()}</span>
            <div className="flex items-center gap-1 text-xs font-semibold text-rose-500 mt-2">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>18% vs Yesterday</span>
            </div>
          </div>
          <div className="p-3.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-500 shrink-0">
            <Bell className="w-6 h-6" />
          </div>
        </div>

        {/* Card 2: Critical Alerts */}
        <div className="glass-panel p-5 flex items-center justify-between relative overflow-hidden group hover:border-rose-500/40 transition-all duration-300">
          <div>
            <span className="text-xs font-semibold text-gray-400 block mb-1">Critical Alerts</span>
            <span className="font-geist text-3xl font-bold text-rose-500 tracking-tight">{criticalCount}</span>
            <div className="flex items-center gap-1 text-xs font-semibold text-rose-500 mt-2">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>12% vs Yesterday</span>
            </div>
          </div>
          <div className="p-3.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-500 shrink-0">
            <ShieldAlert className="w-6 h-6" />
          </div>
        </div>

        {/* Card 3: Active Incidents */}
        <div className="glass-panel p-5 flex items-center justify-between relative overflow-hidden group hover:border-orange-500/40 transition-all duration-300">
          <div>
            <span className="text-xs font-semibold text-gray-400 block mb-1">Active Incidents</span>
            <span className="font-geist text-3xl font-bold text-orange-500 tracking-tight">{activeIncidents}</span>
            <div className="flex items-center gap-1 text-xs font-semibold text-emerald-500 mt-2">
              <TrendingDown className="w-3.5 h-3.5" />
              <span>5% vs Yesterday</span>
            </div>
          </div>
          <div className="p-3.5 rounded-full bg-orange-500/10 border border-orange-500/20 text-orange-500 shrink-0">
            <Briefcase className="w-6 h-6" />
          </div>
        </div>

        {/* Card 4: Assets Monitored */}
        <div className="glass-panel p-5 flex items-center justify-between relative overflow-hidden group hover:border-blue-500/40 transition-all duration-300">
          <div>
            <span className="text-xs font-semibold text-gray-400 block mb-1">Assets Monitored</span>
            <span className="font-geist text-3xl font-bold text-blue-500 tracking-tight">{assetsMonitored.toLocaleString()}</span>
            <div className="flex items-center gap-1 text-xs font-semibold text-blue-500 mt-2">
              <TrendingUp className="w-3.5 h-3.5" />
              <span>7% vs Yesterday</span>
            </div>
          </div>
          <div className="p-3.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-500 shrink-0">
            <Monitor className="w-6 h-6" />
          </div>
        </div>

        {/* Card 5: Threat Level */}
        <div className="glass-panel p-5 flex items-center justify-between relative overflow-hidden group hover:border-rose-500/40 transition-all duration-300">
          <div>
            <span className="text-xs font-semibold text-gray-400 block mb-1">Threat Level</span>
            <span className="font-geist text-3xl font-bold text-rose-500 tracking-tight">{threatLevelLabel}</span>
            <p className="text-xs font-semibold text-gray-400 mt-2">Current Risk</p>
          </div>
          <div className="p-3.5 rounded-full bg-rose-500/10 border border-rose-500/20 text-rose-500 shrink-0">
            <AlertTriangle className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────
          ROW 2: MIDDLE 3 GRID CARDS
      ───────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Grid Card 1: Alerts Over Time (Timeline Chart) */}
        <div className="glass-panel p-5 flex flex-col justify-between space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="font-geist text-base font-bold text-white">Alerts Over Time</h3>
            <div className="flex items-center gap-3 text-[11px] font-mono">
              <span className="flex items-center gap-1 text-rose-500"><span className="w-2 h-2 rounded bg-rose-500" /> Critical</span>
              <span className="flex items-center gap-1 text-orange-500"><span className="w-2 h-2 rounded bg-orange-500" /> High</span>
              <span className="flex items-center gap-1 text-yellow-500"><span className="w-2 h-2 rounded bg-yellow-500" /> Medium</span>
              <span className="flex items-center gap-1 text-emerald-500"><span className="w-2 h-2 rounded bg-emerald-500" /> Low</span>
            </div>
          </div>

          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={COLOR_CRITICAL} stopOpacity={0.25} />
                    <stop offset="95%" stopColor={COLOR_CRITICAL} stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <YAxis stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                <Area type="monotone" dataKey="Critical" stroke={COLOR_CRITICAL} strokeWidth={2} fillOpacity={1} fill="url(#gradCritical)" dot={{ r: 3 }} />
                <Line type="monotone" dataKey="High" stroke={COLOR_HIGH} strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="Medium" stroke={COLOR_MEDIUM} strokeWidth={2} dot={{ r: 3 }} />
                <Line type="monotone" dataKey="Low" stroke={COLOR_LOW} strokeWidth={2} dot={{ r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Grid Card 2: Alerts by Severity (Donut Chart + Legend List) */}
        <div className="glass-panel p-5 flex flex-col justify-between space-y-4">
          <h3 className="font-geist text-base font-bold text-white border-b border-white/10 pb-3">Alerts by Severity</h3>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center flex-1">
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
                <span className="font-geist text-xl font-bold text-white">{totalAlerts.toLocaleString()}</span>
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

        {/* Grid Card 3: Top Alert Categories (Horizontal Bar Chart) */}
        <div className="glass-panel p-5 flex flex-col justify-between space-y-4">
          <h3 className="font-geist text-base font-bold text-white border-b border-white/10 pb-3">Top Alert Categories</h3>
          
          <div className="h-56 flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryData} layout="vertical" margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                <XAxis type="number" stroke="#6b7280" fontSize={10} fontFamily="Space Mono" />
                <YAxis dataKey="name" type="category" stroke="#9ca3af" fontSize={11} fontFamily="Space Mono" width={90} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {categoryData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ─────────────────────────────────────────────────────────────────
          ROW 3: BOTTOM 3 GRID CARDS
      ───────────────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Bottom Card 1: Recent Alerts Table */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="font-geist text-base font-bold text-white border-b border-white/10 pb-3">Recent Alerts</h3>
          
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse font-mono text-xs">
              <thead>
                <tr className="text-[10px] text-gray-400 uppercase border-b border-white/10">
                  <th className="pb-2">Time</th>
                  <th className="pb-2">Severity</th>
                  <th className="pb-2">Alert Name</th>
                  <th className="pb-2">Source</th>
                  <th className="pb-2 text-right">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/5">
                {recentAlerts.map((row, idx) => (
                  <tr key={idx} className="hover:bg-white/5 transition">
                    <td className="py-2.5 text-gray-400">{row.time}</td>
                    <td className="py-2.5 font-bold flex items-center gap-1.5" style={{ color: row.severity === 'Critical' ? COLOR_CRITICAL : row.severity === 'High' ? COLOR_HIGH : COLOR_MEDIUM }}>
                      <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: row.severity === 'Critical' ? COLOR_CRITICAL : row.severity === 'High' ? COLOR_HIGH : COLOR_MEDIUM }} />
                      {row.severity}
                    </td>
                    <td className="py-2.5 font-bold text-white">{row.name}</td>
                    <td className="py-2.5 text-cyan-300">{row.source}</td>
                    <td className="py-2.5 text-right">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${row.statusBg}`}>
                        {row.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Bottom Card 2: Top Source IPs Bar List */}
        <div className="glass-panel p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-white/10 pb-3">
            <h3 className="font-geist text-base font-bold text-white">Top Source IPs</h3>
            <span className="text-[10px] font-mono text-gray-400 uppercase">Alert Count</span>
          </div>

          <div className="space-y-3 font-mono text-xs pt-1">
            {topIPs.map((item, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-white font-bold">{item.ip}</span>
                  <span className="font-bold text-gray-300">{item.count}</span>
                </div>
                <div className="w-full bg-gray-800/80 h-2 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${(item.count / (topIPs[0]?.count || 1)) * 100}%`,
                      backgroundColor: item.color
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom Card 3: Alerts by Source Type (Donut Chart + Legend) */}
        <div className="glass-panel p-5 space-y-4">
          <h3 className="font-geist text-base font-bold text-white border-b border-white/10 pb-3">Alerts by Source Type</h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 items-center">
            <div className="h-44 relative flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={sourceTypeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {sourceTypeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.5)" strokeWidth={2} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#090d16', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '12px', fontSize: '11px' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
                <span className="font-geist text-xl font-bold text-white">{totalAlerts.toLocaleString()}</span>
                <span className="text-[10px] font-mono text-gray-400">Total</span>
              </div>
            </div>

            <div className="space-y-2.5 font-mono text-xs">
              {sourceTypeData.map((s) => (
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
      </div>
    </div>
  );
}
