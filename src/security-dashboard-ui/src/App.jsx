import { useEffect, useMemo, useState } from "react";
import {BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer} from "recharts";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000"


const sampleEvents = () => {
  const now = new Date();
  const iso = (m) => new Date(now.getTime() - m * 60000).toISOString();
  return[
    {id: 'evt-1', source: "ids", asset_id: "srv-1", serverity: "critical", category:"network", timestamp: iso(1)},
    {id: 'evt-2', source: "auth", asset_id: "srv-2", serverity: "medium", category:"auth", timestamp: iso(2), failed_attempts: 6},
    { id: "evt-3", source: "auth", asset_id: "srv-2", serverity: "high", category: "auth", timestamp: iso(3), failed_attempts: 8 },
    { id: "evt-4", source: "ids", asset_id: "srv-2", serverity: "low", category: "network", timestamp: iso(4) },
  ];
};

export default function App(){
  const [events, setEvents] = useState(sampleEvents());
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(" ");

  const runPipeline = async () => {
    setLoading(true); setError(" ");
    try {
      const res = await fetch(`${API_BASE}/run-pipeline`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(events),
      });
      if(!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setResult(data);
    } catch (e){
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const addEvent = () => {
    setEvents((evts) => ([...evts, {
      id: `evt-${evts.length + 1}`,
      asset_id: "srv-1",
      severity: "medium",
      category: "auth",
      timestamp: new Date().toISOStirng(),
      source: "auth", 
    }]));
  };

  const removeEvent = (idx) => {
    setEvents((evts) => evts.filter((_, i) => i != idx));
  };

  const updateEvent = (idx, field, value) => {
    setEvents((evts) => evts.map((e, i) => i == idx ? {...e, [field]: value} :e));
  };

  const severityChartData = useMemo(() => {
    if (!result) return [];
    const assets = result?.report?.find(r => r.type === "event-summary")?.findings?.assets || {};
    return Object.entries(assets).map(([asset, info]) => ({asset, ...info.serverities}));

  }, [result]);

  return (
    <div className="max-w-6xl mx-auto p-6 space-y-6">
      <h1 className="text-2xl font-bold">Security Dashboard — UI MVP</h1>
  
      <section className="bg-white rounded-2xl shadow p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-semibold">Events</h2>
          <div className="space-x-2">
            <button onClick={addEvent} className="px-3 py-1 rounded bg-gray-100 hover:bg-gray-200">+ Add</button>
            <button onClick={() => setEvents(sampleEvents())} className="px-3 py-1 rounded bg-gray-100 hover:bg-gray-200">Reset Sample</button>
            <button onClick={runPipeline} disabled={loading} className="px-3 py-1 rounded bg-black text-white disabled:opacity-50">{loading ? "Running..." : "Run Pipeline"}</button>
          </div>
        </div>
        {error && <div className="text-red-600 text-sm mb-2">{error}</div>}
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="py-2">id</th>
                <th>asset_id</th>
                <th>severity</th>
                <th>category</th>
                <th>timestamp</th>
                <th>source</th>
                <th>failed_attempts</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {events.map((e, idx) => (
                <tr key={idx} className="border-b last:border-0">
                  <td className="py-1 pr-2"><input className="w-28" value={e.id} onChange={ev => updateEvent(idx, "id", ev.target.value)} /></td>
                  <td className="pr-2"><input className="w-20" value={e.asset_id} onChange={ev => updateEvent(idx, "asset_id", ev.target.value)} /></td>
                  <td className="pr-2">
                    <select className="w-28" value={e.severity} onChange={ev => updateEvent(idx, "severity", ev.target.value)}>
                      <option>low</option>
                      <option>medium</option>
                      <option>high</option>
                      <option>critical</option>
                    </select>
                  </td>
                  <td className="pr-2">
                    <select className="w-28" value={e.category} onChange={ev => updateEvent(idx, "category", ev.target.value)}>
                      <option>network</option>
                      <option>auth</option>
                      <option>system</option>
                    </select>
                  </td>
                  <td className="pr-2"><input className="w-64" value={e.timestamp} onChange={ev => updateEvent(idx, "timestamp", ev.target.value)} /></td>
                  <td className="pr-2"><input className="w-24" value={e.source || ""} onChange={ev => updateEvent(idx, "source", ev.target.value)} /></td>
                  <td className="pr-2"><input className="w-16" value={e.failed_attempts ?? ""} onChange={ev => updateEvent(idx, "failed_attempts", ev.target.value ? Number(ev.target.value) : undefined)} /></td>
                  <td><button onClick={() => removeEvent(idx)} className="px-2 py-1 text-red-600">삭제</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

        {result && (
          <>
            <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white rounded-2xl shadow p-4">
                <h2 className= "font-semibold mb-3">Alerts</h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thred>
                      <tr className="text-left border-b">
                        <th className="py-2">id</th>
                        <th>rule</th>
                        <th>severity</th>
                        <th>events</th>
                      </tr>
                    </thred>
                    <tbody>
                    {result.alerts?.map((a, i) => (
                      <tr key={i} className="border-b last:border-0">
                        <td className="py-1 pr-2">{a.id}</td>
                        <td className="pr-2">{a.rule_id}</td>
                        <td className="pr-2">{a.severity}</td>
                        <td className="pr-2">{a.event_ids?.join(", ")}</td>
                      </tr>
                    ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="bg-white rounded-2xl shadow p-4">
                <h2 className="font-semibold mb-3">incidents</h2>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left border-b">
                        <th className="py-2">id</th>
                        <th>priority</th>
                        <th>assignee</th>
                        <th>resolution</th>
                        <th>alerts</th>
                      </tr>
                    </thead>
                    <tbody>
                    {result.incidents?.map((inc, i) => (
                      <tr key={i} className="border-b last:border-0">
                        <td className="py-1 pr-2">{inc.id}</td>
                        <td className="pr-2">{inc.priority}</td>
                        <td className="pr-2">{inc.assignee || "-"}</td>
                        <td className="pr-2">{inc.resolution || "-"}</td>
                        <td className="pr-2">{Array.from(inc.alert_ids || []).join(",")}</td>
                      </tr>
                    ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>

            <section className="bg-white rounded-2xl shadow p-4">
              <h2 className="font-semibold mb-3">Event Summary</h2>
              <div className="h-72">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityChartData}>
                    <XAxis dataKey="asset" />
                    <YAxis />
                    <Legend />
                    <Bar dataKey="low" stackId="sev" />
                    <Bar dataKey="medium" stackId="sev"/>
                    <Bar dataKey="high" stackId="sev"/>
                    <Bar dataKey="critical" stackId="sev"/>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </section>
            <section className="bg-white rounded-2xl shadow p-4">
              <h2 className="font-semibold mb-3">Executed Actions</h2>
              <ul className="list-disc pl-6">
                {result.executed_actions?.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </section>
          </>
        )}
      </div>
      );
}
