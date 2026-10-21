"use client";

import { useState, useEffect } from "react";
import { Terminal, RefreshCw, AlertTriangle, Info, XCircle } from "lucide-react";

type LogEntry = {
  timestamp: string;
  level: 'info' | 'error' | 'warn';
  message: string;
  data?: any;
};

export default function SystemLogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const res = await fetch("/api/logs");
      if (res.ok) {
        const data = await res.json();
        setLogs(data);
      }
    } catch (error) {
      console.error("Failed to fetch logs", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000); // Poll every 5s
    return () => clearInterval(interval);
  }, []);

  const getIcon = (level: string) => {
    switch (level) {
      case 'error': return <XCircle className="w-4 h-4 text-red-500" />;
      case 'warn': return <AlertTriangle className="w-4 h-4 text-amber-500" />;
      default: return <Info className="w-4 h-4 text-blue-500" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white flex items-center gap-2">
            <Terminal className="w-8 h-8 text-[#00E5FF]" />
            Tempo Real: Ingestão de Telemetria
          </h1>
          <p className="text-gray-400 mt-2">
            Monitoramento em tempo real do processador central.
          </p>
        </div>
        <button 
          onClick={fetchLogs}
          className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Atualizar Agora
        </button>
      </div>

      <div className="border border-slate-800 bg-slate-900/50 backdrop-blur-sm rounded-lg shadow-sm">
        <div className="p-6 border-b border-slate-800">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            Output do Servidor (Últimos 200 eventos)
          </h3>
        </div>
        <div className="p-6">
          <div className="bg-black rounded-lg p-4 font-mono text-sm overflow-y-auto h-[600px] border border-slate-800 shadow-inner">
            {logs.length === 0 ? (
              <div className="text-gray-500 flex flex-col items-center justify-center h-full">
                <Terminal className="w-12 h-12 mb-4 opacity-20" />
                Nenhum log registrado ainda... aguardando conexões dos agentes.
              </div>
            ) : (
              <div className="space-y-3">
                {logs.map((log, i) => (
                  <div key={i} className="flex flex-col border-b border-slate-800/50 pb-2">
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">{getIcon(log.level)}</div>
                      <div className="flex-1">
                        <div className="flex items-center gap-2 text-xs">
                          <span className="text-slate-500">{new Date(log.timestamp).toLocaleTimeString()}</span>
                          <span className={`font-bold uppercase ${log.level === 'error' ? 'text-red-400' : log.level === 'warn' ? 'text-amber-400' : 'text-blue-400'}`}>
                            {log.level}
                          </span>
                        </div>
                        <div className={`mt-1 ${log.level === 'error' ? 'text-red-200' : 'text-slate-300'}`}>
                          {log.message}
                        </div>
                        {log.data && (
                          <pre className="mt-2 bg-slate-950 p-2 rounded text-xs text-slate-400 overflow-x-auto max-w-[800px]">
                            {JSON.stringify(log.data, null, 2)}
                          </pre>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
