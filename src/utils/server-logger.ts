type LogEntry = {
  timestamp: string;
  level: 'info' | 'error' | 'warn';
  message: string;
  data?: any;
};

const globalForLogger = globalThis as unknown as {
  _systemLogs: LogEntry[];
};

if (!globalForLogger._systemLogs) {
  globalForLogger._systemLogs = [];
}

export const systemLogs = globalForLogger._systemLogs;

export function addLog(level: 'info' | 'error' | 'warn', message: string, data?: any) {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    data
  };
  
  systemLogs.unshift(entry);
  
  if (systemLogs.length > 200) {
    systemLogs.pop();
  }

  if (level === 'error') {
    console.error(message, data || '');
  } else if (level === 'warn') {
    console.warn(message, data || '');
  } else {
    console.log(message, data || '');
  }
}
