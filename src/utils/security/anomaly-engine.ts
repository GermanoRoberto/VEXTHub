/**
 * VextHub Statistical Anomaly Detection Engine
 * Computes Z-Score statistical deviations (Z = (X - μ) / σ) for endpoint telemetry metrics.
 */

export interface MetricSample {
  cpu: number;
  ram: number;
  disk: number;
  unauthorizedAppsCount?: number;
  activeAlertsCount?: number;
}

export interface EndpointAnomalyResult {
  hostname: string;
  unit: string;
  isAnomalous: boolean;
  maxZScore: number;
  anomalies: Array<{
    metric: string;
    value: number;
    mean: number;
    stdDev: number;
    zScore: number;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
  }>;
}

export function calculateStats(values: number[]): { mean: number; stdDev: number } {
  if (values.length === 0) return { mean: 0, stdDev: 1 };
  
  const mean = values.reduce((sum, v) => sum + v, 0) / values.length;
  const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
  const stdDev = Math.sqrt(variance) || 1; // Prevent division by zero

  return { mean, stdDev };
}

export function computeZScore(value: number, mean: number, stdDev: number): number {
  return (value - mean) / (stdDev || 1);
}

export function detectEndpointAnomalies(
  machines: Array<{
    hostname?: string | null;
    unit?: string | null;
    telemetry?: { cpu?: number; ram?: number; disk?: number } | null;
    inventory_data?: any;
  }>
): EndpointAnomalyResult[] {
  if (!machines || machines.length === 0) return [];

  // 1. Collect population baseline metrics
  const cpus = machines.map((m) => Number(m.telemetry?.cpu || 0));
  const rams = machines.map((m) => Number(m.telemetry?.ram || 0));
  const disks = machines.map((m) => Number(m.telemetry?.disk || 0));

  const cpuStats = calculateStats(cpus);
  const ramStats = calculateStats(rams);
  const diskStats = calculateStats(disks);

  // 2. Evaluate Z-scores per machine
  return machines.map((machine) => {
    const hostname = String(machine.hostname || "Unknown-Host");
    const unit = String(machine.unit || "Sem Unidade");
    const cpu = Number(machine.telemetry?.cpu || 0);
    const ram = Number(machine.telemetry?.ram || 0);
    const disk = Number(machine.telemetry?.disk || 0);

    const cpuZ = computeZScore(cpu, cpuStats.mean, cpuStats.stdDev);
    const ramZ = computeZScore(ram, ramStats.mean, ramStats.stdDev);
    const diskZ = computeZScore(disk, diskStats.mean, diskStats.stdDev);

    const anomalies: EndpointAnomalyResult["anomalies"] = [];

    if (Math.abs(cpuZ) >= 2.2) {
      const severity = Math.abs(cpuZ) >= 3.0 ? "CRITICAL" : "HIGH";
      anomalies.push({
        metric: "CPU Usage",
        value: cpu,
        mean: Math.round(cpuStats.mean),
        stdDev: Number(cpuStats.stdDev.toFixed(1)),
        zScore: Number(cpuZ.toFixed(2)),
        severity,
        description: `Pico anômalo de processamento (${cpu}% vs média populacional ${Math.round(cpuStats.mean)}%, Z-Score: ${cpuZ.toFixed(2)})`,
      });
    }

    if (Math.abs(ramZ) >= 2.2) {
      const severity = Math.abs(ramZ) >= 3.0 ? "HIGH" : "MEDIUM";
      anomalies.push({
        metric: "RAM Usage",
        value: ram,
        mean: Math.round(ramStats.mean),
        stdDev: Number(ramStats.stdDev.toFixed(1)),
        zScore: Number(ramZ.toFixed(2)),
        severity,
        description: `Desvio de consumo de memória RAM (${ram}% vs média populacional ${Math.round(ramStats.mean)}%, Z-Score: ${ramZ.toFixed(2)})`,
      });
    }

    if (Math.abs(diskZ) >= 2.5) {
      anomalies.push({
        metric: "Disk Usage",
        value: disk,
        mean: Math.round(diskStats.mean),
        stdDev: Number(diskStats.stdDev.toFixed(1)),
        zScore: Number(diskZ.toFixed(2)),
        severity: "MEDIUM",
        description: `Anomalia de ocupação de disco (${disk}% vs média populacional ${Math.round(diskStats.mean)}%, Z-Score: ${diskZ.toFixed(2)})`,
      });
    }

    const maxZ = Math.max(0, ...anomalies.map((a) => Math.abs(a.zScore)));

    return {
      hostname,
      unit,
      isAnomalous: anomalies.length > 0,
      maxZScore: Number(maxZ.toFixed(2)),
      anomalies,
    };
  }).filter((res) => res.isAnomalous);
}
