/**
 * VextHub Fleet Threat Clustering & Batch Synthesis Engine
 * Groups threat signals across units and software names to detect mass outbreaks and unit-wide risk spikes.
 */

export interface UnitThreatCluster {
  unit: string;
  totalMachines: number;
  unauthorizedCount: number;
  activeAlertsCount: number;
  outbreakSeverity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  topThreatSoftware: string[];
  affectedHostnames: string[];
  summary: string;
}

export function buildFleetThreatClusters(
  unitStats: Array<{
    name: string;
    machineCount: number;
    unauthorizedApps: number;
    activeAlerts: number;
    riskScore: number;
    violatingDevices?: Array<{ hostname: string; badApps: string[] }>;
  }>
): UnitThreatCluster[] {
  if (!unitStats || unitStats.length === 0) return [];

  return unitStats
    .map((unit) => {
      const violating = unit.violatingDevices || [];
      const affectedHostnames = Array.from(new Set(violating.map((v) => v.hostname)));
      
      const appCounts: Record<string, number> = {};
      violating.forEach((v) => {
        (v.badApps || []).forEach((app) => {
          appCounts[app] = (appCounts[app] || 0) + 1;
        });
      });

      const topThreatSoftware = Object.entries(appCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([app]) => app);

      let outbreakSeverity: UnitThreatCluster['outbreakSeverity'] = 'LOW';
      if (unit.riskScore >= 75 || unit.unauthorizedApps >= 8) {
        outbreakSeverity = 'CRITICAL';
      } else if (unit.riskScore >= 50 || unit.unauthorizedApps >= 4) {
        outbreakSeverity = 'HIGH';
      } else if (unit.riskScore >= 25 || unit.unauthorizedApps >= 2) {
        outbreakSeverity = 'MEDIUM';
      }

      const summary = outbreakSeverity === 'CRITICAL' || outbreakSeverity === 'HIGH'
        ? `Surto tático detectado na unidade ${unit.name}: ${unit.unauthorizedApps} aplicações irregulares em ${affectedHostnames.length} endpoints.`
        : `Unidade ${unit.name} operando com nível de risco ${unit.riskScore}%.`;

      return {
        unit: unit.name,
        totalMachines: unit.machineCount,
        unauthorizedCount: unit.unauthorizedApps,
        activeAlertsCount: unit.activeAlerts,
        outbreakSeverity,
        topThreatSoftware,
        affectedHostnames: affectedHostnames.slice(0, 10),
        summary,
      };
    })
    .filter((cluster) => cluster.unauthorizedCount > 0 || cluster.activeAlertsCount > 0)
    .sort((a, b) => (b.outbreakSeverity === 'CRITICAL' ? 4 : b.outbreakSeverity === 'HIGH' ? 3 : 2) - (a.outbreakSeverity === 'CRITICAL' ? 4 : a.outbreakSeverity === 'HIGH' ? 3 : 2));
}
