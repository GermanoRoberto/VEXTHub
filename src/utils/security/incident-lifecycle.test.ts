import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  SLA_TARGETS_HOURS,
  GRC_STANDARDS,
  INCIDENT_WORKFLOW_STAGES,
  getNextStatus,
  canTransition,
  calculateSlaStatus,
  advanceIncidentStatus,
  calculateBlastRadius,
  mapToGrcControls,
  calculateIncidentMetrics,
  createIncidentFromAlert,
  type SecurityIncident,
  type MachineForBlastRadius,
} from './incident-lifecycle';

describe('Incident Lifecycle - SLA Targets & Status Transitions', () => {
  it('defines exact SLA targets for all severity tiers', () => {
    assert.equal(SLA_TARGETS_HOURS.critical, 1);
    assert.equal(SLA_TARGETS_HOURS.high, 4);
    assert.equal(SLA_TARGETS_HOURS.medium, 24);
    assert.equal(SLA_TARGETS_HOURS.low, 72);
  });

  it('progresses through standard workflow: TRIAGE -> CONTAINMENT -> ERADICATION -> RECOVERED', () => {
    assert.deepEqual(INCIDENT_WORKFLOW_STAGES, ['TRIAGE', 'CONTAINMENT', 'ERADICATION', 'RECOVERED']);
    assert.equal(getNextStatus('TRIAGE'), 'CONTAINMENT');
    assert.equal(getNextStatus('CONTAINMENT'), 'ERADICATION');
    assert.equal(getNextStatus('ERADICATION'), 'RECOVERED');
    assert.equal(getNextStatus('RECOVERED'), null);
  });

  it('validates permitted and prohibited transitions with canTransition', () => {
    assert.equal(canTransition('TRIAGE', 'CONTAINMENT'), true);
    assert.equal(canTransition('CONTAINMENT', 'ERADICATION'), true);
    assert.equal(canTransition('ERADICATION', 'RECOVERED'), true);
    assert.equal(canTransition('TRIAGE', 'RECOVERED'), true); // Fast-track resolution
    assert.equal(canTransition('RECOVERED', 'CONTAINMENT'), true); // Re-infection containment
    assert.equal(canTransition('CONTAINMENT', 'TRIAGE'), false); // Regressing to triage is prohibited
    assert.equal(canTransition('TRIAGE', 'TRIAGE'), false); // No self transition
  });

  it('calculates SLA deadline, remaining minutes and breach status accurately', () => {
    const referenceNow = new Date('2026-10-21T12:00:00.000Z');

    // 1. Critical created 15 minutes ago -> 45 minutes remaining -> within_sla
    const criticalCreated = new Date('2026-10-21T11:45:00.000Z').toISOString();
    const critSla = calculateSlaStatus(criticalCreated, 'critical', undefined, referenceNow);
    assert.equal(critSla.slaTargetHours, 1);
    assert.equal(critSla.remainingMinutes, 45);
    assert.equal(critSla.slaStatus, 'within_sla');

    // 2. Critical created 50 minutes ago -> 10 minutes remaining -> warning (< 30 min)
    const critNearBreach = new Date('2026-10-21T11:10:00.000Z').toISOString();
    const warnSla = calculateSlaStatus(critNearBreach, 'critical', undefined, referenceNow);
    assert.equal(warnSla.remainingMinutes, 10);
    assert.equal(warnSla.slaStatus, 'warning');

    // 3. Critical created 75 minutes ago -> -15 minutes -> breached
    const critBreached = new Date('2026-10-21T10:45:00.000Z').toISOString();
    const breachedSla = calculateSlaStatus(critBreached, 'critical', undefined, referenceNow);
    assert.equal(breachedSla.remainingMinutes, -15);
    assert.equal(breachedSla.slaStatus, 'breached');

    // 4. Incident resolved before deadline
    const highCreated = new Date('2026-10-21T08:00:00.000Z').toISOString();
    const resolvedWithin = new Date('2026-10-21T10:00:00.000Z').toISOString(); // 2h < 4h
    const resolvedSla = calculateSlaStatus(highCreated, 'high', resolvedWithin, referenceNow);
    assert.equal(resolvedSla.slaStatus, 'within_sla');
    assert.ok(resolvedSla.remainingMinutes > 0);
  });

  it('advances incident status and records stage transition timestamps', () => {
    const initial: SecurityIncident = {
      id: 'inc-01',
      machine_id: 'm-01',
      hostname: 'PC-FINANCEIRO',
      unit: 'Filial Sul',
      title: 'Malware alert',
      description: 'Suspicious process detected',
      severity: 'critical',
      status: 'TRIAGE',
      created_at: '2026-10-21T10:00:00.000Z',
      updated_at: '2026-10-21T10:00:00.000Z',
      sla_target_hours: 1,
      sla_deadline: '2026-10-21T11:00:00.000Z',
      sla_status: 'within_sla',
      remaining_minutes: 60,
      blast_radius: {
        vector_type: 'process',
        vector_identifier: 'mimikatz.exe',
        same_unit_count: 0,
        total_fleet_count: 0,
        affected_peers: [],
        risk_multiplier: 1.0,
        recommendation: 'Isolated',
      },
      grc_controls: [],
    };

    // Advance to CONTAINMENT
    const contained = advanceIncidentStatus(initial, 'CONTAINMENT', '2026-10-21T10:20:00.000Z');
    assert.equal(contained.status, 'CONTAINMENT');
    assert.equal(contained.contained_at, '2026-10-21T10:20:00.000Z');

    // Advance to ERADICATION
    const eradicated = advanceIncidentStatus(contained, 'ERADICATION', '2026-10-21T10:35:00.000Z');
    assert.equal(eradicated.status, 'ERADICATION');
    assert.equal(eradicated.eradicated_at, '2026-10-21T10:35:00.000Z');

    // Advance to RECOVERED
    const recovered = advanceIncidentStatus(eradicated, 'RECOVERED', '2026-10-21T10:50:00.000Z');
    assert.equal(recovered.status, 'RECOVERED');
    assert.equal(recovered.recovered_at, '2026-10-21T10:50:00.000Z');
    assert.equal(recovered.sla_status, 'within_sla');
  });
});

describe('Blast Radius Calculation Engine', () => {
  const mockFleet: MachineForBlastRadius[] = [
    {
      id: 'm-target',
      hostname: 'SRV-TARGET',
      unit: 'Matriz',
      inventory_data: {
        installed_programs: [{ name: 'WinRAR 6.22' }, { name: 'Chrome 120' }],
        listening_ports: [{ local_port: 3389 }, { local_port: 8080 }],
        running_processes: [{ name: 'powershell.exe', command_line: 'powershell -enc AAAA' }],
        security_analysis: {
          findings: [{ id: 'CVE-2023-38831', title: 'WinRAR RCE CVE-2023-38831' }],
        },
      },
    },
    {
      id: 'm-peer-unit',
      hostname: 'PC-MATRIZ-01',
      unit: 'Matriz',
      inventory_data: {
        installed_programs: [{ name: 'WinRAR 6.22' }, { name: 'Office 365' }],
        listening_ports: [{ local_port: 3389 }],
        running_processes: [{ name: 'powershell.exe' }],
        security_analysis: {
          findings: [{ id: 'CVE-2023-38831', title: 'WinRAR RCE CVE-2023-38831' }],
        },
      },
    },
    {
      id: 'm-peer-branch',
      hostname: 'PC-FILIAL-01',
      unit: 'Filial SP',
      inventory_data: {
        installed_programs: [{ name: 'WinRAR 6.22' }],
        listening_ports: [{ local_port: 445 }],
        running_processes: [{ name: 'cmd.exe' }],
      },
    },
    {
      id: 'm-peer-branch-2',
      hostname: 'PC-FILIAL-02',
      unit: 'Filial RJ',
      inventory_data: {
        installed_programs: [{ name: '7-Zip 23.01' }],
        listening_ports: [{ local_port: 3389 }],
        running_processes: [{ name: 'powershell.exe', command_line: 'powershell -enc AAAA' }],
      },
    },
    {
      id: 'm-clean',
      hostname: 'PC-CLEAN',
      unit: 'Filial PR',
      inventory_data: {
        installed_programs: [{ name: 'Firefox' }],
        listening_ports: [{ local_port: 443 }],
        running_processes: [{ name: 'explorer.exe' }],
      },
    },
  ];

  it('matches software vector across unit and fleet peers', () => {
    const result = calculateBlastRadius(
      'm-target',
      { type: 'software', identifier: 'WinRAR' },
      mockFleet
    );

    assert.equal(result.vector_type, 'software');
    assert.equal(result.vector_identifier, 'WinRAR');
    assert.equal(result.same_unit_count, 1); // PC-MATRIZ-01
    assert.equal(result.total_fleet_count, 2); // PC-MATRIZ-01 + PC-FILIAL-01
    assert.equal(result.affected_peers.length, 2);
    assert.ok(result.risk_multiplier > 1.0);
    assert.ok(result.recommendation.includes('ALERTA DE PROPAGAÇÃO'));
  });

  it('matches listening port vector across fleet', () => {
    const result = calculateBlastRadius(
      'm-target',
      { type: 'port', identifier: '3389' },
      mockFleet
    );

    assert.equal(result.same_unit_count, 1); // PC-MATRIZ-01
    assert.equal(result.total_fleet_count, 2); // PC-MATRIZ-01 + PC-FILIAL-02
    assert.ok(result.affected_peers.some((p) => p.hostname === 'PC-FILIAL-02'));
  });

  it('matches process name and command-line vectors', () => {
    const result = calculateBlastRadius(
      'm-target',
      { type: 'process', identifier: 'powershell' },
      mockFleet
    );

    assert.equal(result.total_fleet_count, 2); // PC-MATRIZ-01 and PC-FILIAL-02
  });

  it('matches CVE vector in security analysis findings', () => {
    const result = calculateBlastRadius(
      'm-target',
      { type: 'cve', identifier: 'CVE-2023-38831' },
      mockFleet
    );

    assert.equal(result.same_unit_count, 1);
    assert.ok(result.total_fleet_count >= 1);
    assert.ok(result.affected_peers.some((p) => p.hostname === 'PC-MATRIZ-01'));
  });

  it('returns isolated result when vector has zero fleet peers', () => {
    const result = calculateBlastRadius(
      'm-target',
      { type: 'port', identifier: '9999' },
      mockFleet
    );

    assert.equal(result.same_unit_count, 0);
    assert.equal(result.total_fleet_count, 0);
    assert.equal(result.risk_multiplier, 1.0);
    assert.ok(result.recommendation.includes('isolado no host alvo'));
  });
});

describe('GRC Compliance Catalog & Mapping', () => {
  it('contains complete catalog for ISO 27001, LGPD and CIS Controls v8', () => {
    // ISO 27001
    assert.equal(GRC_STANDARDS.ISO_A_8_8.code, 'A.8.8');
    assert.equal(GRC_STANDARDS.ISO_A_8_16.code, 'A.8.16');
    assert.equal(GRC_STANDARDS.ISO_A_8_15.code, 'A.8.15');
    assert.equal(GRC_STANDARDS.ISO_A_5_24.code, 'A.5.24');

    // LGPD
    assert.equal(GRC_STANDARDS.LGPD_ART_46.code, 'Art. 46');
    assert.equal(GRC_STANDARDS.LGPD_ART_48.code, 'Art. 48');

    // CIS Controls v8
    assert.equal(GRC_STANDARDS.CIS_CONTROL_7.code, 'Control 7');
    assert.equal(GRC_STANDARDS.CIS_CONTROL_8.code, 'Control 8');
    assert.equal(GRC_STANDARDS.CIS_CONTROL_17.code, 'Control 17');
  });

  it('maps vulnerability context to ISO A.8.8 and CIS Control 7', () => {
    const controls = mapToGrcControls({
      vectorType: 'cve',
      findingTitle: 'WinRAR Remote Code Execution CVE-2023-38831',
      severity: 'high',
    });

    const codes = controls.map((c) => c.code);
    assert.ok(codes.includes('A.8.8'));
    assert.ok(codes.includes('Control 7'));
    assert.ok(codes.includes('A.8.16')); // Monitoring
    assert.ok(codes.includes('Art. 46')); // LGPD Security
  });

  it('maps critical breach path to mandatory LGPD Art. 48 notification', () => {
    const controls = mapToGrcControls({
      severity: 'critical',
      findingTitle: 'Mimikatz Credential Exfiltration Attack Path',
      isIncident: true,
    });

    const codes = controls.map((c) => c.code);
    assert.ok(codes.includes('Art. 48')); // Mandatory incident communication
    assert.ok(codes.includes('A.5.24')); // ISO Incident Management
    assert.ok(codes.includes('Control 17')); // CIS Incident Response
  });
});

describe('SOC Efficiency Metrics & Aggregations', () => {
  it('calculates MTTD, MTTR, SLA compliance rate and stage distributions', () => {
    const incidents: SecurityIncident[] = [
      {
        id: 'inc-1',
        machine_id: 'm1',
        hostname: 'HOST-01',
        unit: 'SP',
        title: 'Inc 1',
        description: 'Triage',
        severity: 'critical',
        status: 'TRIAGE',
        created_at: '2026-10-21T10:00:00.000Z',
        updated_at: '2026-10-21T10:00:00.000Z',
        sla_target_hours: 1,
        sla_deadline: '2026-10-21T11:00:00.000Z',
        sla_status: 'within_sla',
        remaining_minutes: 30,
        blast_radius: {
          vector_type: 'software',
          vector_identifier: '7-Zip',
          same_unit_count: 1,
          total_fleet_count: 3,
          affected_peers: [],
          risk_multiplier: 1.45,
          recommendation: '',
        },
        grc_controls: [],
      },
      {
        id: 'inc-2',
        machine_id: 'm2',
        hostname: 'HOST-02',
        unit: 'SP',
        title: 'Inc 2',
        description: 'Contained',
        severity: 'high',
        status: 'CONTAINMENT',
        created_at: '2026-10-21T08:00:00.000Z',
        updated_at: '2026-10-21T08:30:00.000Z',
        contained_at: '2026-10-21T08:30:00.000Z', // MTTD = 30 min
        sla_target_hours: 4,
        sla_deadline: '2026-10-21T12:00:00.000Z',
        sla_status: 'within_sla',
        remaining_minutes: 120,
        blast_radius: {
          vector_type: 'port',
          vector_identifier: '445',
          same_unit_count: 0,
          total_fleet_count: 1,
          affected_peers: [],
          risk_multiplier: 1.15,
          recommendation: '',
        },
        grc_controls: [],
      },
      {
        id: 'inc-3',
        machine_id: 'm3',
        hostname: 'HOST-03',
        unit: 'RJ',
        title: 'Inc 3',
        description: 'Recovered',
        severity: 'medium',
        status: 'RECOVERED',
        created_at: '2026-10-20T10:00:00.000Z',
        updated_at: '2026-10-20T11:00:00.000Z',
        contained_at: '2026-10-20T10:15:00.000Z', // MTTD = 15 min
        recovered_at: '2026-10-20T11:00:00.000Z', // MTTR = 60 min
        sla_target_hours: 24,
        sla_deadline: '2026-10-21T10:00:00.000Z',
        sla_status: 'within_sla',
        remaining_minutes: 1380,
        blast_radius: {
          vector_type: 'process',
          vector_identifier: 'test.exe',
          same_unit_count: 0,
          total_fleet_count: 0,
          affected_peers: [],
          risk_multiplier: 1.0,
          recommendation: '',
        },
        grc_controls: [],
      },
    ];

    const metrics = calculateIncidentMetrics(incidents);

    assert.equal(metrics.total_incidents, 3);
    assert.equal(metrics.active_triage, 1);
    assert.equal(metrics.in_containment, 1);
    assert.equal(metrics.in_eradication, 0);
    assert.equal(metrics.recovered, 1);
    // MTTD: (30 + 15) / 2 = 22.5 -> 23 minutes (or 22/23 depending on rounding)
    assert.ok(metrics.mttd_minutes >= 22 && metrics.mttd_minutes <= 23);
    // MTTR: 60 / 1 = 60 minutes
    assert.equal(metrics.mttr_minutes, 60);
    // SLA compliance: 3/3 = 100%
    assert.equal(metrics.sla_compliance_rate, 100);
    // Average blast radius: (3 + 1 + 0) / 3 = 1.3
    assert.equal(metrics.avg_blast_radius, 1.3);
  });

  it('handles empty incident lists safely without dividing by zero', () => {
    const emptyMetrics = calculateIncidentMetrics([]);
    assert.equal(emptyMetrics.total_incidents, 0);
    assert.equal(emptyMetrics.mttd_minutes, 0);
    assert.equal(emptyMetrics.mttr_minutes, 0);
    assert.equal(emptyMetrics.sla_compliance_rate, 100);
    assert.equal(emptyMetrics.avg_blast_radius, 0);
  });
});

describe('Incident Factory & Adapter Helpers', () => {
  it('creates full SecurityIncident from telemetry alert and fleet context', () => {
    const incident = createIncidentFromAlert(
      {
        id: 'alt-42',
        hostname: 'PC-SEC-01',
        unit: 'Brasília',
        software_name: 'CVE-2024-31497 PuTTY ECDSA Nonce Leak',
        message: 'Detectada vulnerabilidade crítica de assinatura em cliente SSH.',
        severity: 'critical',
      },
      [
        {
          id: 'alt-42',
          hostname: 'PC-SEC-01',
          unit: 'Brasília',
        },
      ]
    );

    assert.equal(incident.id, 'inc-alt-42');
    assert.equal(incident.severity, 'critical');
    assert.equal(incident.sla_target_hours, 1);
    assert.equal(incident.status, 'TRIAGE');
    assert.equal(incident.blast_radius.vector_type, 'cve');
    assert.ok(incident.grc_controls.some((c) => c.code === 'A.8.8'));
    assert.ok(incident.grc_controls.some((c) => c.code === 'Art. 46'));
  });
});
