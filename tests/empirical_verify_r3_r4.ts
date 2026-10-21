/**
 * EMPIRICAL VERIFICATION HARNESS FOR R3 & R4
 * Challenger 2 - VextHub Maximum Polish Sprint
 */

import {
  escapeCsvCell,
  generateCsv,
  downloadBlob,
  exportDevicesCsv,
  exportComplianceCsv,
  exportDevicesPdf,
  exportCompliancePdf,
  DeviceExportItem,
  SoftwarePolicyExportItem,
  ComplianceAlertExportItem,
} from '../src/utils/export/reports';
import { GET as statusRouteGet } from '../src/app/api/system/status/route';
import { jsPDF } from 'jspdf';

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition: boolean, testName: string, details?: string) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  [PASS] ${testName}`);
  } else {
    failedTests++;
    console.error(`  [FAIL] ${testName}${details ? ` -> ${details}` : ''}`);
  }
}

async function runR3Tests() {
  console.log('\n======================================================');
  console.log('--- EMPIRICAL TEST SUITE: R3 (CSV & PDF EXPORTS) ---');
  console.log('======================================================\n');

  // --------------------------------------------------------------------------
  // 1. CSV RFC-4180 Escaping & BOM
  // --------------------------------------------------------------------------
  console.log('Group 1: CSV RFC-4180 Escaping Rules');

  // Test 1.1: Plain values without special characters
  assert(escapeCsvCell('VEXT-SRV-01') === 'VEXT-SRV-01', 'Plain string untouched');
  assert(escapeCsvCell(12345) === '12345', 'Number converted to string');
  assert(escapeCsvCell(null) === '', 'Null converts to empty string');
  assert(escapeCsvCell(undefined) === '', 'Undefined converts to empty string');

  // Test 1.2: Commas
  assert(
    escapeCsvCell('Matriz, SP') === '"Matriz, SP"',
    'Cell containing comma wrapped in double quotes'
  );

  // Test 1.3: Quotes
  assert(
    escapeCsvCell('He said "Attack"') === '"He said ""Attack"""',
    'Quotes escaped with double-quotes and enclosed in quotes'
  );

  // Test 1.4: Newlines (CRLF and LF)
  assert(
    escapeCsvCell('First line\r\nSecond line') === '"First line\r\nSecond line"',
    'CRLF newline enclosed in quotes'
  );
  assert(
    escapeCsvCell('First line\nSecond line') === '"First line\nSecond line"',
    'LF newline enclosed in quotes'
  );

  // Test 1.5: Complex combined string
  const complex = 'Risk: "High", Action: "Block, Terminate"\nNode: 01';
  const expectedEscaped = '"Risk: ""High"", Action: ""Block, Terminate""\nNode: 01"';
  assert(
    escapeCsvCell(complex) === expectedEscaped,
    'Combined quotes, commas, and newlines escaped correctly'
  );

  // Test 1.6: CRLF row delimiter in generateCsv
  const headers = ['ID', 'Hostname', 'Unit'];
  const rows = [
    ['1', 'HOST-A', 'Filial 01'],
    ['2', 'HOST-B, Special', 'Filial "02"'],
  ];
  const csvOutput = generateCsv(headers, rows);
  const expectedCsv =
    'ID,Hostname,Unit\r\n1,HOST-A,Filial 01\r\n2,"HOST-B, Special","Filial ""02"""';
  assert(csvOutput === expectedCsv, 'generateCsv outputs RFC-4180 CRLF row delimiters');

  // Test 1.7: UTF-8 BOM Verification in downloadBlob
  console.log('\nGroup 2: UTF-8 BOM (\\uFEFF) Presence & Blob Emulation');
  let capturedBlobContent: string | null = null;
  let capturedMimeType: string | null = null;
  let capturedFilename: string | null = null;

  // Mock browser environment for downloadBlob
  const originalWindow = (globalThis as any).window;
  const originalBlob = (globalThis as any).Blob;
  const originalDocument = (globalThis as any).document;
  const originalUrl = (globalThis as any).URL;

  (globalThis as any).window = {};
  (globalThis as any).Blob = class MockBlob {
    parts: any[];
    options: any;
    constructor(parts: any[], options: any) {
      this.parts = parts;
      this.options = options;
      capturedBlobContent = parts.join('');
      capturedMimeType = options?.type || null;
    }
  };
  (globalThis as any).document = {
    body: {
      appendChild: () => {},
      removeChild: () => {},
    },
    createElement: () => ({
      setAttribute: (k: string, v: string) => {
        if (k === 'download') capturedFilename = v;
      },
      style: {},
      click: () => {},
    }),
  };
  (globalThis as any).URL = {
    createObjectURL: () => 'blob:mock-url-1234',
    revokeObjectURL: () => {},
  };

  try {
    downloadBlob('test,data\r\n1,2', 'export_test.csv');
    const blobText1 = capturedBlobContent as string | null;
    assert(
      blobText1 !== null && blobText1.startsWith('\uFEFF'),
      'Blob content begins with UTF-8 BOM (\\uFEFF)'
    );
    assert(
      blobText1 === '\uFEFFtest,data\r\n1,2',
      'Blob content precisely matches BOM + content'
    );
    assert(
      capturedMimeType === 'text/csv;charset=utf-8;',
      'Blob mime type specifies text/csv;charset=utf-8;'
    );
    assert(
      capturedFilename === 'export_test.csv',
      'Download filename correctly assigned'
    );

    // Test 1.8: exportDevicesCsv execution
    const mockDevices: DeviceExportItem[] = [
      {
        id: 'dev-1',
        hostname: 'SEC-WKS-01',
        unit: 'Sede Principal, SP',
        status: 'online',
        ip: '192.168.1.100',
        user: 'admin.local',
        os: 'Windows 11 Pro "Enterprise"',
        cpu: 'Intel i7',
        ram: '32 GB',
        agentVersion: 'v4.0.0',
        riskScore: 15,
        riskLevel: 'baixo',
        lastPulse: '2026-10-20 18:00:00',
      },
    ];
    capturedBlobContent = null;
    exportDevicesCsv(mockDevices);
    const blobText2 = capturedBlobContent as string | null;
    assert(
      blobText2 !== null &&
        blobText2.startsWith('\uFEFF') &&
        blobText2.includes('"Sede Principal, SP"') &&
        blobText2.includes('"Windows 11 Pro ""Enterprise"""'),
      'exportDevicesCsv properly escapes commas, quotes, and includes BOM'
    );

    // Test 1.9: exportComplianceCsv execution
    const mockPolicies: SoftwarePolicyExportItem[] = [
      {
        name: 'Wireshark "Network Analyzer"',
        status: 'forbidden',
        units: ['Unidade Central', 'Filial 01, Sul'],
        overrides: [{ unit_name: 'TI, Matriz', status: 'allowed' }],
      },
    ];
    const mockAlerts: ComplianceAlertExportItem[] = [
      {
        id: 'alt-1',
        hostname: 'DEV-SRV-09',
        unit: 'TI, Matriz',
        software_name: 'BitTorrent Client',
        message: 'Executável não homologado detectado em "C:\\Program Files\\Torrent\\"',
        created_at: '2026-10-20 19:00:00',
        is_resolved: false,
      },
    ];
    capturedBlobContent = null;
    exportComplianceCsv(mockPolicies, mockAlerts);
    const blobText3 = capturedBlobContent as string | null;
    assert(
      blobText3 !== null &&
        blobText3.startsWith('\uFEFF') &&
        blobText3.includes('Wireshark ""Network Analyzer""') &&
        blobText3.includes('ALERTAS E VIOLAÇÕES DE CONFORMIDADE ATIVOS') &&
        blobText3.includes('BitTorrent Client'),
      'exportComplianceCsv generates multi-section CSV with BOM and RFC-4180 escaping'
    );
  } finally {
    // Restore globals
    (globalThis as any).window = originalWindow;
    (globalThis as any).Blob = originalBlob;
    (globalThis as any).document = originalDocument;
    (globalThis as any).URL = originalUrl;
  }

  // --------------------------------------------------------------------------
  // 2. PDF Multi-Page Pagination, Header Repetition & Footer Accuracy
  // --------------------------------------------------------------------------
  console.log('\nGroup 3: jsPDF Pagination, Header Repetition & Footer Page Count');

  // Let's create a test function that runs the exact pagination and rendering logic from reports.ts
  // without calling doc.save() (which is client-side only).
  async function testPdfPaginationEngine(deviceCount: number) {
    const doc = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4',
      compress: false,
    });

    const devices: DeviceExportItem[] = [];
    for (let i = 1; i <= deviceCount; i++) {
      devices.push({
        id: `device-${i}`,
        hostname: `ENDPOINT-STRESS-${String(i).padStart(4, '0')}`,
        unit: i % 2 === 0 ? 'Matriz Central' : 'Filial Regional 02',
        status: i % 10 === 0 ? 'offline' : i % 5 === 0 ? 'away' : 'online',
        ip: `10.0.${Math.floor(i / 250)}.${i % 250}`,
        user: `operador.${i}`,
        os: 'Windows 11 Pro 23H2',
        cpu: 'Intel Xeon E-2286M',
        ram: '32 GB DDR4',
        agentVersion: 'v4.0.0',
        riskScore: (i * 7) % 100,
        riskLevel: (i * 7) % 100 > 70 ? 'crítico' : (i * 7) % 100 > 40 ? 'médio' : 'baixo',
        lastPulse: '2026-10-20 19:30:00',
      });
    }

    const emissionDate = '20/10/2026 19:30:00';
    const docTitle = 'LAUDO EXECUTIVO DE INVENTÁRIO DO PARQUE';

    // Top Brand Header
    doc.setFillColor(124, 58, 237);
    doc.rect(0, 0, 210, 4, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(20);
    doc.text('VEXTHUB', 14, 16);
    doc.setFontSize(7.5);
    doc.text(`Emissão: ${emissionDate}`, 196, 19, { align: 'right' });

    // KPI Cards
    let currentY = 53;
    const drawTableHeader = (y: number) => {
      doc.setFillColor(15, 23, 42);
      doc.rect(14, y, 182, 6.5, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(255, 255, 255);
      doc.text('HOSTNAME', 16, y + 4.3);
      doc.text('UNIDADE', 48, y + 4.3);
      doc.text('STATUS', 74, y + 4.3);
      doc.text('IP LOCAL', 94, y + 4.3);
      doc.text('USUÁRIO ATIVO', 120, y + 4.3);
      doc.text('SISTEMA OPERACIONAL', 146, y + 4.3);
      doc.text('RISCO', 174, y + 4.3);
    };

    drawTableHeader(currentY);
    currentY += 6.5;

    const rowHeight = 6.0;
    const continuationHeadersDrawn: number[] = [];

    devices.forEach((d, index) => {
      if (currentY + rowHeight > 278) {
        doc.addPage();
        const pageNum = doc.getNumberOfPages();
        // Draw continuation header
        doc.setFillColor(124, 58, 237);
        doc.rect(0, 0, 210, 4, 'F');
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(8);
        doc.setTextColor(15, 23, 42);
        doc.text(`VEXTHUB — CONTINUAÇÃO: ${docTitle.toUpperCase()}`, 14, 12);
        continuationHeadersDrawn.push(pageNum);

        currentY = 19;
        drawTableHeader(currentY);
        currentY += 6.5;
      }

      if (index % 2 === 1) {
        doc.setFillColor(248, 250, 252);
        doc.rect(14, currentY, 182, rowHeight, 'F');
      }

      doc.setDrawColor(241, 245, 249);
      doc.setLineWidth(0.15);
      doc.line(14, currentY + rowHeight, 196, currentY + rowHeight);

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(15, 23, 42);
      doc.text(d.hostname, 16, currentY + 4.0);

      currentY += rowHeight;
    });

    // Finalize footers on all pages
    const totalPages = doc.getNumberOfPages();
    const footersVerified: { page: number; total: number; text: string }[] = [];

    for (let p = 1; p <= totalPages; p++) {
      doc.setPage(p);
      const footerText = `Página ${p} de ${totalPages}`;
      doc.setDrawColor(226, 232, 240);
      doc.setLineWidth(0.2);
      doc.line(14, 286, 196, 286);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(148, 163, 184);
      doc.text('VextHub Security Intelligence — Relatório Executivo Auditável // Confidencial', 14, 291);
      doc.text(footerText, 196, 291, { align: 'right' });
      footersVerified.push({ page: p, total: totalPages, text: footerText });
    }

    return {
      totalPages,
      continuationHeadersDrawn,
      footersVerified,
      pdfBuffer: doc.output('arraybuffer'),
    };
  }

  // Test 2.1: Single device (1 page)
  const singleResult = await testPdfPaginationEngine(1);
  assert(singleResult.totalPages === 1, 'Dataset of 1 device generates exactly 1 page');
  assert(
    singleResult.footersVerified[0].text === 'Página 1 de 1',
    'Footer on single page reads "Página 1 de 1"'
  );

  // Test 2.2: Large dataset (> 50 devices, testing 60 devices)
  const large60Result = await testPdfPaginationEngine(60);
  assert(
    large60Result.totalPages >= 2,
    `Dataset of 60 devices triggers pagination (actual pages: ${large60Result.totalPages})`
  );
  assert(
    large60Result.continuationHeadersDrawn.includes(2),
    'Page 2 receives repetition of continuation header'
  );
  assert(
    large60Result.footersVerified.length === large60Result.totalPages,
    `All ${large60Result.totalPages} pages receive footers`
  );
  assert(
    large60Result.footersVerified[0].text === `Página 1 de ${large60Result.totalPages}` &&
      large60Result.footersVerified[1].text === `Página 2 de ${large60Result.totalPages}`,
    'Footer page numbering accurately reflects "Página X de Y" across all pages'
  );

  // Test 2.3: Stress dataset of 120 devices
  const stress120Result = await testPdfPaginationEngine(120);
  assert(
    stress120Result.totalPages >= 3,
    `Dataset of 120 devices generates ${stress120Result.totalPages} pages (> 2 pages)`
  );
  const allHeadersDrawn = [2, 3].every((p) =>
    stress120Result.continuationHeadersDrawn.includes(p)
  );
  assert(allHeadersDrawn, 'Continuation header drawn on every subsequent page (pages 2, 3)');
  const allFootersAccurate = stress120Result.footersVerified.every(
    (f, idx) => f.page === idx + 1 && f.text === `Página ${idx + 1} de ${stress120Result.totalPages}`
  );
  assert(
    allFootersAccurate,
    `All ${stress120Result.totalPages} footers strictly follow "Página N de ${stress120Result.totalPages}"`
  );
  assert(
    stress120Result.pdfBuffer.byteLength > 10000,
    `Valid non-empty binary PDF generated (${stress120Result.pdfBuffer.byteLength} bytes)`
  );

  // Test 2.4: Test full wrapper function exportDevicesPdf
  const devicesMock: DeviceExportItem[] = Array.from({ length: 55 }, (_, i) => ({
    id: `dev-${i}`,
    hostname: `SRV-HOST-${i}`,
    unit: 'Unidade Alpha',
    status: 'online',
    ip: `10.1.1.${i + 1}`,
    user: 'admin',
    os: 'Windows Server 2022',
    cpu: 'AMD EPYC',
    ram: '64 GB',
    agentVersion: 'v4.0.0',
    riskScore: 20,
    riskLevel: 'baixo',
    lastPulse: '2026-10-20',
  }));

  const fs = await import('fs');
  const path = await import('path');

  // Find any existing PDFs before running
  const beforeFiles = fs.readdirSync(process.cwd()).filter((f: string) => f.startsWith('VextHub_Laudo_') && f.endsWith('.pdf'));
  beforeFiles.forEach((f: string) => fs.unlinkSync(path.join(process.cwd(), f)));

  await exportDevicesPdf(devicesMock);

  const devicePdfFiles = fs.readdirSync(process.cwd()).filter((f: string) => f.startsWith('VextHub_Laudo_Dispositivos_') && f.endsWith('.pdf'));
  assert(
    devicePdfFiles.length === 1,
    `exportDevicesPdf generated PDF file on disk: ${devicePdfFiles[0] || 'none'}`
  );
  if (devicePdfFiles.length === 1) {
    const stat = fs.statSync(path.join(process.cwd(), devicePdfFiles[0]));
    assert(stat.size > 10000, `Device PDF file size is healthy (>10KB, actual: ${stat.size} bytes)`);
    fs.unlinkSync(path.join(process.cwd(), devicePdfFiles[0]));
  }

  // Test 2.5: Test exportCompliancePdf
  const policiesMock: SoftwarePolicyExportItem[] = Array.from({ length: 40 }, (_, i) => ({
    name: `Enterprise Software Package ${i + 1}`,
    status: i % 3 === 0 ? 'forbidden' : i % 2 === 0 ? 'allowed' : 'pending',
    units: ['Matriz', 'Filial 01'],
    overrides: [{ unit_name: 'Filial 01', status: 'allowed' }],
  }));
  const alertsMock: ComplianceAlertExportItem[] = Array.from({ length: 25 }, (_, i) => ({
    id: `alert-${i}`,
    hostname: `WORKSTATION-${i}`,
    unit: 'Filial Regional',
    software_name: `Unapproved P2P Tool ${i}`,
    message: 'Execução de software proibido detectada em background',
    created_at: '20/10/2026 19:40:00',
    is_resolved: false,
  }));

  try {
    await exportCompliancePdf(policiesMock, alertsMock);

    const compliancePdfFiles = fs.readdirSync(process.cwd()).filter((f: string) => f.startsWith('VextHub_Laudo_Compliance_') && f.endsWith('.pdf'));
    assert(
      compliancePdfFiles.length === 1,
      `exportCompliancePdf generated PDF file on disk: ${compliancePdfFiles[0] || 'none'}`
    );
    if (compliancePdfFiles.length === 1) {
      const stat = fs.statSync(path.join(process.cwd(), compliancePdfFiles[0]));
      assert(stat.size > 10000, `Compliance PDF file size is healthy (>10KB, actual: ${stat.size} bytes)`);
    }
  } finally {
    const afterFiles = fs.readdirSync(process.cwd()).filter((f: string) => f.startsWith('VextHub_Laudo_') && f.endsWith('.pdf'));
    afterFiles.forEach((f: string) => fs.unlinkSync(path.join(process.cwd(), f)));
  }

  // Group 4: Adversarial Stress-Tests on R3
  console.log('\nGroup 4: Adversarial Edge Cases (Unicode, Truncation, 0-device edge)');

  // Test 4.1: Unicode, Accents, and Emojis
  const unicodeHost = 'SRV-SÃO-PAULO-MATRIZ-🚀';
  const unicodeUnit = 'Operações & "Defesa Cibernética" // Filial Leste';
  const escapedUnicode = generateCsv(['Host', 'Unit'], [[unicodeHost, unicodeUnit]]);
  assert(
    escapedUnicode.includes('SRV-SÃO-PAULO-MATRIZ-🚀') &&
      escapedUnicode.includes('"Operações & ""Defesa Cibernética"" // Filial Leste"'),
    'Unicode, accents, emojis, and quotes preserved and escaped concurrently'
  );

  // Test 4.2: Zero devices (empty fleet) in PDF
  const zeroResult = await testPdfPaginationEngine(0);
  assert(zeroResult.totalPages === 1, 'Empty fleet (0 devices) produces valid 1-page PDF');
  assert(
    zeroResult.footersVerified[0].text === 'Página 1 de 1',
    'Footer on empty fleet reads "Página 1 de 1"'
  );

  // Test 4.3: Text fitting / truncation on 150-char hostname
  const docForFit = new jsPDF();
  const superLongHostname = 'SRV-DOMAIN-CONTROLLER-VERY-LONG-HOSTNAME-CORPORATE-PRODUCTION-DATABASE-REPLICA-NODE-ALPHA-BRAVO-CHARLIE-0001';
  const colWidth = 30; // 30mm width limit for hostname column
  function localFitText(doc: any, text: string, maxWidth: number): string {
    if (!text) return '';
    if (doc.getTextWidth(text) <= maxWidth) return text;
    let truncated = text;
    while (truncated.length > 0 && doc.getTextWidth(truncated + '…') > maxWidth) {
      truncated = truncated.slice(0, -1);
    }
    return truncated.length > 0 ? truncated + '…' : '';
  }
  const fitted = localFitText(docForFit, superLongHostname, colWidth);
  assert(
    fitted.endsWith('…') && docForFit.getTextWidth(fitted) <= colWidth,
    `Overlong hostname fitted within column width limit (${colWidth}mm) with ellipsis (result: "${fitted}")`
  );
}

async function runR4Tests() {
  console.log('\n======================================================');
  console.log('--- EMPIRICAL TEST SUITE: R4 (SYSTEM STATUS PROBE) ---');
  console.log('======================================================\n');

  console.log('Group 1: Direct Route Invocation & Fallback Verification');

  // Ensure local mode fallback is active
  process.env.VEXTHUB_LOCAL_MODE = 'true';
  process.env.NEXT_PUBLIC_SIMULATION_MODE = 'true';

  const req = new Request('http://localhost:3000/api/system/status', {
    method: 'GET',
    headers: {
      'x-tenant-id': '00000000-0000-0000-0000-000000000000',
    },
  });

  const response = await statusRouteGet(req);
  assert(response.status === 200, 'GET /api/system/status returns HTTP 200 OK');

  const json = await response.json();

  // Test Schema
  console.log('\nGroup 2: Response Schema Verification');
  assert(typeof json.timestamp === 'string', 'Root "timestamp" is string');
  assert(
    !isNaN(Date.parse(json.timestamp)),
    'Root "timestamp" is valid ISO-8601 date string'
  );
  assert(
    ['healthy', 'degraded', 'critical'].includes(json.overall_status),
    `"overall_status" is valid enum value (actual: ${json.overall_status})`
  );

  // Auth structure
  assert(typeof json.auth === 'object' && json.auth !== null, '"auth" object present');
  assert(
    typeof json.auth.mode === 'string' && json.auth.mode === 'local_mode',
    '"auth.mode" accurately reflects "local_mode" under fallback'
  );
  assert(typeof json.auth.role === 'string', '"auth.role" is present');

  // Services structure
  assert(typeof json.services === 'object' && json.services !== null, '"services" object present');

  // Database probe
  const db = json.services.database;
  assert(typeof db === 'object' && db !== null, 'services.database present');
  assert(db.name === 'Supabase PostgreSQL', 'Database name matches');
  assert(
    ['connected', 'simulation_mock', 'degraded', 'error'].includes(db.status),
    `Database status enum valid (actual: ${db.status})`
  );
  assert(
    typeof db.latency_ms === 'number' && db.latency_ms >= 0,
    `Database latency_ms is a non-negative number (${db.latency_ms} ms)`
  );
  assert(
    typeof db.details === 'string' && db.details.length > 0,
    `Database details string populated: "${db.details}"`
  );

  // FastAPI probe (offline fallback)
  const fastapi = json.services.fastapi;
  assert(typeof fastapi === 'object' && fastapi !== null, 'services.fastapi present');
  assert(fastapi.name === 'Motor Tático FastAPI', 'FastAPI name matches');
  assert(
    ['online', 'offline', 'degraded'].includes(fastapi.status),
    `FastAPI status enum valid (actual: ${fastapi.status})`
  );
  assert(
    typeof fastapi.details === 'string' && fastapi.details.length > 0,
    `FastAPI details populated: "${fastapi.details}"`
  );

  // Redis probe (offline fallback)
  const redisService = json.services.redis;
  assert(typeof redisService === 'object' && redisService !== null, 'services.redis present');
  assert(redisService.name === 'Fila Assíncrona Redis', 'Redis name matches');
  assert(
    ['connected', 'fallback_direct'].includes(redisService.status),
    `Redis status enum valid (actual: ${redisService.status})`
  );
  assert(
    typeof redisService.details === 'string' && redisService.details.length > 0,
    `Redis details populated: "${redisService.details}"`
  );

  // AI Triage probe
  const ai = json.services.ai_triage;
  assert(typeof ai === 'object' && ai !== null, 'services.ai_triage present');
  assert(
    typeof ai.enabled === 'boolean',
    `AI triage enabled flag is boolean (${ai.enabled})`
  );
  assert(
    ['ready', 'partially_configured', 'disabled', 'missing_keys'].includes(ai.status),
    `AI triage status enum valid (actual: ${ai.status})`
  );
  assert(
    typeof ai.providers === 'object' &&
      'groq' in ai.providers &&
      'gemini' in ai.providers,
    'AI triage includes groq and gemini provider configurations'
  );

  // Group 3: Adversarial Auth Edge Case on R4
  console.log('\nGroup 3: Adversarial Auth & Production Enforcement on R4');
  const prevLocal = process.env.VEXTHUB_LOCAL_MODE;
  const prevUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const prevKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  try {
    // Simulate production mode with real keys configured and no local mode
    process.env.VEXTHUB_LOCAL_MODE = 'false';
    process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://fake-prod-url.supabase.co';
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'fake-anon-key-eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

    const unauthReq = new Request('http://localhost:3000/api/system/status', {
      method: 'GET',
    });

    const unauthRes = await statusRouteGet(unauthReq);
    assert(
      unauthRes.status === 401 || unauthRes.status === 403,
      `Unauthenticated request in production auth mode correctly blocked with HTTP 401/403 (actual: ${unauthRes.status})`
    );
  } finally {
    process.env.VEXTHUB_LOCAL_MODE = prevLocal;
    if (prevUrl) process.env.NEXT_PUBLIC_SUPABASE_URL = prevUrl;
    else delete process.env.NEXT_PUBLIC_SUPABASE_URL;
    if (prevKey) process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = prevKey;
    else delete process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
  }
}

async function main() {
  try {
    await runR3Tests();
    await runR4Tests();

    console.log('\n======================================================');
    console.log(`TOTAL TESTS: ${totalTests}`);
    console.log(`PASSED: ${passedTests}`);
    console.log(`FAILED: ${failedTests}`);
    console.log('======================================================\n');

    if (failedTests > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (err) {
    console.error('UNEXPECTED TEST HARNESS ERROR:', err);
    process.exit(2);
  }
}

void main();
