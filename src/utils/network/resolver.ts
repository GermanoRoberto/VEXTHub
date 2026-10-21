/**
 * Motor de Resolucao de Rede VextHub (v3.1.1 - Protocol & Privacy Edition)
 */
import vendorDb from './vendorDb.json';

const VENDOR_DB = vendorDb as Record<string, string>;

/**
 * Verifica se um endereço MAC é "Locally Administered" (Aleatório/Privado)
 * Regra: se o segundo dígito hex for 2, 6, A ou E.
 */
function isPrivateMac(mac: string): boolean {
  const secondDigit = mac.charAt(1).toUpperCase();
  return ['2', '6', 'A', 'E'].includes(secondDigit);
}

/**
 * Resolve o fabricante com base no MAC
 */
export function resolveVendor(mac: string | null | undefined): string {
  if (!mac) return "Desconhecido";
  
  const cleanMac = mac.replace(/[:\-]/g, '').toUpperCase();
  if (cleanMac.length < 6) return "MAC Inválido";
  
  const oui = `${cleanMac.substring(0, 2)}:${cleanMac.substring(2, 4)}:${cleanMac.substring(4, 6)}`;
  
  // 1. Verifica se é um fabricante conhecido no banco de dados
  if (VENDOR_DB[oui]) return VENDOR_DB[oui];
  
  // 2. Verifica se é um MAC Privado (Aleatório)
  if (isPrivateMac(cleanMac)) return "Dispositivo Privado (MAC Aleatório)";
  
  return "Hardware Genérico / Desconhecido";
}

/**
 * Motor de Heurística de Identificação Avançada (v3.1.1)
 */
export function getDeviceType(vendor: string, hostname?: string, ip?: string): 'desktop' | 'laptop' | 'printer' | 'collector' | 'mobile' | 'network' | 'virtual' | 'camera' | 'workstation' {
  const v = (vendor || "").toLowerCase();
  const h = (hostname || "").toLowerCase();
  const i = (ip || "");

  // 1. INFRAESTRUTURA DE REDE / PROTOCOLOS (ALTA PRIORIDADE)
  if (v.includes('protocolo') || v.includes('multicast') || v.includes('broadcast')) return 'network';

  const isNetworkBrand = v.includes('draytek') || v.includes('cisco') || v.includes('mikrotik') || 
                         v.includes('ubiquiti') || v.includes('tp-link') || v.includes('d-link') || 
                         v.includes('digibras') || v.includes('aruba') || v.includes('juniper') ||
                         v.includes('fortinet') || v.includes('palo alto');

  const isInfraIp = i.endsWith('.1') || i.endsWith('.254') || i.endsWith('.250') || 
                    i.endsWith('.252') || i.endsWith('.253') || i.endsWith('.200') ||
                    i.startsWith('224.'); // Multicast Range
  
  if (isNetworkBrand || isInfraIp || h.includes('router') || h.includes('switch') || 
      h.includes('firewall') || h.includes('gateway') || h.includes('ap-') || h.includes('wifi')) {
     return 'network';
  }

  // 2. DISPOSITIVOS PRIVADOS / MÓVEIS
  if (v.includes('privado') || v.includes('aleatório')) return 'mobile';

  // 3. IMPRESSORAS
  if (v.includes('printer') || v.includes('impressora') || v.includes('zebra') || 
      v.includes('brother') || v.includes('canon') || v.includes('epson') || 
      v.includes('hp inc') || v.includes('hewlett-packard') && (h.includes('prn') || h.includes('imp'))) {
      if (h.includes('prn-') || h.includes('imp-') || h.includes('laserjet') || h.includes('officejet')) return 'printer';
  }
  if (v.includes('ricoh') || v.includes('xerox') || v.includes('lexmark') || v.includes('kyocera')) return 'printer';

  // 4. COLETORES
  if (v.includes('honeywell') || v.includes('symbol') || v.includes('motorola solutions') || 
      v.includes('intermec') || v.includes('datalogic') || v.includes('bluebird')) return 'collector';
  if (h.includes('col-') || h.includes('hht-') || h.includes('rf-') || h.includes('android-col')) return 'collector';

  // 5. COMPUTADORES & LAPTOPS
  const isPcBrand = v.includes('dell') || v.includes('lenovo') || v.includes('hp inc') || 
                    v.includes('hewlett-packard') || v.includes('asustek') || v.includes('acer') || 
                    v.includes('apple') || v.includes('microsoft') || v.includes('fujitsu');

  if (isPcBrand) {
    if (h.includes('not-') || h.includes('lt-') || h.includes('laptop') || 
        h.includes('notebook') || h.includes('macbook') || h.includes('thinkpad')) return 'laptop';
    return 'desktop';
  }

  // 6. MÓVEIS (RECOMENDADO PARA XIAOMI/SAMSUNG)
  if (v.includes('apple') || v.includes('samsung') || v.includes('xiaomi') || v.includes('motorola')) {
     if (!h.includes('pc') && !h.includes('desk')) return 'mobile';
  }
  if (h.includes('iphone') || h.includes('android') || h.includes('ipad')) return 'mobile';

  // 7. OUTROS
  if (v.includes('hikvision') || v.includes('dahua') || v.includes('intelbras')) return 'camera';
  if (v.includes('vmware') || v.includes('hyper-v') || v.includes('virtualbox')) return 'virtual';

  return 'workstation';
}
