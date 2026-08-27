import { GeoLocationInfo } from '../src/types';

// Robust offline & realistic IP Geolocation & ASN intelligence dictionary
const KNOWN_IP_RANGES: Record<string, GeoLocationInfo> = {
  // Suspect Attack Nodes / VPN / Tor
  '185.220.101.5': {
    ip: '185.220.101.5',
    country: 'Germany',
    country_code: 'DE',
    region: 'Hesse',
    city: 'Frankfurt',
    latitude: 50.1109,
    longitude: 8.6821,
    asn: 'AS208294',
    isp: 'Zwiebelfreunde e.V.',
    org: 'Tor Exit Relay Node',
    is_vpn_tor_proxy: true,
    proxy_type: 'TOR_EXIT',
    threat_reputation: 'MALICIOUS',
  },
  '194.26.29.112': {
    ip: '194.26.29.112',
    country: 'Russia',
    country_code: 'RU',
    region: 'Moscow',
    city: 'Moscow',
    latitude: 55.7558,
    longitude: 37.6173,
    asn: 'AS44050',
    isp: 'PQ Hosting Plus S.R.L.',
    org: 'Bulletproof VPS Services',
    is_vpn_tor_proxy: true,
    proxy_type: 'BULLETPROOF_HOST',
    threat_reputation: 'MALICIOUS',
  },
  '45.154.255.89': {
    ip: '45.154.255.89',
    country: 'Netherlands',
    country_code: 'NL',
    region: 'North Holland',
    city: 'Amsterdam',
    latitude: 52.3676,
    longitude: 4.9041,
    asn: 'AS200019',
    isp: 'ALEXHOST SRL',
    org: 'Offshore Hosting Infrastructure',
    is_vpn_tor_proxy: true,
    proxy_type: 'VPN',
    threat_reputation: 'SUSPICIOUS',
  },
  '103.151.125.40': {
    ip: '103.151.125.40',
    country: 'Nigeria',
    country_code: 'NG',
    region: 'Lagos',
    city: 'Lagos',
    latitude: 6.5244,
    longitude: 3.3792,
    asn: 'AS37148',
    isp: 'MainOne Cable Company',
    org: 'Commercial Internet Access',
    is_vpn_tor_proxy: false,
    threat_reputation: 'SUSPICIOUS',
  },
  '91.240.118.22': {
    ip: '91.240.118.22',
    country: 'Romania',
    country_code: 'RO',
    region: 'Bucharest',
    city: 'Bucharest',
    latitude: 44.4268,
    longitude: 26.1025,
    asn: 'AS49981',
    isp: 'WorldStream B.V.',
    org: 'High Risk Proxy Node',
    is_vpn_tor_proxy: true,
    proxy_type: 'RESIDENTIAL_PROXY',
    threat_reputation: 'MALICIOUS',
  },

  // Legitimate Major Clouds & Mail Relays
  '209.85.220.41': {
    ip: '209.85.220.41',
    country: 'United States',
    country_code: 'US',
    region: 'California',
    city: 'Mountain View',
    latitude: 37.3861,
    longitude: -122.0839,
    asn: 'AS15169',
    isp: 'Google LLC',
    org: 'Google Mail Transfer Agent (Gmail)',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
  '40.92.74.45': {
    ip: '40.92.74.45',
    country: 'United States',
    country_code: 'US',
    region: 'Washington',
    city: 'Redmond',
    latitude: 47.674,
    longitude: -122.1215,
    asn: 'AS8075',
    isp: 'Microsoft Corporation',
    org: 'Exchange Online Protection / Office 365',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
  '54.240.9.112': {
    ip: '54.240.9.112',
    country: 'United States',
    country_code: 'US',
    region: 'Virginia',
    city: 'Ashburn',
    latitude: 39.0438,
    longitude: -77.4874,
    asn: 'AS16509',
    isp: 'Amazon.com, Inc.',
    org: 'Amazon Simple Email Service (SES)',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
  '198.2.138.80': {
    ip: '198.2.138.80',
    country: 'United States',
    country_code: 'US',
    region: 'Georgia',
    city: 'Atlanta',
    latitude: 33.749,
    longitude: -84.388,
    asn: 'AS14782',
    isp: 'The Rocket Science Group LLC',
    org: 'Mailchimp Delivery Infrastructure',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
  '142.250.102.26': {
    ip: '142.250.102.26',
    country: 'United States',
    country_code: 'US',
    region: 'California',
    city: 'Los Angeles',
    latitude: 34.0522,
    longitude: -118.2437,
    asn: 'AS15169',
    isp: 'Google LLC',
    org: 'Google Cloud Mail Relay',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
  '104.244.42.1': {
    ip: '104.244.42.1',
    country: 'United States',
    country_code: 'US',
    region: 'California',
    city: 'San Francisco',
    latitude: 37.7749,
    longitude: -122.4194,
    asn: 'AS13335',
    isp: 'Cloudflare, Inc.',
    org: 'Cloudflare Mail Routing Edge',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
  '103.21.244.0': {
    ip: '103.21.244.0',
    country: 'India',
    country_code: 'IN',
    region: 'Maharashtra',
    city: 'Mumbai',
    latitude: 19.076,
    longitude: 72.8777,
    asn: 'AS55836',
    isp: 'Reliance Jio Infocomm',
    org: 'Enterprise Edge Gateway',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
  '14.139.45.2': {
    ip: '14.139.45.2',
    country: 'India',
    country_code: 'IN',
    region: 'Delhi',
    city: 'New Delhi',
    latitude: 28.6139,
    longitude: 77.209,
    asn: 'AS4600',
    isp: 'National Knowledge Network (NKN)',
    org: 'NIC Govt Mail Gateway',
    is_vpn_tor_proxy: false,
    threat_reputation: 'CLEAN',
  },
};

export function isPrivateIp(ip: string): boolean {
  if (!ip) return true;
  const clean = ip.trim().replace(/[\[\]]/g, '');
  if (
    clean === '127.0.0.1' ||
    clean === 'localhost' ||
    clean === '::1' ||
    clean.startsWith('10.') ||
    clean.startsWith('192.168.') ||
    clean.startsWith('169.254.')
  ) {
    return true;
  }
  if (clean.startsWith('172.')) {
    const parts = clean.split('.');
    if (parts.length >= 2) {
      const second = parseInt(parts[1], 10);
      if (second >= 16 && second <= 31) return true;
    }
  }
  return false;
}

export function lookupIpIntelligence(ip: string): GeoLocationInfo {
  if (!ip) {
    return {
      ip: 'Unknown',
      country: 'Unknown',
      country_code: 'XX',
      region: 'Unknown',
      city: 'Unknown',
      latitude: 0,
      longitude: 0,
      asn: 'AS0',
      isp: 'Unknown Provider',
      org: 'Unknown',
      threat_reputation: 'UNKNOWN',
    };
  }

  const cleanIp = ip.trim().replace(/[\[\]]/g, '');

  if (isPrivateIp(cleanIp)) {
    return {
      ip: cleanIp,
      country: 'Internal Network',
      country_code: 'LAN',
      region: 'RFC 1918 Private',
      city: 'Local Area Network',
      latitude: 0,
      longitude: 0,
      asn: 'PRIVATE',
      isp: 'Intranet / LAN Relay',
      org: 'Corporate Private Subnet',
      is_vpn_tor_proxy: false,
      threat_reputation: 'CLEAN',
    };
  }

  if (KNOWN_IP_RANGES[cleanIp]) {
    return KNOWN_IP_RANGES[cleanIp];
  }

  // Deterministic pseudo-geo calculation for arbitrary public IPs to ensure seamless visualization
  const octets = cleanIp.split('.').map((x) => parseInt(x, 10) || 0);
  const hash = (octets[0] * 73 + octets[1] * 37 + octets[2] * 19 + octets[3]) % 1000;

  const sampleLocs: Array<{
    country: string;
    code: string;
    region: string;
    city: string;
    lat: number;
    lon: number;
    asn: string;
    isp: string;
  }> = [
    { country: 'United States', code: 'US', region: 'Virginia', city: 'Ashburn', lat: 39.0438, lon: -77.4874, asn: 'AS16509', isp: 'Amazon Web Services' },
    { country: 'United States', code: 'US', region: 'California', city: 'Santa Clara', lat: 37.3541, lon: -121.9552, asn: 'AS8075', isp: 'Microsoft Cloud' },
    { country: 'Germany', code: 'DE', region: 'Bavaria', city: 'Nuremberg', lat: 49.4521, lon: 11.0767, asn: 'AS24940', isp: 'Hetzner Online GmbH' },
    { country: 'United Kingdom', code: 'GB', region: 'England', city: 'London', lat: 51.5074, lon: -0.1278, asn: 'AS2856', isp: 'British Telecommunications' },
    { country: 'Singapore', code: 'SG', region: 'Central', city: 'Singapore', lat: 1.3521, lon: 103.8198, asn: 'AS4657', isp: 'StarHub Ltd' },
    { country: 'India', code: 'IN', region: 'Karnataka', city: 'Bengaluru', lat: 12.9716, lon: 77.5946, asn: 'AS45820', isp: 'Tata Communications' },
    { country: 'India', code: 'IN', region: 'Maharashtra', city: 'Mumbai', lat: 19.076, lon: 72.8777, asn: 'AS55836', isp: 'Jio Infocomm Ltd' },
    { country: 'Netherlands', code: 'NL', region: 'North Holland', city: 'Amsterdam', lat: 52.3676, lon: 4.9041, asn: 'AS1103', isp: 'SURF B.V.' },
    { country: 'France', code: 'FR', region: 'Île-de-France', city: 'Paris', lat: 48.8566, lon: 2.3522, asn: 'AS16276', isp: 'OVH SAS' },
    { country: 'Brazil', code: 'BR', region: 'São Paulo', city: 'São Paulo', lat: -23.5505, lon: -46.6333, asn: 'AS28573', isp: 'Claro Brasil' },
  ];

  const loc = sampleLocs[hash % sampleLocs.length];

  return {
    ip: cleanIp,
    country: loc.country,
    country_code: loc.code,
    region: loc.region,
    city: loc.city,
    latitude: loc.lat + ((hash % 10) - 5) * 0.05,
    longitude: loc.lon + (((hash >> 2) % 10) - 5) * 0.05,
    asn: loc.asn,
    isp: loc.isp,
    org: `${loc.isp} Network Segment`,
    is_vpn_tor_proxy: hash % 7 === 0,
    proxy_type: hash % 7 === 0 ? 'DATACENTER_PROXY' : undefined,
    threat_reputation: hash % 5 === 0 ? 'SUSPICIOUS' : 'CLEAN',
  };
}
