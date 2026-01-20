/**
 * VPN/Proxy/Datacenter/Tor Detection System
 * Detects and blocks traffic from VPNs, proxies, data centers, and Tor exit nodes
 */

import crypto from 'crypto';

export interface IPAnalysisResult {
    ip: string;
    isVPN: boolean;
    isProxy: boolean;
    isDatacenter: boolean;
    isTor: boolean;
    isResidential: boolean;
    isMobile: boolean;
    isHosting: boolean;
    isBogon: boolean;
    riskScore: number; // 0-100
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    country?: string;
    asn?: string;
    asnOrg?: string;
    isp?: string;
    flags: string[];
}

// Known VPN/Proxy ASN ranges (partial list - should be updated regularly)
const KNOWN_VPN_ASNS = new Set([
    'AS9009',   // M247
    'AS20473',  // Vultr
    'AS14061',  // DigitalOcean
    'AS16276',  // OVH
    'AS24940',  // Hetzner
    'AS14618',  // Amazon AWS
    'AS15169',  // Google Cloud
    'AS8075',   // Microsoft Azure
    'AS396982', // Google Cloud
    'AS13238',  // Yandex
    'AS16509',  // Amazon EC2
    'AS45102',  // Alibaba Cloud
    'AS37963',  // Alibaba Cloud
    'AS4134',   // ChinaNet
    'AS4837',   // China Unicom
    'AS9808',   // China Mobile
    'AS136907', // Huawei Cloud
    'AS132203', // Tencent Cloud
    'AS55990',  // Huawei Cloud
    'AS398101', // SharkTech
    'AS53667',  // FranTech
    'AS62563',  // GTHost
    'AS46562',  // Performive
    'AS30083',  // HEG US
    'AS51167',  // Contabo
    'AS60068',  // Datacamp Limited - CDN77
    'AS209',    // CenturyLink
    'AS62041',  // PrivateVPN
    'AS9370',   // SAKURA Internet
]);

// Known datacenter IP ranges (CIDR notation)
const DATACENTER_CIDR_PREFIXES = [
    // AWS
    '3.', '13.', '15.', '18.', '23.20.', '23.21.', '34.', '35.', '44.', '50.', '52.', '54.', '63.', '65.', '70.', '72.', '75.', '76.', '99.', '100.',
    // Google Cloud  
    '34.64.', '34.65.', '34.66.', '34.67.', '35.186.', '35.187.', '35.188.', '35.189.', '35.190.', '35.191.', '35.192.',
    // Azure
    '13.64.', '13.65.', '13.66.', '13.67.', '13.68.', '13.69.', '13.70.', '13.71.', '20.', '40.', '51.', '52.', '65.', '70.',
    // DigitalOcean
    '104.131.', '104.236.', '107.170.', '138.68.', '138.197.', '139.59.', '142.93.', '143.110.', '143.198.', '144.126.', '146.185.', '157.230.', '157.245.', '159.65.', '159.89.', '159.203.', '161.35.', '162.243.', '163.47.', '164.90.', '165.22.', '165.227.', '167.71.', '167.99.', '167.172.', '174.138.', '178.62.', '178.128.', '188.166.', '192.241.', '198.199.', '198.211.', '203.', '206.189.', '206.81.', '207.154.', '209.97.',
    // Linode
    '45.33.', '45.56.', '45.79.', '50.116.', '66.175.', '66.228.', '69.164.', '72.14.', '74.207.', '96.126.', '97.107.', '104.200.', '104.237.', '106.187.', '109.74.', '139.162.', '172.104.', '173.230.', '173.255.', '178.79.', '183.90.', '192.155.', '194.195.', '198.58.', '198.74.', '212.71.', '212.111.',
    // Vultr
    '45.32.', '45.63.', '45.76.', '45.77.', '64.156.', '64.237.', '66.42.', '66.55.', '67.219.', '69.65.', '78.141.', '80.240.', '95.179.', '104.156.', '104.207.', '104.238.', '107.191.', '108.61.', '136.244.', '140.82.', '141.164.', '144.202.', '149.28.', '149.248.', '155.138.', '158.247.', '167.179.', '173.199.', '199.247.', '202.182.', '207.148.', '207.246.', '208.167.', '209.250.', '216.128.', '217.69.',
    // OVH
    '5.39.', '5.135.', '5.196.', '5.199.', '37.59.', '37.187.', '46.105.', '51.38.', '51.68.', '51.75.', '51.77.', '51.79.', '51.81.', '51.83.', '51.89.', '51.91.', '51.161.', '51.178.', '51.195.', '51.210.', '51.222.', '54.36.', '54.37.', '54.38.', '57.128.', '57.129.', '66.70.', '79.137.', '87.98.', '91.121.', '91.134.', '92.222.', '94.23.', '109.190.', '137.74.', '139.99.', '141.94.', '141.95.', '142.4.', '142.44.', '144.217.', '145.239.', '147.135.', '149.202.', '149.56.', '151.80.', '158.69.', '164.132.', '167.114.', '176.31.', '178.32.', '178.33.', '185.12.', '188.165.', '192.95.', '192.99.', '193.70.', '195.154.', '198.27.', '198.50.', '198.100.', '198.245.', '213.186.', '213.251.', '217.182.',
    // Hetzner
    '5.9.', '5.75.', '5.161.', '23.88.', '46.4.', '49.12.', '49.13.', '65.21.', '78.46.', '78.47.', '85.10.', '88.99.', '88.198.', '91.107.', '94.130.', '95.216.', '116.202.', '116.203.', '128.140.', '135.181.', '136.243.', '138.201.', '142.132.', '144.76.', '148.251.', '157.90.', '159.69.', '162.55.', '167.233.', '168.119.', '176.9.', '178.212.', '178.63.', '188.34.', '188.40.', '193.25.', '195.201.', '213.133.', '213.239.',
];

// Known Tor exit node check (simplified - in production use Tor exit list API)
const TOR_EXIT_INDICATORS = [
    'tor-exit', 'torproject', 'tor.', '.tor.', 'exit.', 'relay.',
];

// Bogon/Private IP ranges
const BOGON_RANGES = [
    '0.', '10.', '100.64.', '127.', '169.254.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
    '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.0.0.', '192.0.2.', '192.168.', '198.18.', '198.19.', '198.51.100.',
    '203.0.113.', '224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', '232.', '233.',
    '234.', '235.', '236.', '237.', '238.', '239.', '240.', '255.',
];

export class VPNProxyDetector {
    private apiKey?: string;
    private cache: Map<string, { result: IPAnalysisResult; timestamp: number }> = new Map();
    private cacheTTL: number = 3600000; // 1 hour

    constructor(apiKey?: string) {
        this.apiKey = apiKey;
    }

    /**
     * Analyze an IP address for VPN/Proxy/Datacenter indicators
     */
    async analyze(ip: string, asnInfo?: { asn?: string; org?: string; isp?: string }): Promise<IPAnalysisResult> {
        // Check cache
        const cached = this.cache.get(ip);
        if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
            return cached.result;
        }

        const flags: string[] = [];
        let riskScore = 0;

        // Check for bogon/private IPs
        const isBogon = this.isBogonIP(ip);
        if (isBogon) {
            flags.push('bogon_ip');
            riskScore += 50;
        }

        // Check datacenter IP ranges
        const isDatacenter = this.isDatacenterIP(ip);
        if (isDatacenter) {
            flags.push('datacenter_ip');
            riskScore += 40;
        }

        // Check known VPN ASNs
        const isKnownVPNAsn = asnInfo?.asn ? KNOWN_VPN_ASNS.has(asnInfo.asn) : false;
        if (isKnownVPNAsn) {
            flags.push('known_vpn_asn');
            riskScore += 35;
        }

        // Check hosting/cloud provider keywords
        const isHosting = this.isHostingProvider(asnInfo?.org || '', asnInfo?.isp || '');
        if (isHosting) {
            flags.push('hosting_provider');
            riskScore += 30;
        }

        // Check for Tor indicators
        const isTor = this.hasTorIndicators(asnInfo?.org || '');
        if (isTor) {
            flags.push('tor_exit_node');
            riskScore += 50;
        }

        // Check for VPN/Proxy keywords in ISP/Org
        const hasVPNKeywords = this.hasVPNKeywords(asnInfo?.org || '', asnInfo?.isp || '');
        if (hasVPNKeywords) {
            flags.push('vpn_keywords');
            riskScore += 30;
        }

        // Determine final classifications
        const result: IPAnalysisResult = {
            ip,
            isVPN: hasVPNKeywords || isKnownVPNAsn,
            isProxy: hasVPNKeywords,
            isDatacenter,
            isTor,
            isResidential: !isDatacenter && !isHosting && !isKnownVPNAsn && !isBogon,
            isMobile: this.isMobileCarrier(asnInfo?.isp || '', asnInfo?.org || ''),
            isHosting,
            isBogon,
            riskScore: Math.min(riskScore, 100),
            riskLevel: this.calculateRiskLevel(riskScore),
            asn: asnInfo?.asn,
            asnOrg: asnInfo?.org,
            isp: asnInfo?.isp,
            flags,
        };

        // Cache result
        this.cache.set(ip, { result, timestamp: Date.now() });

        return result;
    }

    /**
     * Quick check without full analysis
     */
    quickCheck(ip: string): { suspicious: boolean; reason?: string } {
        if (this.isBogonIP(ip)) {
            return { suspicious: true, reason: 'Bogon/Private IP' };
        }
        if (this.isDatacenterIP(ip)) {
            return { suspicious: true, reason: 'Datacenter IP' };
        }
        return { suspicious: false };
    }

    private isBogonIP(ip: string): boolean {
        return BOGON_RANGES.some(prefix => ip.startsWith(prefix));
    }

    private isDatacenterIP(ip: string): boolean {
        return DATACENTER_CIDR_PREFIXES.some(prefix => ip.startsWith(prefix));
    }

    private isHostingProvider(org: string, isp: string): boolean {
        const combined = (org + ' ' + isp).toLowerCase();
        const hostingKeywords = [
            'amazon', 'aws', 'google', 'gcp', 'microsoft', 'azure', 'digitalocean',
            'linode', 'vultr', 'ovh', 'hetzner', 'cloudflare', 'akamai', 'fastly',
            'leaseweb', 'rackspace', 'softlayer', 'ibm cloud', 'oracle cloud',
            'alibaba', 'tencent', 'huawei', 'contabo', 'hostinger', 'godaddy',
            'namecheap', 'bluehost', 'hostgator', 'ionos', '1&1', 'dreamhost',
            'siteground', 'a2 hosting', 'inmotion', 'liquidweb', 'datacamp',
            'frantech', 'buyvm', 'ramnode', 'server', 'hosting', 'vps', 'cloud',
            'dedicat', 'colocation', 'colo', 'data center', 'datacenter',
        ];
        return hostingKeywords.some(kw => combined.includes(kw));
    }

    private hasTorIndicators(org: string): boolean {
        const lower = org.toLowerCase();
        return TOR_EXIT_INDICATORS.some(ind => lower.includes(ind));
    }

    private hasVPNKeywords(org: string, isp: string): boolean {
        const combined = (org + ' ' + isp).toLowerCase();
        const vpnKeywords = [
            'vpn', 'proxy', 'anonymous', 'privacy', 'hide', 'tunnel', 'private',
            'mullvad', 'nordvpn', 'expressvpn', 'surfshark', 'cyberghost',
            'protonvpn', 'ipvanish', 'purevpn', 'hotspot shield', 'tunnelbear',
            'windscribe', 'ivacy', 'perfectprivacy', 'airvpn', 'torguard',
            'privatevpn', 'vyprvpn', 'strongvpn', 'btguard', 'astrill',
            'm247', 'frantech', 'tzulo', 'private internet access', 'pia',
        ];
        return vpnKeywords.some(kw => combined.includes(kw));
    }

    private isMobileCarrier(isp: string, org: string): boolean {
        const combined = (isp + ' ' + org).toLowerCase();
        const mobileKeywords = [
            'mobile', 'cellular', 'wireless', 'lte', '4g', '5g',
            'verizon', 'at&t', 't-mobile', 'sprint', 'vodafone', 'orange',
            'telefonica', 'o2', 'three', 'ee', 'airtel', 'jio', 'idea',
            'docomo', 'softbank', 'kddi', 'au', 'china mobile', 'china unicom',
            'china telecom', 'kt', 'sk telecom', 'lg uplus',
        ];
        return mobileKeywords.some(kw => combined.includes(kw));
    }

    private calculateRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
        if (score >= 70) return 'critical';
        if (score >= 50) return 'high';
        if (score >= 30) return 'medium';
        return 'low';
    }

    /**
     * Clear expired cache entries
     */
    cleanupCache(): void {
        const now = Date.now();
        for (const [ip, entry] of this.cache.entries()) {
            if (now - entry.timestamp > this.cacheTTL) {
                this.cache.delete(ip);
            }
        }
    }
}

/**
 * IP Reputation Service Integration
 * Interfaces with external IP reputation APIs
 */
export class IPReputationService {
    private providers: Map<string, { url: string; key: string }> = new Map();

    /**
     * Add an IP reputation provider
     * Supported: ipqualityscore, abuseipdb, proxycheck, ip2proxy
     */
    addProvider(name: string, apiKey: string): void {
        const urls: Record<string, string> = {
            'ipqualityscore': 'https://ipqualityscore.com/api/json/ip/',
            'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
            'proxycheck': 'https://proxycheck.io/v2/',
            'ip2proxy': 'https://api.ip2proxy.com/',
        };
        if (urls[name]) {
            this.providers.set(name, { url: urls[name], key: apiKey });
        }
    }

    /**
     * Check IP against all configured providers
     */
    async checkIP(ip: string): Promise<{
        consensus: { isProxy: boolean; isVPN: boolean; isTor: boolean; riskScore: number };
        results: Record<string, any>;
    }> {
        const results: Record<string, any> = {};
        let proxyVotes = 0;
        let vpnVotes = 0;
        let torVotes = 0;
        let totalRisk = 0;
        let providerCount = 0;

        for (const [name, config] of this.providers) {
            try {
                const result = await this.queryProvider(name, ip, config);
                results[name] = result;

                if (result.isProxy) proxyVotes++;
                if (result.isVPN) vpnVotes++;
                if (result.isTor) torVotes++;
                totalRisk += result.riskScore || 0;
                providerCount++;
            } catch (e) {
                results[name] = { error: (e as Error).message };
            }
        }

        const threshold = Math.ceil(providerCount / 2);

        return {
            consensus: {
                isProxy: proxyVotes >= threshold,
                isVPN: vpnVotes >= threshold,
                isTor: torVotes >= threshold,
                riskScore: providerCount > 0 ? Math.round(totalRisk / providerCount) : 0,
            },
            results,
        };
    }

    private async queryProvider(name: string, ip: string, config: { url: string; key: string }): Promise<any> {
        // This is a template - actual implementation depends on provider API
        // In production, implement proper API calls for each provider

        switch (name) {
            case 'ipqualityscore':
                // GET https://ipqualityscore.com/api/json/ip/{key}/{ip}
                return { isProxy: false, isVPN: false, isTor: false, riskScore: 0 };

            case 'abuseipdb':
                // GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}
                // Headers: Key: {key}
                return { isProxy: false, isVPN: false, isTor: false, riskScore: 0 };

            case 'proxycheck':
                // GET https://proxycheck.io/v2/{ip}?key={key}&vpn=1
                return { isProxy: false, isVPN: false, isTor: false, riskScore: 0 };

            default:
                return { isProxy: false, isVPN: false, isTor: false, riskScore: 0 };
        }
    }
}
