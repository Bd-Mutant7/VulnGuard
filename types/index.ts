export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  location: {
    file: string;
    line?: number;
  };
  codeSnippet: string;
  risk: string;
  remediation: string;
  detectedAt: Date;
}

export interface ScanResult {
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  scanDuration: number;
}