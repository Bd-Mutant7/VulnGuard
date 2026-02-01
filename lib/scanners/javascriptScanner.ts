export class JavaScriptScanner {
  private vulnerabilities: any[] = [];

  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    // Check for SQL injection
    this.checkSQLInjection(code, filePath);
    
    // Check for hardcoded secrets
    this.checkHardcodedSecrets(code, filePath);
    
    return {
      vulnerabilities: this.vulnerabilities,
      summary: {
        total: this.vulnerabilities.length,
        critical: this.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        high: this.vulnerabilities.filter(v => v.severity === 'HIGH').length,
        medium: this.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
        low: this.vulnerabilities.filter(v => v.severity === 'LOW').length,
      }
    };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      /SELECT.*\$\{.*\}/gi,
      /INSERT.*\$\{.*\}/gi,
      /UPDATE.*\$\{.*\}/gi,
      /DELETE.*\$\{.*\}/gi,
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        matches.forEach(match => {
          this.vulnerabilities.push({
            id: `sql_${Date.now()}_${Math.random()}`,
            name: 'SQL Injection',
            description: 'Potential SQL injection vulnerability',
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 100),
            risk: 'Attackers can execute arbitrary SQL commands',
            remediation: 'Use parameterized queries or prepared statements',
            detectedAt: new Date()
          });
        });
      }
    });
  }

  private checkHardcodedSecrets(code: string, filePath: string) {
    const patterns = [
      /password\s*=\s*["'].+["']/gi,
      /api[_-]?key\s*=\s*["'].+["']/gi,
      /secret\s*=\s*["'].+["']/gi,
      /token\s*=\s*["'].+["']/gi,
    ];

    patterns.forEach(pattern => {
      const matches = code.match(pattern);
      if (matches) {
        matches.forEach(match => {
          this.vulnerabilities.push({
            id: `secret_${Date.now()}_${Math.random()}`,
            name: 'Hardcoded Secret',
            description: 'Hardcoded secret found in code',
            severity: 'HIGH',
            category: 'SECRETS',
            location: { file: filePath },
            codeSnippet: match.substring(0, 100),
            risk: 'Secrets can be extracted from source code',
            remediation: 'Use environment variables or secret management',
            detectedAt: new Date()
          });
        });
      }
    });
  }
}