import { NextRequest, NextResponse } from 'next/server';

// ========== BASE SCANNER CLASS ==========
abstract class BaseScanner {
  protected vulnerabilities: any[] = [];

  abstract scan(code: string, filePath: string): {
    vulnerabilities: any[];
    summary: {
      total: number;
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };

  protected addVulnerability(vuln: Omit<any, 'id' | 'detectedAt'>) {
    this.vulnerabilities.push({
      ...vuln,
      id: `${this.constructor.name.toLowerCase()}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      detectedAt: new Date().toISOString()
    });
  }

  protected getSummary() {
    return {
      total: this.vulnerabilities.length,
      critical: this.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      high: this.vulnerabilities.filter(v => v.severity === 'HIGH').length,
      medium: this.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      low: this.vulnerabilities.filter(v => v.severity === 'LOW').length,
    };
  }

  protected checkHardcodedSecrets(code: string, filePath: string, language: string) {
    const secretPatterns = [
      { regex: /password\s*[:=]\s*["'].+["']/gi, name: 'Hardcoded Password' },
      { regex: /api[_-]?key\s*[:=]\s*["'].+["']/gi, name: 'Hardcoded API Key' },
      { regex: /secret\s*[:=]\s*["'].+["']/gi, name: 'Hardcoded Secret' },
      { regex: /token\s*[:=]\s*["'].+["']/gi, name: 'Hardcoded Token' },
      { regex: /(aws[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*["'].+["']/gi, name: 'Hardcoded AWS Credentials' },
      { regex: /(stripe[_-]?key|stripe[_-]?secret)\s*[:=]\s*["'].+["']/gi, name: 'Hardcoded Stripe Key' },
    ];

    secretPatterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name,
            description: `Hardcoded secret in ${language} code`,
            severity: 'HIGH',
            category: 'SECRETS',
            location: { file: filePath },
            codeSnippet: match.substring(0, 100),
            risk: 'Secrets can be extracted from source code',
            remediation: 'Use environment variables or secret management systems',
            cweId: 'CWE-798',
            owaspCategory: 'A02:2021-Cryptographic Failures'
          });
        });
      }
    });
  }
}

// ========== JAVASCRIPT/TYPESCRIPT ==========
class JavaScriptScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'JavaScript');
    this.checkXSS(code, filePath);
    this.checkCommandInjection(code, filePath);
    this.checkInsecureCrypto(code, filePath);
    this.checkPathTraversal(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /(SELECT|INSERT|UPDATE|DELETE).*(\$\{|\+\s*req\.)/gi, name: 'SQL Injection' },
      { regex: /query\(.*(`\$\{|\+\s*)/gi, name: 'SQL Injection in query()' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name,
            description: 'User input directly concatenated into SQL query',
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL commands',
            remediation: 'Use parameterized queries or ORM methods',
            cweId: 'CWE-89',
            owaspCategory: 'A03:2021-Injection'
          });
        });
      }
    });
  }

  private checkXSS(code: string, filePath: string) {
    const patterns = [
      { regex: /innerHTML\s*=\s*.*(req\.|params\.)/gi, name: 'DOM XSS via innerHTML' },
      { regex: /document\.write\(.*(req\.|params\.)/gi, name: 'DOM XSS via document.write()' },
      { regex: /eval\(.*(req\.|params\.)/gi, name: 'XSS via eval()' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Cross-Site Scripting (XSS)',
            description: `Potential XSS vulnerability via ${name}`,
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can inject malicious scripts',
            remediation: 'Use proper output encoding and Content Security Policy',
            cweId: 'CWE-79',
            owaspCategory: 'A03:2021-Injection'
          });
        });
      }
    });
  }

  private checkCommandInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /child_process\.(exec|execFile|spawn)\(.*(req\.|params\.)/gi, name: 'Command Injection' },
      { regex: /exec\(.*(`\$\{|\+\s*)/gi, name: 'Command Injection in exec()' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name,
            description: 'User input used in command execution',
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary commands',
            remediation: 'Use command parameterization',
            cweId: 'CWE-78',
            owaspCategory: 'A03:2021-Injection'
          });
        });
      }
    });
  }

  private checkInsecureCrypto(code: string, filePath: string) {
    const patterns = [
      { regex: /crypto\.createHash\("md5"\)/gi, name: 'Weak Hash Algorithm (MD5)' },
      { regex: /crypto\.createHash\("sha1"\)/gi, name: 'Weak Hash Algorithm (SHA-1)' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Insecure Cryptography',
            description: `Weak cryptographic practice: ${name}`,
            severity: 'HIGH',
            category: 'CRYPTO',
            location: { file: filePath },
            codeSnippet: match.substring(0, 100),
            risk: 'Weak cryptography can be broken',
            remediation: 'Use strong algorithms (SHA-256, bcrypt with 12+ rounds)',
            cweId: 'CWE-327',
            owaspCategory: 'A02:2021-Cryptographic Failures'
          });
        });
      }
    });
  }

  private checkPathTraversal(code: string, filePath: string) {
    const patterns = [
      { regex: /fs\.(readFile|writeFile)\(.*(req\.|params\.)/gi, name: 'Path Traversal' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Path Traversal',
            description: 'User input used in file path',
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can access arbitrary files',
            remediation: 'Validate and sanitize file paths',
            cweId: 'CWE-22',
            owaspCategory: 'A01:2021-Broken Access Control'
          });
        });
      }
    });
  }
}

// ========== PYTHON ==========
class PythonScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'Python');
    this.checkCommandInjection(code, filePath);
    this.checkPickleInsecure(code, filePath);
    this.checkEvalInjection(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /execute\(.*(%s|%d|%f).*%/gi, name: 'SQL Injection with formatting' },
      { regex: /cursor\.execute\(.*\+.*\)/gi, name: 'SQL Injection with concatenation' },
      { regex: /f"SELECT.*\{.*\}"/gi, name: 'SQL Injection with f-strings' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `Python SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use parameterized queries with ? placeholders',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkCommandInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /subprocess\.(run|call|Popen)\(.*shell=True.*\)/gi, name: 'Command Injection with shell=True' },
      { regex: /os\.system\(.*\+/gi, name: 'Command Injection with os.system' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Command Injection',
            description: `Python command injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary command execution',
            remediation: 'Avoid shell=True, use parameterized commands',
            cweId: 'CWE-78'
          });
        });
      }
    });
  }

  private checkPickleInsecure(code: string, filePath: string) {
    if (code.includes('pickle.loads') || code.includes('pickle.load')) {
      this.addVulnerability({
        name: 'Insecure Deserialization',
        description: 'Python pickle deserialization can execute arbitrary code',
        severity: 'CRITICAL',
        category: 'DESERIALIZATION',
        location: { file: filePath },
        codeSnippet: 'pickle.loads() or pickle.load() detected',
        risk: 'Arbitrary code execution',
        remediation: 'Use JSON or safer serialization formats',
        cweId: 'CWE-502',
        owaspCategory: 'A08:2021-Software and Data Integrity Failures'
      });
    }
  }

  private checkEvalInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /eval\(.*\+/gi, name: 'Eval Injection' },
      { regex: /exec\(.*\+/gi, name: 'Exec Injection' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Code Injection',
            description: `Python code injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary code execution',
            remediation: 'Avoid eval() and exec() with user input',
            cweId: 'CWE-94'
          });
        });
      }
    });
  }
}

// ========== JAVA ==========
class JavaScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'Java');
    this.checkCommandInjection(code, filePath);
    this.checkXSS(code, filePath);
    this.checkDeserialization(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /Statement\.executeQuery\(.*\+.*\)/gi, name: 'SQL Injection with Statement' },
      { regex: /PreparedStatement.*\+.*\)/gi, name: 'SQL Injection with concatenated PreparedStatement' },
      { regex: /"SELECT.*"\s*\+\s*\w+/gi, name: 'SQL Injection with string concatenation' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `Java SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use PreparedStatement with parameter binding',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkCommandInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /Runtime\.getRuntime\(\)\.exec\(.*\+.*\)/gi, name: 'Command Injection with Runtime.exec' },
      { regex: /ProcessBuilder\(.*\+.*\)/gi, name: 'Command Injection with ProcessBuilder' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Command Injection',
            description: `Java command injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary command execution',
            remediation: 'Use parameterized commands',
            cweId: 'CWE-78'
          });
        });
      }
    });
  }

  private checkXSS(code: string, filePath: string) {
    const patterns = [
      { regex: /response\.getWriter\(\)\.write\(.*\+.*\)/gi, name: 'XSS with response writer' },
      { regex: /out\.print\(.*\+.*\)/gi, name: 'XSS with out.print' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Cross-Site Scripting (XSS)',
            description: `Java XSS vulnerability via ${name}`,
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can inject malicious scripts',
            remediation: 'Use JSP EL escaping or OWASP Java Encoder',
            cweId: 'CWE-79'
          });
        });
      }
    });
  }

  private checkDeserialization(code: string, filePath: string) {
    const patterns = [
      { regex: /ObjectInputStream.*readObject\(\)/gi, name: 'Insecure Deserialization' },
      { regex: /readObject\(.*\)/gi, name: 'Deserialization method' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Insecure Deserialization',
            description: 'Java insecure deserialization',
            severity: 'CRITICAL',
            category: 'DESERIALIZATION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary code execution',
            remediation: 'Use safe serialization formats or validate input',
            cweId: 'CWE-502'
          });
        });
      }
    });
  }
}

// ========== PHP ==========
class PHPScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'PHP');
    this.checkXSS(code, filePath);
    this.checkCommandInjection(code, filePath);
    this.checkFileInclusion(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /mysql_query\(.*\$/gi, name: 'SQL Injection with mysql_query' },
      { regex: /"SELECT.*"\s*\.\s*\$/gi, name: 'SQL Injection with concatenation' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `PHP SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use prepared statements with PDO',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkXSS(code: string, filePath: string) {
    const patterns = [
      { regex: /echo\s*\$_(GET|POST)\[/gi, name: 'XSS via echo' },
      { regex: /print\s*\$_(GET|POST)\[/gi, name: 'XSS via print' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Cross-Site Scripting (XSS)',
            description: `PHP XSS vulnerability via ${name}`,
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can inject malicious scripts',
            remediation: 'Use htmlspecialchars() for output',
            cweId: 'CWE-79'
          });
        });
      }
    });
  }

  private checkCommandInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /system\(.*\$_(GET|POST)/gi, name: 'Command Injection with system()' },
      { regex: /exec\(.*\$_(GET|POST)/gi, name: 'Command Injection with exec()' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Command Injection',
            description: `PHP command injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary command execution',
            remediation: 'Use escapeshellarg()',
            cweId: 'CWE-78'
          });
        });
      }
    });
  }

  private checkFileInclusion(code: string, filePath: string) {
    const patterns = [
      { regex: /include\(.*\$_(GET|POST)/gi, name: 'File Inclusion with include()' },
      { regex: /require\(.*\$_(GET|POST)/gi, name: 'File Inclusion with require()' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Local File Inclusion (LFI)',
            description: `PHP file inclusion via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can include arbitrary files',
            remediation: 'Use whitelists for included files',
            cweId: 'CWE-98'
          });
        });
      }
    });
  }
}

// ========== GO ==========
class GoScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'Go');
    this.checkCommandInjection(code, filePath);
    this.checkPathTraversal(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /db\.Query\(.*fmt\.Sprintf.*\)/gi, name: 'SQL Injection with fmt.Sprintf' },
      { regex: /db\.Query\(.*\+.*\)/gi, name: 'SQL Injection with concatenation' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `Go SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use parameterized queries with ? placeholders',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkCommandInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /exec\.Command\(.*\+.*\)/gi, name: 'Command Injection with exec.Command' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Command Injection',
            description: `Go command injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary command execution',
            remediation: 'Use exec.Command with separate arguments',
            cweId: 'CWE-78'
          });
        });
      }
    });
  }

  private checkPathTraversal(code: string, filePath: string) {
    const patterns = [
      { regex: /os\.Open\(.*\+.*\)/gi, name: 'Path Traversal with os.Open' },
      { regex: /ioutil\.ReadFile\(.*\+.*\)/gi, name: 'Path Traversal with ioutil.ReadFile' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Path Traversal',
            description: `Go path traversal via ${name}`,
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Access arbitrary files',
            remediation: 'Validate and sanitize file paths',
            cweId: 'CWE-22'
          });
        });
      }
    });
  }
}

// ========== RUST ==========
class RustScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'Rust');
    this.checkUnsafeBlocks(code, filePath);
    this.checkPanicUsage(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /format!\("SELECT.*\{.*\}".*\)/gi, name: 'SQL Injection with format!' },
      { regex: /execute\(.*format!.*\)/gi, name: 'SQL Injection in execute with format!' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `Rust SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use parameterized queries',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkUnsafeBlocks(code: string, filePath: string) {
    if (code.includes('unsafe {')) {
      this.addVulnerability({
        name: 'Unsafe Rust Code',
        description: 'Unsafe Rust block detected',
        severity: 'HIGH',
        category: 'MEMORY',
        location: { file: filePath },
        codeSnippet: 'unsafe { ... }',
        risk: 'Memory safety violations possible',
        remediation: 'Minimize unsafe blocks, ensure proper bounds checking',
        cweId: 'CWE-119',
        owaspCategory: 'A08:2021-Software and Data Integrity Failures'
      });
    }
  }

  private checkPanicUsage(code: string, filePath: string) {
    const patterns = [
      { regex: /panic!\(.*\)/gi, name: 'Panic usage' },
      { regex: /unwrap\(\)/gi, name: 'Unwrap usage' },
      { regex: /expect\(.*\)/gi, name: 'Expect usage' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches && matches.length > 3) {
        this.addVulnerability({
          name: 'Excessive Panic Usage',
          description: `Multiple ${name} calls found`,
          severity: 'MEDIUM',
          category: 'ERROR',
          location: { file: filePath },
          codeSnippet: `${matches.length} instances found`,
          risk: 'Application may crash unexpectedly',
          remediation: 'Use proper error handling with Result types',
          cweId: 'CWE-248'
        });
      }
    });
  }
}

// ========== C# ==========
class CSharpScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'C#');
    this.checkCommandInjection(code, filePath);
    this.checkXSS(code, filePath);
    this.checkDeserialization(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /SqlCommand\(.*\+.*\)/gi, name: 'SQL Injection with SqlCommand' },
      { regex: /"SELECT.*"\s*\+\s*\w+/gi, name: 'SQL Injection with concatenation' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `C# SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use parameterized queries with SqlParameter',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkCommandInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /Process\.Start\(.*\+.*\)/gi, name: 'Command Injection with Process.Start' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Command Injection',
            description: `C# command injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary command execution',
            remediation: 'Use parameterized commands',
            cweId: 'CWE-78'
          });
        });
      }
    });
  }

  private checkXSS(code: string, filePath: string) {
    const patterns = [
      { regex: /Response\.Write\(.*\+.*\)/gi, name: 'XSS with Response.Write' },
      { regex: /<%=.*%>/gi, name: 'XSS with ASP.NET inline expression' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Cross-Site Scripting (XSS)',
            description: `C# XSS vulnerability via ${name}`,
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can inject malicious scripts',
            remediation: 'Use HttpUtility.HtmlEncode for output',
            cweId: 'CWE-79'
          });
        });
      }
    });
  }

  private checkDeserialization(code: string, filePath: string) {
    const patterns = [
      { regex: /BinaryFormatter\.Deserialize/gi, name: 'Insecure Deserialization with BinaryFormatter' },
      { regex: /JavaScriptSerializer\.Deserialize/gi, name: 'Deserialization with JavaScriptSerializer' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Insecure Deserialization',
            description: `C# insecure deserialization via ${name}`,
            severity: 'CRITICAL',
            category: 'DESERIALIZATION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary code execution',
            remediation: 'Use safe serializers like System.Text.Json',
            cweId: 'CWE-502'
          });
        });
      }
    });
  }
}

// ========== SWIFT ==========
class SwiftScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'Swift');
    this.checkXSS(code, filePath);
    this.checkForceUnwrap(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /executeQuery\(.*\+.*\)/gi, name: 'SQL Injection with executeQuery' },
      { regex: /"SELECT.*"\s*\+\s*\w+/gi, name: 'SQL Injection with concatenation' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `Swift SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use parameterized queries',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkXSS(code: string, filePath: string) {
    const patterns = [
      { regex: /loadHTMLString\(.*\+.*\)/gi, name: 'XSS with loadHTMLString' },
      { regex: /stringByEvaluatingJavaScriptFromString\(.*\)/gi, name: 'XSS with JavaScript evaluation' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Cross-Site Scripting (XSS)',
            description: `Swift XSS vulnerability via ${name}`,
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can inject malicious scripts',
            remediation: 'Sanitize HTML input, use WKWebView',
            cweId: 'CWE-79'
          });
        });
      }
    });
  }

  private checkForceUnwrap(code: string, filePath: string) {
    const patterns = [
      { regex: /!/g, name: 'Force unwrap operator' },
      { regex: /try!/g, name: 'Force try operator' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches && matches.length > 5) {
        this.addVulnerability({
          name: 'Excessive Force Unwrapping',
          description: `Multiple ${name} operators found`,
          severity: 'MEDIUM',
          category: 'ERROR',
          location: { file: filePath },
          codeSnippet: `${matches.length} instances found`,
          risk: 'Application may crash on nil values',
          remediation: 'Use optional binding (if let) or guard statements',
          cweId: 'CWE-248'
        });
      }
    });
  }
}

// ========== KOTLIN ==========
class KotlinScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'Kotlin');
    this.checkXSS(code, filePath);
    this.checkExceptionSwallowing(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /rawQuery\(.*\+.*\)/gi, name: 'SQL Injection with rawQuery' },
      { regex: /execSQL\(.*\+.*\)/gi, name: 'SQL Injection with execSQL' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `Kotlin SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use parameterized queries with ? placeholders',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkXSS(code: string, filePath: string) {
    const patterns = [
      { regex: /loadUrl\(.*\+.*\)/gi, name: 'XSS with loadUrl' },
      { regex: /evaluateJavascript\(.*\+.*\)/gi, name: 'XSS with evaluateJavascript' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Cross-Site Scripting (XSS)',
            description: `Kotlin XSS vulnerability via ${name}`,
            severity: 'HIGH',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can inject malicious scripts',
            remediation: 'Validate and encode URLs',
            cweId: 'CWE-79'
          });
        });
      }
    });
  }

  private checkExceptionSwallowing(code: string, filePath: string) {
    if (code.includes('catch (e: Exception) {}') || code.includes('catch (e: Throwable) {}')) {
      this.addVulnerability({
        name: 'Exception Swallowing',
        description: 'Empty catch block detected',
        severity: 'MEDIUM',
        category: 'ERROR',
        location: { file: filePath },
        codeSnippet: 'catch (e: Exception) {}',
        risk: 'Errors are silently ignored',
        remediation: 'Log exceptions or handle them appropriately',
        cweId: 'CWE-391'
      });
    }
  }
}

// ========== RUBY ==========
class RubyScanner extends BaseScanner {
  scan(code: string, filePath: string) {
    this.vulnerabilities = [];
    
    this.checkSQLInjection(code, filePath);
    this.checkHardcodedSecrets(code, filePath, 'Ruby');
    this.checkCommandInjection(code, filePath);
    this.checkEvalInjection(code, filePath);

    return { vulnerabilities: this.vulnerabilities, summary: this.getSummary() };
  }

  private checkSQLInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /execute\(.*#\{.*\}\)/gi, name: 'SQL Injection with string interpolation' },
      { regex: /"SELECT.*#\{.*\}"/gi, name: 'SQL Injection with interpolation in string' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'SQL Injection',
            description: `Ruby SQL injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Attackers can execute arbitrary SQL',
            remediation: 'Use parameterized queries with ? placeholders',
            cweId: 'CWE-89'
          });
        });
      }
    });
  }

  private checkCommandInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /`.*#\{.*\}`/gi, name: 'Command Injection with backticks' },
      { regex: /system\(.*#\{.*\}\)/gi, name: 'Command Injection with system()' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Command Injection',
            description: `Ruby command injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary command execution',
            remediation: 'Use system() with separate arguments',
            cweId: 'CWE-78'
          });
        });
      }
    });
  }

  private checkEvalInjection(code: string, filePath: string) {
    const patterns = [
      { regex: /eval\(.*#\{.*\}\)/gi, name: 'Eval Injection' },
      { regex: /instance_eval\(.*#\{.*\}\)/gi, name: 'Instance Eval Injection' },
    ];

    patterns.forEach(({ regex, name }) => {
      const matches = code.match(regex);
      if (matches) {
        matches.forEach(match => {
          this.addVulnerability({
            name: 'Code Injection',
            description: `Ruby code injection via ${name}`,
            severity: 'CRITICAL',
            category: 'INJECTION',
            location: { file: filePath },
            codeSnippet: match.substring(0, 150),
            risk: 'Arbitrary code execution',
            remediation: 'Avoid eval() with user input',
            cweId: 'CWE-94'
          });
        });
      }
    });
  }
}

// ========== ADD MORE LANGUAGES HERE ==========
// We'll add simpler scanners for the remaining languages
// Each scanner extends BaseScanner and implements language-specific checks

// ========== SCANNER FACTORY ==========
const scannerFactory = {
  javascript: JavaScriptScanner,
  typescript: JavaScriptScanner, // Uses same scanner as JavaScript
  python: PythonScanner,
  java: JavaScanner,
  php: PHPScanner,
  go: GoScanner,
  rust: RustScanner,
  csharp: CSharpScanner,
  swift: SwiftScanner,
  kotlin: KotlinScanner,
  ruby: RubyScanner,
  // Placeholder scanners for other languages
  c: JavaScriptScanner,
  cpp: JavaScriptScanner,
  r: JavaScriptScanner,
  matlab: JavaScriptScanner,
  perl: JavaScriptScanner,
  scala: JavaScriptScanner,
  haskell: JavaScriptScanner,
  lua: JavaScriptScanner,
  dart: JavaScriptScanner,
  elixir: JavaScriptScanner,
};

// ========== MAIN API HANDLER ==========
export async function POST(request: NextRequest) {
  try {
    const { code, language, filePath } = await request.json();

    if (!code) {
      return NextResponse.json(
        { error: 'Code is required' },
        { status: 400 }
      );
    }

    const normalizedLanguage = language.toLowerCase();
    const ScannerClass = scannerFactory[normalizedLanguage as keyof typeof scannerFactory];
    
    if (!ScannerClass) {
      return NextResponse.json(
        { 
          success: true,
          data: {
            vulnerabilities: [{
              id: 'unsupported_lang',
              name: 'Language Not Fully Supported',
              description: `Basic scanning for ${language} - advanced features coming soon`,
              severity: 'LOW',
              category: 'INFO',
              location: { file: filePath || 'unknown' },
              codeSnippet: 'Language support in development',
              risk: 'Limited scanning capabilities',
              remediation: 'Check back for updates',
              detectedAt: new Date().toISOString()
            }],
            summary: { total: 1, critical: 0, high: 0, medium: 0, low: 1 },
            scanDuration: 0,
            scanner: `${language} (Basic Support)`
          }
        }
      );
    }

    const scanner = new ScannerClass();
    const startTime = Date.now();
    const result = scanner.scan(code, filePath || 'unknown');
    const scanDuration = Date.now() - startTime;

    return NextResponse.json({
      success: true,
      data: {
        ...result,
        scanDuration,
        scanner: language.charAt(0).toUpperCase() + language.slice(1)
      }
    });

  } catch (error) {
    console.error('Scan error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET() {
  const languages = [
    // Fully implemented
    'JavaScript', 'TypeScript', 'Python', 'Java', 'PHP', 'Go', 'Rust', 'C#',
    // Partially implemented  
    'Swift', 'Kotlin', 'Ruby',
    // Basic support
    'C', 'C++', 'R', 'MATLAB', 'Perl', 'Scala', 'Haskell', 'Lua', 'Dart', 'Elixir'
  ];

  return NextResponse.json({ 
    message: 'Security Scanner API',
    supportedLanguages: languages,
    fullyImplemented: ['JavaScript/TypeScript', 'Python', 'Java', 'PHP', 'Go', 'Rust', 'C#'],
    partiallyImplemented: ['Swift', 'Kotlin', 'Ruby'],
    basicSupport: ['C', 'C++', 'R', 'MATLAB', 'Perl', 'Scala', 'Haskell', 'Lua', 'Dart', 'Elixir'],
    endpoint: '/api/scan',
    method: 'POST'
  });
}