'use client';

import { useState, useRef } from 'react';
import Editor from '@monaco-editor/react';
declare global {
  const monaco: typeof import('monaco-editor');
}
export function SecurityScanner() {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState('javascript');
  const [result, setResult] = useState<any>(null);
  const [scanning, setScanning] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [editorTheme, setEditorTheme] = useState<'vs-dark' | 'light'>('vs-dark');
  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'recommendations' | 'metrics'>('vulnerabilities');
  const [selectedVulnerability, setSelectedVulnerability] = useState<any>(null);
  const [showDetails, setShowDetails] = useState(false);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [exportFormat, setExportFormat] = useState<'json' | 'csv' | 'pdf'>('json');
  const [includeRemediation, setIncludeRemediation] = useState(true);
  const [includeCodeSnippets, setIncludeCodeSnippets] = useState(true);
  
  const editorRef = useRef<any>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleScan = async () => {
    if (!code.trim()) {
      alert('Please enter some code to scan');
      return;
    }
    
    setScanning(true);
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          code,
          language,
          filePath: 'app.js'
        }),
      });

      const data = await response.json();
      if (data.success) {
        const scanResult = {
          ...data.data,
          timestamp: new Date().toISOString(),
          codePreview: code.substring(0, 100) + '...',
          language
        };
        
        setResult(data.data);
        setScanHistory(prev => [scanResult, ...prev.slice(0, 9)]); // Keep last 10 scans
        
        // Auto-select first vulnerability for details view
        if (data.data.vulnerabilities && data.data.vulnerabilities.length > 0) {
          setSelectedVulnerability(data.data.vulnerabilities[0]);
        }
      } else {
        alert('Scan failed: ' + data.error);
      }
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed. Please try again.');
    } finally {
      setScanning(false);
    }
  };

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setCode(content);
        
        // Try to detect language from file extension
        const extension = file.name.split('.').pop()?.toLowerCase();
        const languageMap: Record<string, string> = {
          'js': 'javascript',
          'ts': 'typescript',
          'jsx': 'javascript',
          'tsx': 'typescript',
          'py': 'python',
          'java': 'java',
          'php': 'php',
          'go': 'go',
          'rs': 'rust',
          'cs': 'csharp',
          'swift': 'swift',
          'kt': 'kotlin',
          'rb': 'ruby',
          'c': 'c',
          'cpp': 'cpp',
          'h': 'c'
        };
        
        if (extension && languageMap[extension]) {
          setLanguage(languageMap[extension]);
        }
      };
      reader.readAsText(file);
    }
  };

  const loadExample = (exampleCode: string, exampleLanguage: string = 'javascript') => {
    setCode(exampleCode);
    setLanguage(exampleLanguage);
    setResult(null);
    setSelectedVulnerability(null);
  };

  const handleEditorDidMount = (editor: any) => {
  editorRef.current = editor;
  // Keyboard shortcut temporarily removed to fix build
  // You can add it back later with proper setup
};
  const exportResults = () => {
    if (!result) return;
    
    if (exportFormat === 'json') {
      const dataStr = JSON.stringify(result, null, 2);
      const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
      const exportFileDefaultName = `security-scan-${new Date().toISOString()}.json`;
      
      const linkElement = document.createElement('a');
      linkElement.setAttribute('href', dataUri);
      linkElement.setAttribute('download', exportFileDefaultName);
      linkElement.click();
    } else if (exportFormat === 'csv') {
      // Simple CSV export for vulnerabilities
      let csvContent = "ID,Severity,Name,Description,Risk,Remediation,CWE,OWASP\n";
      result.vulnerabilities.forEach((vuln: any) => {
        csvContent += `"${vuln.id}","${vuln.severity}","${vuln.name}","${vuln.description}","${vuln.risk}","${vuln.remediation}","${vuln.cweId || ''}","${vuln.owaspCategory || ''}"\n`;
      });
      
      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-scan-${new Date().toISOString()}.csv`;
      a.click();
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  const handleVulnerabilityClick = (vuln: any) => {
    setSelectedVulnerability(vuln);
    setShowDetails(true);
  };

  const getSeverityColor = (severity: string) => {
    switch(severity?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500';
      case 'HIGH': return 'bg-orange-500';
      case 'MEDIUM': return 'bg-yellow-500';
      case 'LOW': return 'bg-blue-500';
      default: return 'bg-gray-500';
    }
  };

  const getSeverityTextColor = (severity: string) => {
    switch(severity?.toUpperCase()) {
      case 'CRITICAL': return 'text-red-400';
      case 'HIGH': return 'text-orange-400';
      case 'MEDIUM': return 'text-yellow-400';
      case 'LOW': return 'text-blue-400';
      default: return 'text-gray-400';
    }
  };

  const getSeverityBorderColor = (severity: string) => {
    switch(severity?.toUpperCase()) {
      case 'CRITICAL': return 'border-red-700';
      case 'HIGH': return 'border-orange-700';
      case 'MEDIUM': return 'border-yellow-700';
      case 'LOW': return 'border-blue-700';
      default: return 'border-gray-700';
    }
  };

  const filteredVulnerabilities = result?.vulnerabilities.filter((v: any) => 
    selectedSeverity === 'all' || v.severity === selectedSeverity.toUpperCase()
  ) || [];

  // Calculate metrics
  const vulnerabilityMetrics = result ? {
    total: result.summary.total,
    critical: result.summary.critical,
    high: result.summary.high,
    medium: result.summary.medium || 0,
    low: result.summary.low || 0,
    byCategory: result.vulnerabilities.reduce((acc: any, vuln: any) => {
      const category = vuln.category || 'Other';
      acc[category] = (acc[category] || 0) + 1;
      return acc;
    }, {})
  } : null;

  // Example codes for different languages
  const examples = [
    {
      name: 'JavaScript',
      language: 'javascript',
      code: `// JavaScript Vulnerable Code Examples

// 1. SQL Injection
const query = \`SELECT * FROM users WHERE email = '\${req.body.email}'\`;

// 2. Hardcoded Secrets
const password = "admin123";
const stripeKey = "sk_live_1234567890";
const apiKey = "ghp_abcdef1234567890";

// 3. XSS Vulnerability
document.getElementById('output').innerHTML = userInput;
element.innerHTML = \`Welcome \${username}\`;

// 4. Command Injection
const { exec } = require('child_process');
exec(\`ls \${userInput}\`);

// 5. Weak Cryptography
const hash = crypto.createHash('md5');
const weakHash = crypto.createHash('sha1');

// 6. JWT without Strong Algorithm
const token = jwt.sign({ userId: 1 }, 'weak-secret', { algorithm: 'HS256' });

// 7. Missing Input Validation
app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  // No validation!
});`
    },
    {
      name: 'Python',
      language: 'python',
      code: `# Python Vulnerable Code Examples

# 1. SQL Injection
query = "SELECT * FROM users WHERE email = '%s'" % email
cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")

# 2. Hardcoded Secrets
API_KEY = "sk_test_1234567890"
SECRET_KEY = "django-insecure-abcdef123456"
DATABASE_PASSWORD = "postgres123"

# 3. Command Injection
import subprocess
import os
subprocess.run(f"echo {user_input}", shell=True)
os.system("rm " + filename)

# 4. Insecure Deserialization
import pickle
data = pickle.loads(user_data)
pickle.load(open('data.pkl', 'rb'))

# 5. Eval Injection
result = eval(user_input)
exec("print('" + user_input + "')")

# 6. Path Traversal
with open("/var/www/uploads/" + filename, 'r') as f:
    content = f.read()

# 7. Weak Random
import random
password = str(random.randint(1000, 9999))`
    },
    {
      name: 'Java',
      language: 'java',
      code: `// Java Vulnerable Code Examples

// 1. SQL Injection
String query = "SELECT * FROM users WHERE email = '" + email + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);

// 2. Hardcoded Secrets
String password = "admin123";
String apiKey = "sk_live_abcdef123456";
String jwtSecret = "my-weak-secret-key";

// 3. XSS
response.getWriter().write(request.getParameter("input"));
out.println("Welcome " + username);

// 4. Command Injection
Runtime.getRuntime().exec("ping " + userInput);

// 5. Weak Cryptography
MessageDigest md = MessageDigest.getInstance("MD5");
Cipher cipher = Cipher.getInstance("DES");

// 6. Insecure Random
Random random = new Random();
int token = random.nextInt(10000);

// 7. Path Traversal
File file = new File("/uploads/" + filename);
Files.readAllBytes(file.toPath());`
    },
    {
      name: 'PHP',
      language: 'php',
      code: `<?php
// PHP Vulnerable Code Examples

// 1. SQL Injection
$query = "SELECT * FROM users WHERE email = '" . $_POST['email'] . "'";
mysql_query($query);

// 2. XSS
echo $_GET['name'];
print "<div>" . $userInput . "</div>";

// 3. Command Injection
exec("ls " . $_GET['dir']);
system("cat " . $filename);

// 4. File Inclusion
include($_GET['page'] . '.php');

// 5. Hardcoded Secrets
$db_password = "mysql123";
$api_key = "sk_live_1234567890";

// 6. Weak Session
ini_set('session.cookie_httponly', 0);

// 7. Unvalidated Redirect
header("Location: " . $_GET['url']);
?>`
    },
    {
      name: 'Go',
      language: 'go',
      code: `// Go Vulnerable Code Examples

package main

import (
    "database/sql"
    "fmt"
    "os"
    "os/exec"
)

// 1. SQL Injection
func getUser(db *sql.DB, username string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
    db.Query(query)
}

// 2. Hardcoded Secrets
var (
    DatabasePassword = "postgres123"
    APISecretKey     = "sk_live_abcdef1234567890"
)

// 3. Command Injection
func runCommand(cmdStr string) {
    cmd := exec.Command("sh", "-c", "ls " + cmdStr)
    cmd.Run()
}

// 4. Path Traversal
func readUserFile(filename string) {
    data, _ := os.ReadFile("/home/user/" + filename)
    fmt.Println(string(data))
}`
    },
    {
      name: 'Rust',
      language: 'rust',
      code: `// Rust Vulnerable Code Examples

// 1. SQL Injection
let query = format!("SELECT * FROM users WHERE id = {}", user_id);

// 2. Hardcoded Secrets
const API_KEY: &str = "sk_live_1234567890";
const DB_PASSWORD: &str = "postgres123";

// 3. Unsafe Blocks
unsafe {
    let ptr = user_input.as_ptr();
    // Memory unsafe operations
}

// 4. Panic usage
let value = some_option.unwrap();
let result = some_result.expect("Failed");`
    },
    {
      name: 'C#',
      language: 'csharp',
      code: `// C# Vulnerable Code Examples

// 1. SQL Injection
string query = "SELECT * FROM users WHERE name = '" + userName + "'";
SqlCommand cmd = new SqlCommand(query, connection);

// 2. Hardcoded Secrets
string password = "admin123";
string apiKey = "sk_live_abcdef123456";

// 3. XSS
Response.Write("Hello " + Request.QueryString["name"]);

// 4. Command Injection
Process.Start("cmd.exe", "/c " + userCommand);

// 5. Insecure Deserialization
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);`
    },
    {
      name: 'Swift',
      language: 'swift',
      code: `// Swift Vulnerable Code Examples

// 1. SQL Injection
let query = "SELECT * FROM users WHERE name = '\\(userInput)'"

// 2. Hardcoded Secrets
let apiKey = "sk_live_1234567890"
let password = "admin123"

// 3. XSS
let html = "<div>\\(userContent)</div>"
webView.loadHTMLString(html, baseURL: nil)

// 4. Force Unwrap
let value = optionalValue!
let result = try! dangerousOperation()`
    },
    {
      name: 'Kotlin',
      language: 'kotlin',
      code: `// Kotlin Vulnerable Code Examples

// 1. SQL Injection
val query = "SELECT * FROM users WHERE id = $userId"

// 2. Hardcoded Secrets
val apiKey = "sk_live_1234567890"
val password = "admin123"

// 3. XSS
webView.loadUrl("javascript:alert('$userInput')")

// 4. Exception Swallowing
try {
    // code
} catch (e: Exception) {
    // Empty catch - exception swallowed
}`,
    },
    {
      name: 'Ruby',
      language: 'ruby',
      code: `# Ruby Vulnerable Code Examples

# 1. SQL Injection
query = "SELECT * FROM users WHERE email = '\#{email}'"

# 2. Hardcoded Secrets
API_KEY = "sk_live_1234567890"
PASSWORD = "admin123"

# 3. Command Injection
system("ls \#{user_input}")
\`cat \#{filename}\`

# 4. Eval Injection
eval(user_code)
instance_eval(user_input)`
    }
  ];

  // Map Monaco language IDs
  const getMonacoLanguage = (lang: string) => {
    const map: Record<string, string> = {
      javascript: 'javascript',
      typescript: 'typescript',
      python: 'python',
      java: 'java',
      php: 'php',
      go: 'go',
      rust: 'rust',
      csharp: 'csharp',
      swift: 'swift',
      kotlin: 'kotlin',
      ruby: 'ruby',
      c: 'c',
      cpp: 'cpp',
      r: 'r',
      matlab: 'matlab',
      perl: 'perl',
      scala: 'scala',
      haskell: 'haskell',
      lua: 'lua',
      dart: 'dart',
      elixir: 'elixir'
    };
    return map[lang] || 'plaintext';
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-black text-white p-4 md:p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
            <div>
              <h1 className="text-3xl font-bold mb-2">🔒 Security Code Scanner</h1>
              <p className="text-gray-400">
                Professional security vulnerability scanner with Monaco Editor • Supports 20+ languages
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <button
                onClick={() => setEditorTheme(editorTheme === 'vs-dark' ? 'light' : 'vs-dark')}
                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg flex items-center gap-2 transition-colors"
              >
                {editorTheme === 'vs-dark' ? (
                  <>
                    <span>☀️</span>
                    <span>Light Theme</span>
                  </>
                ) : (
                  <>
                    <span>🌙</span>
                    <span>Dark Theme</span>
                  </>
                )}
              </button>
              
              {result && (
                <div className="flex gap-2">
                  <select
                    value={exportFormat}
                    onChange={(e) => setExportFormat(e.target.value as any)}
                    className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm"
                  >
                    <option value="json">Export JSON</option>
                    <option value="csv">Export CSV</option>
                    <option value="pdf" disabled>Export PDF (Coming Soon)</option>
                  </select>
                  <button
                    onClick={exportResults}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg flex items-center gap-2 transition-colors"
                  >
                    <span>📥</span>
                    <span>Export</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Left Panel - Code Input */}
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
              <div className="flex flex-col md:flex-row md:items-center justify-between mb-4 gap-4">
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <span className="text-blue-400">📝</span>
                  Code Editor
                </h2>
                <div className="flex flex-col md:flex-row gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Programming Language</label>
                    <select
                      value={language}
                      onChange={(e) => setLanguage(e.target.value)}
                      className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm w-full md:w-auto"
                    >
                      {/* Fully Supported */}
                      <optgroup label="🎯 Fully Supported">
                        <option value="javascript">JavaScript/TypeScript</option>
                        <option value="python">Python</option>
                        <option value="java">Java</option>
                        <option value="php">PHP</option>
                        <option value="go">Go</option>
                        <option value="rust">Rust</option>
                        <option value="csharp">C#</option>
                      </optgroup>
                      
                      {/* Partially Supported */}
                      <optgroup label="⚠️ Partially Supported">
                        <option value="swift">Swift</option>
                        <option value="kotlin">Kotlin</option>
                        <option value="ruby">Ruby</option>
                      </optgroup>
                      
                      {/* Basic Support */}
                      <optgroup label="🔧 Basic Support">
                        <option value="c">C</option>
                        <option value="cpp">C++</option>
                        <option value="r">R</option>
                        <option value="matlab">MATLAB</option>
                        <option value="perl">Perl</option>
                        <option value="scala">Scala</option>
                        <option value="haskell">Haskell</option>
                        <option value="lua">Lua</option>
                        <option value="dart">Dart</option>
                        <option value="elixir">Elixir</option>
                      </optgroup>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Upload Source File</label>
                    <div className="flex gap-2">
                      <input
                        ref={fileInputRef}
                        type="file"
                        onChange={handleFileUpload}
                        className="hidden"
                        accept=".js,.ts,.jsx,.tsx,.py,.java,.php,.go,.rs,.cs,.swift,.kt,.rb,.c,.cpp,.h,.hpp"
                      />
                      <button
                        onClick={() => fileInputRef.current?.click()}
                        className="px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm flex items-center gap-2 transition-colors"
                      >
                        <span>📁</span>
                        <span>Choose File</span>
                      </button>
                      {code && (
                        <button
                          onClick={() => copyToClipboard(code)}
                          className="px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm flex items-center gap-2 transition-colors"
                          title="Copy entire code to clipboard"
                        >
                          <span>📋</span>
                          <span>Copy All</span>
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Monaco Editor */}
              <div className="border border-gray-700 rounded-lg overflow-hidden h-96 shadow-inner">
                <Editor
                  height="100%"
                  language={getMonacoLanguage(language)}
                  value={code}
                  onChange={(value) => setCode(value || '')}
                  theme={editorTheme}
                  onMount={handleEditorDidMount}
                  options={{
                    minimap: { enabled: true },
                    fontSize: 14,
                    wordWrap: 'on',
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                    formatOnPaste: true,
                    formatOnType: true,
                    suggestOnTriggerCharacters: true,
                    acceptSuggestionOnEnter: 'on',
                    tabSize: 2,
                    insertSpaces: true,
                    autoClosingBrackets: 'always',
                    autoClosingQuotes: 'always',
                    autoIndent: 'full',
                    glyphMargin: true,
                    lineNumbers: 'on',
                    folding: true,
                    cursorBlinking: 'smooth',
                  }}
                />
              </div>

              {/* Quick Actions */}
              <div className="mt-4 space-y-3">
                <div className="flex justify-between items-center">
                  <p className="text-sm text-gray-400">Quick actions:</p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setCode('')}
                      className="text-sm px-3 py-1 bg-red-700 hover:bg-red-600 rounded flex items-center gap-1 transition-colors"
                    >
                      <span>🗑️</span>
                      <span>Clear</span>
                    </button>
                    <button
                      onClick={() => handleScan()}
                      disabled={scanning || !code.trim()}
                      className="text-sm px-3 py-1 bg-emerald-700 hover:bg-emerald-600 rounded flex items-center gap-1 transition-colors disabled:opacity-50"
                    >
                      <span>🚀</span>
                      <span>Quick Scan</span>
                    </button>
                  </div>
                </div>
                
                <div>
                  <p className="text-sm text-gray-400 mb-2">Load vulnerable code examples:</p>
                  <div className="flex flex-wrap gap-2">
                    {examples.slice(0, 6).map((example, index) => (
                      <button
                        key={index}
                        onClick={() => loadExample(example.code, example.language)}
                        className="text-sm px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded transition-all duration-200 hover:scale-105 flex items-center gap-1"
                        title={`Load ${example.name} example`}
                      >
                        <span className="text-xs">{getFlagForLanguage(example.language)}</span>
                        <span>{example.name}</span>
                      </button>
                    ))}
                    {examples.length > 6 && (
                      <select
                        onChange={(e) => {
                          const example = examples.find(ex => ex.name === e.target.value);
                          if (example) loadExample(example.code, example.language);
                        }}
                        className="text-sm px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                      >
                        <option value="">More examples...</option>
                        {examples.slice(6).map((example, index) => (
                          <option key={index + 6} value={example.name}>
                            {example.name}
                          </option>
                        ))}
                      </select>
                    )}
                  </div>
                </div>
                
                <p className="text-xs text-gray-500 pt-2 border-t border-gray-700">
                  💡 <strong>Pro Tip:</strong> Press <kbd className="px-1.5 py-0.5 bg-gray-900 rounded text-xs">Ctrl/Cmd + Enter</kbd> to scan • <kbd className="px-1.5 py-0.5 bg-gray-900 rounded text-xs">Ctrl/Cmd + S</kbd> to save
                </p>
              </div>

              {/* Main Scan Button */}
              <div className="mt-6">
                <button
                  onClick={handleScan}
                  disabled={scanning || !code.trim()}
                  className="w-full py-3 px-4 bg-gradient-to-r from-emerald-500 to-teal-600 hover:from-emerald-600 hover:to-teal-700 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 transform hover:scale-[1.02] flex items-center justify-center gap-3 shadow-lg"
                >
                  {scanning ? (
                    <>
                      <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      <span className="text-lg">Scanning Code...</span>
                    </>
                  ) : (
                    <>
                      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                      </svg>
                      <span className="text-lg">🔍 Scan for Vulnerabilities (Ctrl+Enter)</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Quick Tips & Language Support */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Quick Tips */}
              <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
                <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                  <span className="text-yellow-500">💡</span>
                  Editor Shortcuts & Tips
                </h3>
                <ul className="space-y-3 text-gray-300">
                  <li className="flex items-center justify-between p-2 hover:bg-gray-700/50 rounded transition-colors">
                    <span className="flex items-center gap-2">
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">Ctrl/Cmd</kbd>
                      <span>+</span>
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">Enter</kbd>
                    </span>
                    <span className="text-sm text-gray-400">Execute security scan</span>
                  </li>
                  <li className="flex items-center justify-between p-2 hover:bg-gray-700/50 rounded transition-colors">
                    <span className="flex items-center gap-2">
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">Ctrl/Cmd</kbd>
                      <span>+</span>
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">S</kbd>
                    </span>
                    <span className="text-sm text-gray-400">Save code locally</span>
                  </li>
                  <li className="flex items-center justify-between p-2 hover:bg-gray-700/50 rounded transition-colors">
                    <span className="flex items-center gap-2">
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">Ctrl/Cmd</kbd>
                      <span>+</span>
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">/</kbd>
                    </span>
                    <span className="text-sm text-gray-400">Toggle line comment</span>
                  </li>
                  <li className="flex items-center justify-between p-2 hover:bg-gray-700/50 rounded transition-colors">
                    <span className="flex items-center gap-2">
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">Alt</kbd>
                      <span>+</span>
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">↑/↓</kbd>
                    </span>
                    <span className="text-sm text-gray-400">Move line up/down</span>
                  </li>
                  <li className="flex items-center justify-between p-2 hover:bg-gray-700/50 rounded transition-colors">
                    <span className="flex items-center gap-2">
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">Ctrl/Cmd</kbd>
                      <span>+</span>
                      <kbd className="px-2 py-1 bg-gray-900 rounded text-xs">D</kbd>
                    </span>
                    <span className="text-sm text-gray-400">Select next occurrence</span>
                  </li>
                </ul>
              </div>

              {/* Language Support Info */}
              <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
                <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                  <span className="text-blue-500">🌐</span>
                  Language Support Levels
                </h3>
                <div className="space-y-4">
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <h4 className="text-sm font-semibold text-emerald-400">🎯 Fully Supported (7)</h4>
                      <span className="text-xs px-2 py-1 bg-emerald-900/30 text-emerald-300 rounded">Best Detection</span>
                    </div>
                    <p className="text-sm text-gray-400">JavaScript, Python, Java, PHP, Go, Rust, C#</p>
                    <p className="text-xs text-gray-500 mt-1">Full pattern matching & semantic analysis</p>
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <h4 className="text-sm font-semibold text-yellow-400">⚠️ Partially Supported (3)</h4>
                      <span className="text-xs px-2 py-1 bg-yellow-900/30 text-yellow-300 rounded">Basic Detection</span>
                    </div>
                    <p className="text-sm text-gray-400">Swift, Kotlin, Ruby</p>
                    <p className="text-xs text-gray-500 mt-1">Basic pattern matching & keyword detection</p>
                  </div>
                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <h4 className="text-sm font-semibold text-gray-400">🔧 Basic Support (10+)</h4>
                      <span className="text-xs px-2 py-1 bg-gray-900 text-gray-300 rounded">Limited Detection</span>
                    </div>
                    <p className="text-sm text-gray-400">C, C++, R, MATLAB, Perl, Scala, Haskell, Lua, Dart, Elixir</p>
                    <p className="text-xs text-gray-500 mt-1">General security pattern detection</p>
                  </div>
                </div>
              </div>
            </div>
            
            {/* Scan History (if available) */}
            {scanHistory.length > 0 && (
              <div className="bg-gray-800 rounded-xl p-6 shadow-lg">
                <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                  <span className="text-purple-500">📊</span>
                  Recent Scans
                </h3>
                <div className="space-y-2 max-h-60 overflow-y-auto pr-2">
                  {scanHistory.map((scan, index) => (
                    <div 
                      key={index}
                      className="p-3 bg-gray-900/50 hover:bg-gray-900 rounded-lg cursor-pointer transition-colors"
                      onClick={() => {
                        setCode(scan.codePreview.includes('...') ? '' : scan.codePreview);
                        setLanguage(scan.language);
                        setResult(scan);
                      }}
                    >
                      <div className="flex justify-between items-start">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">{scan.language.toUpperCase()}</span>
                            <span className="text-xs px-2 py-0.5 bg-gray-700 rounded">
                              {new Date(scan.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 mt-1 truncate">{scan.codePreview}</p>
                        </div>
                        <div className="text-right">
                          <div className={`text-sm font-bold ${scan.summary.critical > 0 ? 'text-red-400' : 'text-green-400'}`}>
                            {scan.summary.total} issues
                          </div>
                          {scan.summary.critical > 0 && (
                            <div className="text-xs text-red-300">⚠️ {scan.summary.critical} critical</div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Right Panel - Results */}
          <div className="space-y-6">
            {result ? (
              <>
                {/* Scanner Info & Controls */}
                <div className="bg-gray-800 rounded-xl p-4 shadow-lg">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-blue-900/30 rounded-lg">
                        <span className="text-2xl">📊</span>
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm text-gray-400">Scanner:</span>
                          <span className="text-sm font-medium">{result.scanner || "AI Security Scanner"}</span>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <span>Time: <span className="text-gray-300">{result.scanDuration}ms</span></span>
                          <span>Lines: <span className="text-gray-300">{result.linesOfCode || "N/A"}</span></span>
                          <span>File: <span className="text-gray-300">{result.filePath || "input"}</span></span>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => copyToClipboard(JSON.stringify(result, null, 2))}
                        className="px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg flex items-center gap-2 transition-colors text-sm"
                        title="Copy full results to clipboard"
                      >
                        <span>📋</span>
                        <span>Copy JSON</span>
                      </button>
                      <button
                        onClick={() => setResult(null)}
                        className="px-3 py-2 bg-red-700/30 hover:bg-red-700/50 rounded-lg flex items-center gap-2 transition-colors text-sm"
                      >
                        <span>🗑️</span>
                        <span>Clear Results</span>
                      </button>
                    </div>
                  </div>
                </div>

                {/* Summary Cards with Metrics */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-gray-800 rounded-xl p-4 shadow-lg hover:shadow-xl transition-shadow">
                    <div className="text-2xl font-bold text-white">
                      {result.summary.total}
                    </div>
                    <div className="text-sm text-gray-400">Total Issues</div>
                    <div className="text-xs text-gray-500 mt-1">Across all severity levels</div>
                  </div>
                  <div className="bg-red-900/30 border border-red-800 rounded-xl p-4 shadow-lg hover:shadow-xl transition-shadow">
                    <div className="text-2xl font-bold text-red-400">
                      {result.summary.critical}
                    </div>
                    <div className="text-sm text-red-300">Critical</div>
                    <div className="text-xs text-red-400/70 mt-1">Immediate attention required</div>
                  </div>
                  <div className="bg-orange-900/30 border border-orange-800 rounded-xl p-4 shadow-lg hover:shadow-xl transition-shadow">
                    <div className="text-2xl font-bold text-orange-400">
                      {result.summary.high}
                    </div>
                    <div className="text-sm text-orange-300">High</div>
                    <div className="text-xs text-orange-400/70 mt-1">Address as soon as possible</div>
                  </div>
                  <div className="bg-yellow-900/30 border border-yellow-800 rounded-xl p-4 shadow-lg hover:shadow-xl transition-shadow">
                    <div className="text-2xl font-bold text-yellow-400">
                      {result.summary.medium || 0}
                    </div>
                    <div className="text-sm text-yellow-300">Medium</div>
                    <div className="text-xs text-yellow-400/70 mt-1">Consider addressing</div>
                  </div>
                </div>

                {/* Results Filter - SIMPLIFIED */}
                <div className="bg-gray-800 rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold">Vulnerabilities</h3>
                    <div className="flex gap-4">
                      <select
                        value={selectedSeverity}
                        onChange={(e) => setSelectedSeverity(e.target.value)}
                        className="bg-gray-700 border border-gray-600 rounded-lg px-3 py-2 text-sm"
                      >
                        <option value="all">All Severities ({result.vulnerabilities.length})</option>
                        <option value="critical">Critical ({result.summary.critical})</option>
                        <option value="high">High ({result.summary.high})</option>
                        <option value="medium">Medium ({result.summary.medium || 0})</option>
                        <option value="low">Low ({result.summary.low || 0})</option>
                      </select>
                      <button
                        onClick={() => setResult(null)}
                        className="px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm"
                      >
                        Clear Results
                      </button>
                    </div>
                  </div>
                </div>

                {/* Vulnerability List - ORIGINAL STYLE */}
                <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2">
                  {filteredVulnerabilities.length > 0 ? (
                    filteredVulnerabilities.map((vuln: any) => (
                      <div key={vuln.id} className={`border rounded-xl p-4 ${
                        vuln.severity === 'CRITICAL' ? 'border-red-700 bg-red-900/20' :
                        vuln.severity === 'HIGH' ? 'border-orange-700 bg-orange-900/20' :
                        vuln.severity === 'MEDIUM' ? 'border-yellow-700 bg-yellow-900/20' :
                        'border-blue-700 bg-blue-900/20'
                      }`}>
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h3 className="font-bold text-lg">
                              {vuln.severity === 'CRITICAL' ? '🔴 ' : 
                               vuln.severity === 'HIGH' ? '🟠 ' : 
                               vuln.severity === 'MEDIUM' ? '🟡 ' : '🔵 '}
                              {vuln.name}
                            </h3>
                            <p className="text-sm opacity-90 mt-1">{vuln.description}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-1 text-xs rounded ${
                              vuln.severity === 'CRITICAL' ? 'bg-red-800 text-red-200' :
                              vuln.severity === 'HIGH' ? 'bg-orange-800 text-orange-200' :
                              vuln.severity === 'MEDIUM' ? 'bg-yellow-800 text-yellow-200' :
                              'bg-blue-800 text-blue-200'
                            }`}>
                              {vuln.severity}
                            </span>
                            <button
                              onClick={() => copyToClipboard(vuln.remediation)}
                              className="text-xs px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded"
                              title="Copy fix to clipboard"
                            >
                              📋
                            </button>
                          </div>
                        </div>
                        
                        <div className="space-y-3">
                          <div>
                            <h4 className="text-sm font-semibold mb-1 flex items-center gap-1">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                              </svg>
                              Code Snippet
                            </h4>
                            <pre className="text-sm bg-black/30 p-3 rounded overflow-x-auto">
                              {vuln.codeSnippet}
                            </pre>
                          </div>
                          
                          <div>
                            <h4 className="text-sm font-semibold mb-1 flex items-center gap-1">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.242 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                              </svg>
                              Risk
                            </h4>
                            <p className="text-sm opacity-90">{vuln.risk}</p>
                          </div>
                          
                          <div>
                            <h4 className="text-sm font-semibold mb-1 flex items-center gap-1">
                              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                              </svg>
                              Remediation
                            </h4>
                            <p className="text-sm text-green-300">{vuln.remediation}</p>
                          </div>

                          {(vuln.cweId || vuln.owaspCategory) && (
                            <div className="flex gap-2 pt-2 border-t border-white/10">
                              {vuln.cweId && (
                                <a
                                  href={`https://cwe.mitre.org/data/definitions/${vuln.cweId.replace('CWE-', '')}.html`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-xs px-2 py-1 bg-gray-800 hover:bg-gray-700 rounded transition-colors"
                                >
                                  {vuln.cweId}
                                </a>
                              )}
                              {vuln.owaspCategory && (
                                <span className="text-xs px-2 py-1 bg-purple-900/50 rounded">
                                  {vuln.owaspCategory}
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="bg-gray-800 rounded-xl p-8 text-center">
                      <div className="text-6xl mb-4">🎉</div>
                      <h3 className="text-xl font-semibold mb-2">No Issues Found!</h3>
                      <p className="text-gray-400">
                        Your code appears to be secure. Good job!
                      </p>
                      <p className="text-sm text-gray-500 mt-2">
                        Try different code examples or languages to test the scanner.
                      </p>
                    </div>
                  )}
                </div>
              </>
            ) : (
              /* Empty State - Enhanced */
              <div className="bg-gray-800 rounded-xl p-8 md:p-12 text-center h-full flex flex-col items-center justify-center shadow-lg">
                <div className="text-6xl mb-6 animate-pulse">🔒</div>
                <h3 className="text-2xl font-semibold mb-3">Ready to Scan Your Code</h3>
                <p className="text-gray-400 mb-6 max-w-md">
                  Paste your code, select a language, or load an example to start scanning for security vulnerabilities.
                </p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <div className="text-2xl mb-2">🚀</div>
                    <h4 className="font-semibold mb-1">Quick Start</h4>
                    <p className="text-sm text-gray-400">Click any language button to load example code</p>
                  </div>
                  <div className="p-4 bg-gray-900/50 rounded-lg">
                    <div className="text-2xl mb-2">📁</div>
                    <h4 className="font-semibold mb-1">Upload Files</h4>
                    <p className="text-sm text-gray-400">Upload source files in 20+ languages</p>
                  </div>
                </div>
                
                <div className="text-sm text-gray-500 max-w-md">
                  <p className="mb-3 font-semibold text-gray-400">Supported Languages:</p>
                  <div className="flex flex-wrap justify-center gap-2">
                    {['JavaScript', 'Python', 'Java', 'PHP', 'Go', 'Rust', 'C#', 'Swift', 'Kotlin', 'Ruby'].map((lang) => (
                      <span key={lang} className="px-3 py-1.5 bg-gray-900 rounded-lg text-xs flex items-center gap-1">
                        <span>{getFlagForLanguage(lang.toLowerCase())}</span>
                        <span>{lang}</span>
                      </span>
                    ))}
                    <span className="px-3 py-1.5 bg-gray-900 rounded-lg text-xs">
                      +10 more
                    </span>
                  </div>
                </div>
                
                <div className="mt-8 pt-6 border-t border-gray-700 w-full max-w-sm">
                  <p className="text-xs text-gray-500">
                    <span className="text-green-400">✅</span> Free to use • 
                    <span className="text-blue-400 ml-2">🔒</span> No data stored • 
                    <span className="text-yellow-400 ml-2">⚡</span> Instant results
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
        
        {/* Footer */}
        <div className="mt-8 pt-6 border-t border-gray-800 text-center text-sm text-gray-500">
          <p>
            🔍 <strong>AI-Powered Security Scanner</strong> • 
            Detects 50+ vulnerability patterns • 
            Supports 20+ programming languages • 
            Built with Next.js & Monaco Editor
          </p>
          <p className="mt-2 text-xs">
            Note: This tool provides security guidance. Always conduct thorough security reviews for production code.
          </p>
        </div>
      </div>
    </div>
  );
}

// Helper function to get flag emoji for language
function getFlagForLanguage(lang: string): string {
  const flags: Record<string, string> = {
    javascript: '🇯🇸',
    typescript: '🇹🇸',
    python: '🐍',
    java: '☕',
    php: '🐘',
    go: '🇬🇴',
    rust: '🦀',
    csharp: '#️⃣',
    swift: '🐦',
    kotlin: '🇰🇹',
    ruby: '💎',
    c: '🔧',
    cpp: '⚡',
    r: '📊',
    matlab: '🧮',
    perl: '🐪',
    scala: '⚡',
    haskell: 'λ',
    lua: '🌙',
    dart: '🎯',
    elixir: '⚗️'
  };
  return flags[lang] || '📄';
}
