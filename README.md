# 🔒 VulnGuard

**A Modern Web Vulnerability Scanner Built with Next.js & TypeScript**

![Vulnerability Scanner](https://img.shields.io/badge/Type-Security%20Scanner-blue)
![Next.js](https://img.shields.io/badge/Next.js-14-black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue)
![License](https://img.shields.io/badge/License-MIT-green)

VulnGuard is an automated security scanning tool designed to identify common vulnerabilities in web applications. Built with modern web technologies, it provides developers with actionable security insights for their projects.

## ✨ Features

- **🔍 Multi-Language Scanning**
  - JavaScript/TypeScript vulnerability detection
  - Dependency vulnerability analysis
  - Common security misconfigurations

- **🚀 Modern Stack**
  - Built with Next.js 14 (App Router)
  - TypeScript for type safety
  - Tailwind CSS for styling
  - Prisma for database operations

- **📊 Comprehensive Reporting**
  - Detailed vulnerability reports
  - Severity classification (Critical, High, Medium, Low)
  - Actionable remediation steps
  - Real-time scanning progress

- **⚡ Performance**
  - Fast, parallel scanning
  - Minimal false positives
  - Extensible scanner architecture

## 📦 Installation

### Prerequisites
- Node.js 18+ 
- npm or yarn
- Git

### Clone & Setup
`git clone https://github.com/Bd-Mutant7/vulnguard.git`

`cd vulnguard`

`npm install` or `yarn install`

`cp .env.example .env.local`

### Environment Configuration
Create a `.env.local` file with:
`DATABASE_URL="your-database-url"`
`NEXT_PUBLIC_API_URL="http://localhost:3000"`

### Database Setup
`npx prisma generate`
`npx prisma db push`

## 🚀 Usage

### Development Server
`npm run dev` or `yarn dev`

Open [vuln-guard.vercel.app](https://vuln-guard.vercel.app/) in your browser.

### Production Build
`npm run build`
`npm start`

### Scanning Your Project
1. Navigate to the web interface
2. Enter your project path or URL
3. Select scanning options
4. Click "Start Scan"
5. View detailed vulnerability report

## 🛠️ Project Structure

## 🛠️ Project Structure

**vulnguard/**
- **app/** - Next.js app directory
  - **api/** - API routes
    - **scan/** - Scanning API endpoint
  - globals.css - Global styles
  - layout.tsx - Root layout
  - page.tsx - Home page
- **components/** - React components
  - SecurityScanner.tsx - Main scanner component
- **lib/** - Core libraries
  - **scanners/** - Scanner implementations
    - javascriptScanner.ts - JS vulnerability scanner
- **prisma/** - Database schema
  - schema.prisma - Prisma schema
- **types/** - TypeScript definitions
- **public/** - Static assets
- config files - Various config files

## 🔧 Available Scripts

`npm run dev`      # Start development server
`npm run build`    # Build for production
`npm start`        # Start production server
`npm run lint`     # Run ESLint
`npm test`         # Run tests

## 📈 Scanner Capabilities

### Currently Detected Vulnerabilities
1. **Injection Flaws**
   - SQL Injection patterns
   - Command Injection
   - XSS (Cross-Site Scripting)

2. **Security Misconfigurations**
   - Exposed sensitive files
   - Insecure headers
   - Default credentials

3. **JavaScript/TypeScript Specific**
   - eval() usage detection
   - Insecure random number generation
   - Prototype pollution patterns
   - Hardcoded secrets

4. **Dependency Issues**
   - Outdated packages with known vulnerabilities
   - Unmaintained dependencies
   - License compliance issues

## 🧪 Testing

`npm test` # Run unit tests
`npm test -- --coverage` # Run with coverage
`npm test -- scanners/javascriptScanner.test.ts` # Run specific test file

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow TypeScript best practices
- Write tests for new features
- Update documentation as needed
- Use conventional commits

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

**Important**: VulnGuard is a security scanning tool. Use it responsibly:
- Only scan systems you own or have permission to test
- Respect privacy and legal boundaries
- Do not use for malicious purposes

If you discover a security vulnerability within VulnGuard, please report it responsibly via GitHub Issues.

## 🌟 Show Your Support

Give a ⭐️ if this project helped you!

## 📞 Contact

- **GitHub**: [@Bd-Mutant7](https://github.com/Bd-Mutant7)
- **Project**: [VulnGuard Repository](https://github.com/Bd-Mutant7/vulnguard)

---

**Built with ❤️**
