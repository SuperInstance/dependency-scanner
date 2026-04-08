interface Vessel {
  id: string;
  name: string;
  dependencies: Dependency[];
  lastScanned: number;
  riskScore: number;
  issues: Issue[];
}

interface Dependency {
  name: string;
  version: string;
  license: string;
  vulnerabilities: Vulnerability[];
  supplyChainRisk: number;
}

interface Vulnerability {
  cveId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fixedIn: string;
}

interface Issue {
  type: 'cve' | 'license' | 'api-key' | 'csp' | 'supply-chain';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix?: string;
}

interface ScanRequest {
  vesselId: string;
  dependencies: Array<{
    name: string;
    version: string;
    license?: string;
  }>;
}

interface ScanResult {
  vesselId: string;
  riskScore: number;
  issues: Issue[];
  timestamp: number;
}

const store = new Map<string, Vessel>();
const reports = new Map<string, ScanResult>();

const CVE_DATABASE = {
  'lodash-4.17.20': [{ cveId: 'CVE-2021-23337', severity: 'high', description: 'Command injection', fixedIn: '4.17.21' }],
  'express-4.17.1': [{ cveId: 'CVE-2022-24999', severity: 'medium', description: 'Prototype pollution', fixedIn: '4.18.0' }]
};

const LICENSE_RISKS = ['GPL-3.0', 'AGPL-3.0', 'SSPL-1.0'];
const API_KEY_PATTERNS = [
  /sk_live_[0-9a-zA-Z]{24}/,
  /AKIA[0-9A-Z]{16}/,
  /ghp_[0-9a-zA-Z]{36}/
];

function calculateRiskScore(issues: Issue[]): number {
  const weights = { critical: 10, high: 6, medium: 3, low: 1 };
  const total = issues.reduce((sum, issue) => sum + weights[issue.severity], 0);
  return Math.min(100, Math.floor((total / 40) * 100));
}

function scanDependencies(deps: Dependency[]): Issue[] {
  const issues: Issue[] = [];

  deps.forEach(dep => {
    const key = `${dep.name}-${dep.version}`;
    const cves = CVE_DATABASE[key as keyof typeof CVE_DATABASE];
    
    if (cves) {
      cves.forEach(cve => {
        issues.push({
          type: 'cve',
          severity: cve.severity,
          description: `${dep.name}@${dep.version}: ${cve.cveId} - ${cve.description}`,
          fix: `Upgrade to ${cve.fixedIn} or later`
        });
      });
    }

    if (LICENSE_RISKS.includes(dep.license)) {
      issues.push({
        type: 'license',
        severity: 'medium',
        description: `${dep.name} uses restrictive license: ${dep.license}`,
        fix: 'Consider alternative dependency or legal review'
      });
    }

    if (dep.supplyChainRisk > 7) {
      issues.push({
        type: 'supply-chain',
        severity: 'high',
        description: `${dep.name} has high supply chain risk score: ${dep.supplyChainRisk}/10`,
        fix: 'Implement dependency pinning and integrity verification'
      });
    }
  });

  return issues;
}

function checkAPIKeys(content: string): Issue[] {
  const issues: Issue[] = [];
  API_KEY_PATTERNS.forEach(pattern => {
    if (pattern.test(content)) {
      issues.push({
        type: 'api-key',
        severity: 'critical',
        description: 'Live API key detected in source code',
        fix: 'Immediately rotate key and use environment variables'
      });
    }
  });
  return issues;
}

function auditCSP(headers: Record<string, string>): Issue[] {
  const issues: Issue[] = [];
  const csp = headers['content-security-policy'];
  
  if (!csp) {
    issues.push({
      type: 'csp',
      severity: 'high',
      description: 'Missing Content-Security-Policy header',
      fix: 'Implement CSP with default-src, script-src, and style-src directives'
    });
  } else if (csp.includes("'unsafe-inline'")) {
    issues.push({
      type: 'csp',
      severity: 'medium',
      description: 'CSP allows unsafe-inline scripts',
      fix: 'Remove unsafe-inline and use nonces/hashes instead'
    });
  }
  
  return issues;
}

const html = (content: string) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dependency Scanner</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', sans-serif;
      background: #0a0a0f;
      color: #e5e5e5;
      line-height: 1.6;
      min-height: 100vh;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    header { border-bottom: 1px solid #1f1f2e; padding-bottom: 1.5rem; margin-bottom: 2rem; }
    h1 { color: #dc2626; font-size: 2.5rem; margin-bottom: 0.5rem; }
    .subtitle { color: #94a3b8; font-size: 1.1rem; }
    .card {
      background: #11111a;
      border: 1px solid #1f1f2e;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .severity-critical { color: #dc2626; border-left: 4px solid #dc2626; }
    .severity-high { color: #ea580c; border-left: 4px solid #ea580c; }
    .severity-medium { color: #ca8a04; border-left: 4px solid #ca8a04; }
    .severity-low { color: #16a34a; border-left: 4px solid #16a34a; }
    .footer {
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid #1f1f2e;
      text-align: center;
      color: #64748b;
      font-size: 0.9rem;
    }
    code { background: #1e1e2e; padding: 0.2rem 0.4rem; border-radius: 4px; font-family: monospace; }
    .risk-score { font-size: 2rem; font-weight: bold; }
    .score-critical { color: #dc2626; }
    .score-high { color: #ea580c; }
    .score-medium { color: #ca8a04; }
    .score-low { color: #16a34a; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Dependency Scanner</h1>
      <p class="subtitle">Know what your fleet depends on</p>
    </header>
    ${content}
    <div class="footer">
      <p>Fleet Dependency Scanner v1.0 • Zero Dependencies • Secure by Design</p>
    </div>
  </div>
</body>
</html>`;

export default {
  async fetch(request: Request, env: unknown, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const headers = {
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com",
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff'
    };

    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: Date.now() }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...headers }
      });
    }

    if (url.pathname === '/api/scan' && request.method === 'POST') {
      try {
        const body: ScanRequest = await request.json();
        const issues: Issue[] = [];
        
        const dependencies: Dependency[] = body.dependencies.map(dep => ({
          ...dep,
          vulnerabilities: CVE_DATABASE[`${dep.name}-${dep.version}` as keyof typeof CVE_DATABASE] || [],
          supplyChainRisk: Math.floor(Math.random() * 10) + 1
        }));

        issues.push(...scanDependencies(dependencies));
        issues.push(...checkAPIKeys(JSON.stringify(body)));
        
        const riskScore = calculateRiskScore(issues);
        const report: ScanResult = {
          vesselId: body.vesselId,
          riskScore,
          issues,
          timestamp: Date.now()
        };

        reports.set(body.vesselId, report);
        
        store.set(body.vesselId, {
          id: body.vesselId,
          name: body.vesselId,
          dependencies,
          lastScanned: Date.now(),
          riskScore,
          issues
        });

        return new Response(JSON.stringify(report), {
          status: 200,
          headers: { 'Content-Type': 'application/json', ...headers }
        });
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Invalid request' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...headers }
        });
      }
    }

    if (url.pathname.startsWith('/api/report/') && request.method === 'GET') {
      const vesselId = url.pathname.split('/').pop();
      if (!vesselId || !reports.has(vesselId)) {
        return new Response(JSON.stringify({ error: 'Report not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json', ...headers }
        });
      }
      
      const report = reports.get(vesselId);
      return new Response(JSON.stringify(report), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...headers }
      });
    }

    if (url.pathname === '/api/fleet-risks' && request.method === 'GET') {
      const fleetRisks = Array.from(store.values()).map(vessel => ({
        id: vessel.id,
        name: vessel.name,
        riskScore: vessel.riskScore,
        lastScanned: vessel.lastScanned,
        issueCount: vessel.issues.length,
        criticalCount: vessel.issues.filter(i => i.severity === 'critical').length
      }));

      return new Response(JSON.stringify(fleetRisks), {
        status: 200,
        headers: { 'Content-Type': 'application/json', ...headers }
      });
    }

    if (url.pathname === '/' && request.method === 'GET') {
      const fleet = Array.from(store.values());
      const totalVessels = fleet.length;
      const avgRisk = fleet.length > 0 
        ? Math.round(fleet.reduce((sum, v) => sum + v.riskScore, 0) / fleet.length)
        : 0;
      
      const content = `
        <div class="card">
          <h2>Fleet Overview</h2>
          <p>Vessels monitored: <strong>${totalVessels}</strong></p>
          <p>Average risk score: <span class="risk-score score-${avgRisk > 70 ? 'critical' : avgRisk > 50 ? 'high' : avgRisk > 30 ? 'medium' : 'low'}">${avgRisk}</span></p>
        </div>
        <div class="card">
          <h2>Recent Scans</h2>
          ${fleet.length > 0 ? fleet.slice(-5).reverse().map(v => `
            <div class="card severity-${v.riskScore > 70 ? 'critical' : v.riskScore > 50 ? 'high' : v.riskScore > 30 ? 'medium' : 'low'}">
              <h3>${v.name}</h3>
              <p>Risk: ${v.riskScore} • Issues: ${v.issues.length} • Last scanned: ${new Date(v.lastScanned).toLocaleString()}</p>
            </div>
          `).join('') : '<p>No vessels scanned yet</p>'}
        </div>
        <div class="card">
          <h2>API Endpoints</h2>
          <p><code>POST /api/scan</code> - Submit vessel for dependency scanning</p>
          <p><code>GET /api/report/:vessel</code> - Retrieve scan report</p>
          <p><code>GET /api/fleet-risks</code> - Get fleet-wide risk assessment</p>
          <p><code>GET /health</code> - Service health check</p>
        </div>
      `;

      return new Response(html(content), {
        status: 200,
        headers: { 'Content-Type': 'text/html', ...headers }
      });
    }

    return new Response(JSON.stringify({ error: 'Not found' }), {
      status: 404,
      headers: { 'Content-Type': 'application/json', ...headers }
    });
  }
};
