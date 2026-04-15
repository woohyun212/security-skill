const express = require('express');
const app = express();

app.get('/api/nvd/cve/CVE-2021-44228', (req, res) => res.json({
  id: 'CVE-2021-44228', cvss: 10.0, severity: 'CRITICAL',
  description: 'Apache Log4j2 JNDI remote code execution vulnerability.',
  published: '2021-12-10', affected: ['log4j-core < 2.15.0']
}));

app.get('/api/vt/files/:hash', (req, res) => res.json({
  hash: req.params.hash, malicious: 12, undetected: 60,
  type: 'PE32', name: 'test-malware-sample'
}));

app.get('/api/whois/:domain', (req, res) => res.json({
  domain: req.params.domain, registrar: 'Test Registrar Inc.',
  created: '2020-01-01', expires: '2030-01-01',
  nameservers: ['ns1.test.security-skill.local', 'ns2.test.security-skill.local']
}));

app.get('/api/crtsh/:domain', (req, res) => res.json([
  { id: 1, name_value: req.params.domain, issuer: 'Test CA', not_before: '2024-01-01' },
  { id: 2, name_value: `www.${req.params.domain}`, issuer: 'Test CA', not_before: '2024-01-01' },
  { id: 3, name_value: `api.${req.params.domain}`, issuer: 'Test CA', not_before: '2024-06-01' }
]));

app.listen(3000, () => console.log('Mock API listening on :3000'));
