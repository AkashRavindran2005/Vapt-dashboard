import React, { useState, useEffect, useRef, useCallback } from 'react';
import axios from 'axios';
import { jsPDF } from 'jspdf';
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Server,
  Globe,
  Activity,
  Target,
  Zap,
  FileText,
  RefreshCw,
  Settings,
  BarChart3,
  AlertCircle,
  Info,
  Network,
  Monitor,
  FileSpreadsheet,
  TrendingUp,
  Lock,
  Eye,
  Menu,
  X,
  Sun,
  Moon,
  Gauge,
  BookOpen,
  Layers,
  HardDrive,
  Wifi,
  Bug,
  Play,
  Pause,
  Upload
} from 'lucide-react';

const ProgressBar = ({ 
  progress = 0, 
  status = 'running', 
  label = '', 
  showPercentage = true,
  animated = true,
  height = '8px',
  darkMode = false
}) => {
  const getStatusColor = () => {
    switch (status) {
      case 'running': return '#2563eb';
      case 'finished': return '#10b981';
      case 'failed': return '#ef4444';
      case 'queued': return '#f59e0b';
      default: return '#2563eb';
    }
  };

  const getStatusIcon = () => {
    switch (status) {
      case 'running': return <Activity className="w-4 h-4" style={{ animation: 'pulse 2s infinite' }} />;
      case 'finished': return <CheckCircle className="w-4 h-4" />;
      case 'failed': return <AlertCircle className="w-4 h-4" />;
      case 'queued': return <Clock className="w-4 h-4" />;
      default: return <Activity className="w-4 h-4" />;
    }
  };

  return (
    <div style={{ marginBottom: '16px' }}>
      {label && (
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          marginBottom: '8px' 
        }}>
          <div style={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: '8px',
            fontSize: '14px',
            fontWeight: 500,
            color: darkMode ? '#a0aec0' : '#64748b'
          }}>
            {getStatusIcon()}
            {label}
          </div>
          {showPercentage && (
            <span style={{ 
              fontSize: '12px', 
              fontWeight: 600, 
              color: darkMode ? '#e2e8f0' : '#1e293b' 
            }}>
              {Math.round(progress)}%
            </span>
          )}
        </div>
      )}
      
      <div style={{
        width: '100%',
        height: height,
        backgroundColor: darkMode ? '#4a5568' : '#e2e8f0',
        borderRadius: '4px',
        overflow: 'hidden',
        position: 'relative'
      }}>
        <div
          style={{
            height: '100%',
            width: `${Math.min(progress, 100)}%`,
            backgroundColor: getStatusColor(),
            borderRadius: '4px',
            transition: animated ? 'width 0.3s ease-in-out' : 'none',
            position: 'relative',
            overflow: 'hidden'
          }}
        >
          {animated && status === 'running' && (
            <div
              style={{
                position: 'absolute',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)',
                animation: 'shimmer 2s infinite',
                borderRadius: '4px'
              }}
            />
          )}
        </div>
      </div>
    </div>
  );
};

const Dashboard = () => {
  const [singleTarget, setSingleTarget] = useState('');
  const [bulkTargets, setBulkTargets] = useState('');
  const [singleJob, setSingleJob] = useState(null);
  const [bulkJob, setBulkJob] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeView, setActiveView] = useState('dashboard');
  const [selectedResult, setSelectedResult] = useState(null);
  const [debugInfo, setDebugInfo] = useState([]);
  const [stats, setStats] = useState({});
  const [enableExploits, setEnableExploits] = useState(false);
  const [exploitConfirmed, setExploitConfirmed] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [showDebugInfo, setShowDebugInfo] = useState(false);
  const [backendLogs, setBackendLogs] = useState([]);
  const [singleScanProgress, setSingleScanProgress] = useState(0);
  const [bulkScanProgress, setBulkScanProgress] = useState(0);
  const [scanPhase, setScanPhase] = useState('');

  const pollingIntervalRef = useRef(null);
  const pollCountRef = useRef(0);
  const isPollingRef = useRef(false);
  const currentJobIdRef = useRef(null);
  const bulkPollingIntervalRef = useRef(null);
  const isBulkPollingRef = useRef(false);

  const API_BASE = 'http://localhost:4000';

  useEffect(() => {
    const fetchBackendLogs = async () => {
      try {
        const response = await axios.get(`${API_BASE}/api/logs`);
        if (response.data.lines && response.data.lines.length) {
          setBackendLogs(prev => [...response.data.lines, ...prev].slice(0, 200));
        }
      } catch (error) {
      }
    };

    const interval = setInterval(fetchBackendLogs, 3000);
    return () => clearInterval(interval);
  }, [API_BASE]);

  const addDebugLog = useCallback((message) => {
    const timestamp = new Date().toLocaleTimeString();
    const logMessage = `[${timestamp}] ${message}`;
    setDebugInfo(prev => [logMessage, ...prev.slice(0, 19)]);
  }, []);

  const toggleDebugInfo = () => {
    setShowDebugInfo(!showDebugInfo);
  };

  const calculateScanProgress = (job, isBulk = false) => {
    if (!job) return 0;
    
    const { status, start_time, total_targets, completed } = job;
    
    if (status === 'finished') return 100;
    if (status === 'failed') return 0;
    if (status === 'queued') return 0;
    
    if (isBulk) {
      if (total_targets && completed !== undefined) {
        return Math.round((completed / total_targets) * 100);
      }
      return job.progress || 0;
    } else {
      if (start_time) {
        const elapsed = Date.now() / 1000 - start_time;
        const estimatedTotal = 45; 
        const timeProgress = Math.min((elapsed / estimatedTotal) * 100, 95);
        return Math.round(timeProgress);
      }
      return 0;
    }
  };

  const clearPolling = useCallback(() => {
    if (pollingIntervalRef.current) {
      clearInterval(pollingIntervalRef.current);
      pollingIntervalRef.current = null;
      isPollingRef.current = false;
    }
  }, []);

  const clearBulkPolling = useCallback(() => {
    if (bulkPollingIntervalRef.current) {
      clearInterval(bulkPollingIntervalRef.current);
      bulkPollingIntervalRef.current = null;
      isBulkPollingRef.current = false;
    }
  }, []);

  const pollJobStatus = useCallback(async (jobId) => {
    try {
      pollCountRef.current++;
      
      const response = await axios.get(`${API_BASE}/api/scan/${jobId}`);
      
      setSingleJob(prevJob => {
        if (prevJob?.job_id === response.data.job_id) {
          const updatedJob = { ...prevJob, ...response.data };
          
          const progress = calculateScanProgress(updatedJob, false);
          setSingleScanProgress(progress);
          
          if (response.data.status === 'running') {
            if (progress < 15) setScanPhase('Initializing port discovery...');
            else if (progress < 30) setScanPhase('Scanning network ports...');
            else if (progress < 45) setScanPhase('Detecting services...');
            else if (progress < 65) setScanPhase('Running vulnerability scans...');
            else if (progress < 80) setScanPhase('Analyzing results...');
            else if (progress < 95) setScanPhase('Generating report...');
            else setScanPhase('Finalizing scan...');
          } else if (response.data.status === 'queued') {
            setScanPhase('Scan queued...');
          }
          
          return updatedJob;
        }
        return prevJob;
      });

      if (response.data.status === 'finished') {
        setSingleScanProgress(100);
        setScanPhase('Scan completed successfully!');
        clearPolling();
        
        if (response.data.result) {
          setResults(prev => {
            const exists = prev.some(r => 
              r.target === response.data.result.target && 
              Math.abs((r.timestamp || 0) - (response.data.result.timestamp || 0)) < 30
            );
            if (!exists) {
              return [response.data.result, ...prev.slice(0, 49)];
            }
            return prev;
          });
          setTimeout(() => setActiveView('results'), 1000);
        }
      } else if (response.data.status === 'failed') {
        setSingleScanProgress(0);
        setScanPhase('Scan failed');
        clearPolling();
      }
    } catch (error) {
      if (pollCountRef.current > 20) {
        clearPolling();
        setScanPhase('Connection error');
      }
    }
  }, [API_BASE, clearPolling]);

  const pollBulkJobStatus = useCallback(async (jobId) => {
    try {
      const response = await axios.get(`${API_BASE}/api/bulk-scan/${jobId}`);
      
      setBulkJob(prevJob => {
        if (prevJob?.job_id === response.data.job_id) {
          const updatedJob = { ...prevJob, ...response.data };
          
          const progress = calculateScanProgress(updatedJob, true);
          setBulkScanProgress(progress);
          
          if (response.data.status === 'running') {
            const completed = response.data.completed || 0;
            const total = response.data.total_targets || 1;
            setScanPhase(`Scanning ${completed}/${total} targets...`);
          } else if (response.data.status === 'queued') {
            setScanPhase('Bulk scan queued...');
          }
          
          return updatedJob;
        }
        return prevJob;
      });

      if (response.data.status === 'finished') {
        setBulkScanProgress(100);
        setScanPhase('Bulk scan completed successfully!');
        clearBulkPolling();
        
        if (response.data.results && Array.isArray(response.data.results)) {
          setResults(prev => [...response.data.results, ...prev].slice(0, 100));
          setTimeout(() => setActiveView('results'), 1000);
        }
      } else if (response.data.status === 'failed') {
        setBulkScanProgress(0);
        setScanPhase('Bulk scan failed');
        clearBulkPolling();
      }
    } catch (error) {
    }
  }, [API_BASE, clearBulkPolling]);

  const startPolling = useCallback((jobId) => {
    if (isPollingRef.current && currentJobIdRef.current === jobId) {
      return;
    }
    
    clearPolling();
    currentJobIdRef.current = jobId;
    isPollingRef.current = true;
    pollCountRef.current = 0;
    
    pollJobStatus(jobId);
    
    pollingIntervalRef.current = setInterval(() => {
      if (isPollingRef.current && currentJobIdRef.current === jobId) {
        pollJobStatus(jobId);
      } else {
        clearPolling();
      }
    }, 2000);
  }, [clearPolling, pollJobStatus]);

  const startBulkPolling = useCallback((jobId) => {
    if (isBulkPollingRef.current) {
      return;
    }
    
    clearBulkPolling();
    isBulkPollingRef.current = true;
    
    pollBulkJobStatus(jobId);
    
    bulkPollingIntervalRef.current = setInterval(() => {
      if (isBulkPollingRef.current) {
        pollBulkJobStatus(jobId);
      } else {
        clearBulkPolling();
      }
    }, 3000);
  }, [clearBulkPolling, pollBulkJobStatus]);

  useEffect(() => {
    if (singleJob?.job_id && ['queued', 'running'].includes(singleJob.status)) {
      if (!isPollingRef.current || currentJobIdRef.current !== singleJob.job_id) {
        startPolling(singleJob.job_id);
      }
    }
  }, [singleJob?.job_id, singleJob?.status, startPolling]);

  useEffect(() => {
    if (bulkJob?.job_id && ['queued', 'running'].includes(bulkJob.status)) {
      if (!isBulkPollingRef.current) {
        startBulkPolling(bulkJob.job_id);
      }
    }
  }, [bulkJob?.job_id, bulkJob?.status, startBulkPolling]);

  useEffect(() => {
    return () => {
      clearPolling();
      clearBulkPolling();
    };
  }, [clearPolling, clearBulkPolling]);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const response = await axios.get(`${API_BASE}/api/stats`);
        setStats(response.data);
      } catch (error) {
        console.error('Failed to fetch stats:', error);
      }
    };

    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [API_BASE]);

  const startSingleScan = async () => {
    if (!singleTarget.trim()) return;
    
    clearPolling();
    setSingleScanProgress(0);
    setScanPhase('Initializing scan...');
    addDebugLog(`Starting scan for: ${singleTarget}`);
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/scan`, null, {
        params: { 
          target: singleTarget.trim(),
          enable_exploits: enableExploits && exploitConfirmed ? 'true' : 'false'
        }
      });
      
      addDebugLog(`Scan started with job ID: ${response.data.job_id}`);
      addDebugLog(`Exploit mode: ${enableExploits && exploitConfirmed ? 'ENABLED' : 'DISABLED'}`);
      
      setSingleJob({
        job_id: response.data.job_id,
        status: 'queued',
        target: singleTarget.trim(),
        exploit_mode: response.data.exploit_mode,
        start_time: Date.now() / 1000
      });
      
      setScanPhase('Scan queued...');
      setActiveView('monitoring');
    } catch (error) {
      addDebugLog(`Scan failed: ${error.message}`);
      setScanPhase('Failed to start scan');
      alert(`Scan failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const startBulkScan = async () => {
    const targets = bulkTargets.split('\n').map(t => t.trim()).filter(t => t);
    if (targets.length === 0) return;
    
    clearBulkPolling();
    setBulkScanProgress(0);
    setScanPhase('Initializing bulk scan...');
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/bulk-scan`, {
        targets,
        max_concurrent: 100,
        enable_exploits: enableExploits && exploitConfirmed
      });
      
      addDebugLog(`Bulk scan started with job ID: ${response.data.job_id}`);
      addDebugLog(`Exploit mode: ${enableExploits && exploitConfirmed ? 'ENABLED' : 'DISABLED'}`);
      
      setBulkJob({
        job_id: response.data.job_id,
        status: 'queued',
        exploit_mode: response.data.exploit_mode,
        total_targets: targets.length,
        completed: 0,
        progress: 0,
        start_time: Date.now() / 1000
      });
      
      setScanPhase('Bulk scan queued...');
      setActiveView('monitoring');
    } catch (error) {
      console.error('Failed to start bulk scan:', error);
      setScanPhase('Failed to start bulk scan');
      alert('Failed to start bulk scan. Please check if the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const cancelScan = () => {
    addDebugLog('Scan cancelled by user');
    setScanPhase('Scan cancelled');
    setSingleScanProgress(0);
    clearPolling();
    setSingleJob(null);
    currentJobIdRef.current = null;
  };

  const cancelBulkScan = () => {
    addDebugLog('Bulk scan cancelled by user');
    setScanPhase('Bulk scan cancelled');
    setBulkScanProgress(0);
    clearBulkPolling();
    setBulkJob(null);
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setBulkTargets(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  const calculateConfidenceScore = (result) => {
    let score = 0;
    let factors = [];
    
    const portCount = result.ports_masscan?.length || 0;
    if (portCount > 0) {
      score += Math.min(portCount * 2, 25);
      factors.push(`Port Discovery: ${portCount} ports found`);
    }
    
    const serviceCount = Object.keys(result.services || {}).length;
    if (serviceCount > 0) {
      score += Math.min(serviceCount * 3, 25);
      factors.push(`Service Detection: ${serviceCount} services identified`);
    }
    
    const vulnTools = [
      result.nuclei?.length || 0,
      result.nikto?.length || 0,
      result.nmap_vulns?.length || 0,
      result.custom_checks?.length || 0
    ];
    const activeTools = vulnTools.filter(count => count > 0).length;
    score += activeTools * 7.5;
    factors.push(`Vulnerability Tools: ${activeTools}/4 tools executed`);
    
    const scanTime = result.scan_time || 0;
    if (scanTime > 10 && scanTime < 300) {
      score += 10;
      factors.push(`Scan Duration: ${scanTime}s (appropriate)`);
    } else if (scanTime > 0) {
      score += 5;
      factors.push(`Scan Duration: ${scanTime}s (${scanTime < 10 ? 'very quick' : 'extended'})`);
    }
    
    if (result.exploit_results) {
      const exploitCategories = Object.keys(result.exploit_results).length;
      score += exploitCategories * 2;
      factors.push(`Exploit Testing: ${exploitCategories} categories tested`);
    }
    
    const finalScore = Math.min(Math.round(score), 100);
    
    let level = 'Low';
    if (finalScore >= 90) level = 'Excellent';
    else if (finalScore >= 80) level = 'High';
    else if (finalScore >= 70) level = 'Good';
    else if (finalScore >= 60) level = 'Moderate';
    else if (finalScore >= 50) level = 'Fair';
    
    return { score: finalScore, level, factors };
  };

  const analyzeFindings = (record) => {
    const analysis = {
      criticalIssues: [],
      highRiskIssues: [],
      mediumRiskIssues: [],
      lowRiskIssues: [],
      informationalFindings: [],
      networkExposure: [],
      serviceVulnerabilities: [],
      webApplicationIssues: [],
      configurationProblems: [],
      complianceIssues: [],
      testingMethodology: [],
      toolsUsed: [],
      scanCoverage: {},
      riskMetrics: {},
      businessImpact: {},
      recommendations: []
    };

    if (record.ports_masscan?.length > 0) {
      const criticalPorts = record.ports_masscan.filter(port => 
        [21, 23, 135, 139, 445, 1433, 3389, 5432].includes(port)
      );
      const managementPorts = record.ports_masscan.filter(port => 
        [22, 3389, 5900, 5901].includes(port)
      );
      const webPorts = record.ports_masscan.filter(port => 
        [80, 443, 8080, 8443, 9000, 9001].includes(port)
      );
      const databasePorts = record.ports_masscan.filter(port => 
        [1433, 3306, 5432, 27017, 6379].includes(port)
      );

      if (criticalPorts.length > 0) {
        analysis.criticalIssues.push({
          category: "Network Exposure",
          issue: "Critical services exposed to network",
          details: `High-risk ports ${criticalPorts.join(', ')} are accessible and may provide attack vectors`,
          impact: "Direct system compromise, lateral movement, data exfiltration",
          recommendation: "Implement strict firewall rules, disable unnecessary services, use VPN for remote access",
          cve: "Multiple CVEs associated with exposed services",
          severity: "Critical"
        });
      }

      if (managementPorts.length > 0) {
        analysis.highRiskIssues.push({
          category: "Management Interface Exposure",
          issue: "Remote management services accessible",
          details: `Management ports ${managementPorts.join(', ')} detected`,
          impact: "Administrative access compromise, credential theft",
          recommendation: "Restrict management interface access, implement multi-factor authentication"
        });
      }

      analysis.networkExposure.push({
        category: "Port Distribution",
        webPorts: webPorts.length,
        managementPorts: managementPorts.length,
        databasePorts: databasePorts.length,
        totalPorts: record.ports_masscan.length,
        riskLevel: criticalPorts.length > 0 ? "Critical" : managementPorts.length > 0 ? "High" : "Medium"
      });
    }

    Object.entries(record.services || {}).forEach(([port, service]) => {
      const serviceName = service.service.toLowerCase();
      const version = service.version.toLowerCase();

      if (serviceName.includes('ssh')) {
        if (version.includes('openssh 2.') || version.includes('openssh 3.') || 
            version.includes('openssh 4.') || version.includes('openssh 5.')) {
          analysis.criticalIssues.push({
            category: "Service Vulnerability",
            issue: `Outdated SSH service on port ${port}`,
            details: `${service.service} ${service.version} contains multiple known vulnerabilities`,
            impact: "Remote code execution, authentication bypass, privilege escalation",
            recommendation: "Upgrade to OpenSSH 8.0 or later, implement key-based authentication",
            cve: "CVE-2016-0777, CVE-2016-0778, CVE-2015-5600",
            severity: "Critical"
          });
        }
      }

      if (serviceName.includes('ftp')) {
        if (version.includes('vsftpd 2.3.4')) {
          analysis.criticalIssues.push({
            category: "Service Vulnerability",
            issue: `FTP service contains backdoor on port ${port}`,
            details: "vsftpd 2.3.4 contains a backdoor that allows remote command execution",
            impact: "Complete system compromise, backdoor access",
            recommendation: "Immediately replace with secure FTP alternative or latest version",
            cve: "CVE-2011-2523",
            severity: "Critical"
          });
        }
      }

      if (serviceName.includes('apache') || serviceName.includes('nginx') || serviceName.includes('iis')) {
        if (version.includes('apache 2.0') || version.includes('apache 2.2') || 
            version.includes('nginx 1.0') || version.includes('nginx 1.2')) {
          analysis.highRiskIssues.push({
            category: "Web Server Vulnerability",
            issue: `Outdated web server on port ${port}`,
            details: `${service.service} ${service.version} has known security vulnerabilities`,
            impact: "Web application compromise, data disclosure, DoS attacks",
            recommendation: "Upgrade to latest stable version, implement security headers"
          });
        }
      }

      if (['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb'].some(db => serviceName.includes(db))) {
        analysis.mediumRiskIssues.push({
          category: "Database Exposure",
          issue: `Database service exposed on port ${port}`,
          details: `${service.service} directly accessible from network`,
          impact: "Data breach, unauthorized access, data manipulation",
          recommendation: "Implement database firewall, restrict network access, use connection pooling"
        });
      }
    });

    const allFindings = [
      ...(record.nuclei || []),
      ...(record.nikto || []),
      ...(record.nmap_vulns || []),
      ...(record.custom_checks || [])
    ];

    const vulnerabilityMap = {};

    allFindings.forEach(finding => {
      const findingLower = finding.toLowerCase();
      
      let vulnKey = finding;
      let severity = 'Medium';
      let category = 'Security Finding';
      let impact = 'Potential security risk';
      let recommendation = 'Apply security patches';
      let cve = '';
      
      const cveMatch = finding.match(/(CVE-\d{4}-\d{4,})/i);
      if (cveMatch) {
        cve = cveMatch[1];
        vulnKey = cveMatch[1];
      }
      
      if (findingLower.includes('critical') || findingLower.includes('cve-2017-0144') || 
          findingLower.includes('eternalblue') || findingLower.includes('backdoor') ||
          findingLower.includes('rce') || findingLower.includes('remote code execution')) {
        severity = 'Critical';
        impact = "Remote code execution, system compromise";
        recommendation = "Immediate patching required, isolate system";
      } else if (findingLower.includes('high') || findingLower.includes('sqli') || 
                 findingLower.includes('sql injection') || findingLower.includes('xss') ||
                 findingLower.includes('auth') || findingLower.includes('privilege')) {
        severity = 'High';
        impact = "Authentication bypass, privilege escalation";
        recommendation = "Priority patching within 72 hours";
      } else if (findingLower.includes('medium') || findingLower.includes('weak') || 
                 findingLower.includes('outdated') || findingLower.includes('misconfigur')) {
        severity = 'Medium';
        impact = "Configuration weakness, information disclosure";
        recommendation = "Update configuration, apply hardening";
      } else if (findingLower.includes('low') || findingLower.includes('info') || 
                 findingLower.includes('disclosure')) {
        severity = 'Low';
        impact = "Information gathering, minimal risk";
        recommendation = "Address during maintenance window";
      }

      if (findingLower.includes('sql') || findingLower.includes('sqli')) {
        category = 'SQL Injection';
        vulnKey = 'SQL Injection Vulnerability';
      } else if (findingLower.includes('xss') || findingLower.includes('cross-site')) {
        category = 'Cross-Site Scripting';
        vulnKey = 'XSS Vulnerability';
      } else if (findingLower.includes('lfi') || findingLower.includes('local file')) {
        category = 'Local File Inclusion';
        vulnKey = 'LFI Vulnerability';
      } else if (findingLower.includes('rfi') || findingLower.includes('remote file')) {
        category = 'Remote File Inclusion';
        vulnKey = 'RFI Vulnerability';
      } else if (findingLower.includes('ssrf')) {
        category = 'Server-Side Request Forgery';
        vulnKey = 'SSRF Vulnerability';
      } else if (findingLower.includes('csrf')) {
        category = 'Cross-Site Request Forgery';
        vulnKey = 'CSRF Vulnerability';
      } else if (findingLower.includes('dir') || findingLower.includes('traversal')) {
        category = 'Directory Traversal';
        vulnKey = 'Directory Traversal Vulnerability';
      } else if (findingLower.includes('upload')) {
        category = 'File Upload';
        vulnKey = 'File Upload Vulnerability';
      } else if (findingLower.includes('apache') || findingLower.includes('nginx') || findingLower.includes('iis')) {
        category = 'Web Server';
        vulnKey = 'Web Server Vulnerability';
      } else if (findingLower.includes('cms') || findingLower.includes('wordpress') || findingLower.includes('joomla')) {
        category = 'CMS Vulnerability';
        vulnKey = 'CMS Security Issue';
      }

      if (!vulnerabilityMap[vulnKey]) {
        vulnerabilityMap[vulnKey] = {
          category,
          issue: vulnKey,
          details: finding,
          impact,
          recommendation,
          cve,
          severity,
          count: 1,
          examples: [finding]
        };
      } else {
        vulnerabilityMap[vulnKey].count++;
        if (vulnerabilityMap[vulnKey].examples.length < 3) {
          vulnerabilityMap[vulnKey].examples.push(finding);
        }
      }
    });

    Object.values(vulnerabilityMap).forEach(vuln => {
      const vulnObject = {
        category: vuln.category,
        issue: vuln.count > 1 ? `${vuln.issue} (${vuln.count} instances)` : vuln.issue,
        details: vuln.count > 1 ? vuln.examples.join('; ') : vuln.details,
        impact: vuln.impact,
        recommendation: vuln.recommendation,
        cve: vuln.cve,
        severity: vuln.severity
      };

      if (vuln.severity === 'Critical') {
        analysis.criticalIssues.push(vulnObject);
      } else if (vuln.severity === 'High') {
        analysis.highRiskIssues.push(vulnObject);
      } else if (vuln.severity === 'Medium') {
        analysis.mediumRiskIssues.push(vulnObject);
      } else {
        analysis.lowRiskIssues.push(vulnObject);
      }
    });

    analysis.riskMetrics = {
      totalFindings: allFindings.length,
      criticalCount: analysis.criticalIssues.length,
      highCount: analysis.highRiskIssues.length,
      mediumCount: analysis.mediumRiskIssues.length,
      lowCount: analysis.lowRiskIssues.length,
      riskScore: (analysis.criticalIssues.length * 10) + (analysis.highRiskIssues.length * 7) + 
                 (analysis.mediumRiskIssues.length * 4) + (analysis.lowRiskIssues.length * 1),
      exposureLevel: analysis.criticalIssues.length > 0 ? "Critical" : 
                     analysis.highRiskIssues.length > 0 ? "High" : "Medium",
      complianceImpact: analysis.criticalIssues.length > 0 ? "Major compliance violations likely" : 
                        analysis.highRiskIssues.length > 0 ? "Potential compliance issues" : "Minor compliance concerns"
    };

    analysis.businessImpact = {
      dataBreachRisk: analysis.criticalIssues.length > 0 ? "High" : analysis.highRiskIssues.length > 0 ? "Medium" : "Low",
      operationalImpact: analysis.criticalIssues.length > 0 ? "Severe" : analysis.highRiskIssues.length > 0 ? "Moderate" : "Minimal",
      financialRisk: analysis.criticalIssues.length > 0 ? "High" : analysis.highRiskIssues.length > 0 ? "Medium" : "Low",
      reputationalRisk: analysis.criticalIssues.length > 0 ? "Severe" : analysis.highRiskIssues.length > 0 ? "Moderate" : "Low",
      regulatoryRisk: analysis.criticalIssues.length > 0 ? "High" : analysis.highRiskIssues.length > 0 ? "Medium" : "Low"
    };

    analysis.recommendations = [
      ...(analysis.criticalIssues.length > 0 ? [
        "IMMEDIATE ACTION: Isolate affected systems from network",
        "Apply all critical security patches within 24 hours",
        "Implement emergency monitoring and incident response",
        "Conduct thorough security audit of all systems"
      ] : []),
      ...(analysis.highRiskIssues.length > 0 ? [
        "Address high-risk vulnerabilities within 72 hours",
        "Implement additional security controls and monitoring",
        "Review and update security policies and procedures",
        "Conduct security awareness training for staff"
      ] : []),
      "Implement regular vulnerability assessment schedule",
      "Establish security patch management program",
      "Deploy intrusion detection and prevention systems",
      "Implement network segmentation and access controls",
      "Conduct regular security audits and penetration testing"
    ];

    analysis.scanCoverage = {
      networkPorts: record.ports_masscan?.length || 0,
      identifiedServices: Object.keys(record.services || {}).length,
      vulnerabilityChecks: allFindings.length,
      webPaths: record.paths?.length || 0,
      technologies: record.whatweb?.length || 0,
      totalChecks: (record.nuclei?.length || 0) + (record.nikto?.length || 0) + 
                   (record.nmap_vulns?.length || 0) + (record.custom_checks?.length || 0),
      scanCompleteness: Math.min(100, ((record.ports_masscan?.length || 0) * 2) + 
                                      ((Object.keys(record.services || {}).length) * 5) + 
                                      (allFindings.length * 1)),
      confidenceLevel: calculateConfidenceScore(record)
    };

    return analysis;
  };

  const addTextWithWrap = (doc, text, x, y, maxWidth, options = {}) => {
    const { fontSize = 12, color = [0, 0, 0], bold = false, lineHeight = 6 } = options;
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);
    doc.setFont(undefined, bold ? 'bold' : 'normal');
    
    const lines = doc.splitTextToSize(text, maxWidth);
    let currentY = y;
    
    lines.forEach(line => {
      if (currentY > doc.internal.pageSize.height - 30) {
        doc.addPage();
        currentY = 30;
      }
      doc.text(line, x, currentY);
      currentY += lineHeight;
    });
    
    return currentY;
  };

  const generateTechnicalReport = (record) => {
    const analysis = analyzeFindings(record);
    const confidence = calculateConfidenceScore(record);
    
    const technicalReport = `
COMPREHENSIVE VAPT TECHNICAL ASSESSMENT REPORT
=============================================

EXECUTIVE SUMMARY
================
Target: ${record.target}
Assessment Date: ${new Date(record.timestamp * 1000).toLocaleDateString()}
Report Generated: ${new Date().toLocaleString()}
Overall Risk Rating: ${record.risk}
Confidence Score: ${confidence.score}/100 (${confidence.level})

ASSESSMENT OVERVIEW
==================
Total Vulnerabilities Identified: ${record.total_vulnerabilities || 0}
Network Ports Scanned: ${record.ports_masscan?.length || 0}
Services Identified: ${Object.keys(record.services || {}).length}
Assessment Duration: ${record.scan_time || 0} seconds
Exploit Testing: ${record.exploit_results ? 'Enabled' : 'Disabled'}

CRITICAL VULNERABILITIES (${analysis.criticalIssues.length})
${analysis.criticalIssues.map((issue, i) => `
${i + 1}. ${issue.issue}
   Category: ${issue.category}
   Risk Details: ${issue.details}
   Impact: ${issue.impact}
   CVE: ${issue.cve || 'Not specified'}
   Recommendation: ${issue.recommendation}
`).join('\n')}

HIGH RISK VULNERABILITIES (${analysis.highRiskIssues.length})
${analysis.highRiskIssues.map((issue, i) => `
${i + 1}. ${issue.issue}
   Category: ${issue.category}
   Risk Details: ${issue.details}
   Impact: ${issue.impact}
   Recommendation: ${issue.recommendation}
`).join('\n')}

MEDIUM RISK FINDINGS (${analysis.mediumRiskIssues.length})
${analysis.mediumRiskIssues.map((issue, i) => `
${i + 1}. ${issue.issue}
   Category: ${issue.category}
   Risk Details: ${issue.details}
   Impact: ${issue.impact}
   Recommendation: ${issue.recommendation}
`).join('\n')}

LOW RISK FINDINGS (${analysis.lowRiskIssues.length})
${analysis.lowRiskIssues.map((issue, i) => `
${i + 1}. ${issue.issue}
   Category: ${issue.category}
   Risk Details: ${issue.details}
   Impact: ${issue.impact}
   Recommendation: ${issue.recommendation}
`).join('\n')}

NETWORK INFRASTRUCTURE ANALYSIS
===============================
Open Ports: ${record.ports_masscan?.join(', ') || 'No open ports detected'}

SERVICE ENUMERATION
==================
${Object.entries(record.services || {}).map(([port, svc]) => `
Port ${port}/tcp: ${svc.service} ${svc.version || ''}
`).join('\n')}

DETAILED SCANNER RESULTS
=======================
Nuclei Templates: ${record.nuclei?.length || 0} findings
${record.nuclei?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No vulnerabilities detected'}

Nikto Web Scanner: ${record.nikto?.length || 0} findings
${record.nikto?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No web vulnerabilities detected'}

Nmap Vulnerability Scripts: ${record.nmap_vulns?.length || 0} findings
${record.nmap_vulns?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No script vulnerabilities detected'}

Custom Security Checks: ${record.custom_checks?.length || 0} findings
${record.custom_checks?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No custom security issues detected'}

${record.exploit_results ? `
EXPLOIT TESTING RESULTS
=======================
EternalBlue: ${record.exploit_results.eternalblue?.length || 0} findings
${record.exploit_results.eternalblue?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No EternalBlue vulnerabilities detected'}

SQL Injection: ${record.exploit_results.sql_injection?.length || 0} findings
${record.exploit_results.sql_injection?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No SQL injection vulnerabilities detected'}

Web Exploits: ${record.exploit_results.web_exploits?.length || 0} findings
${record.exploit_results.web_exploits?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No web exploits detected'}

FTP Exploits: ${record.exploit_results.ftp_exploits?.length || 0} findings
${record.exploit_results.ftp_exploits?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No FTP exploits detected'}

SSH Exploits: ${record.exploit_results.ssh_exploits?.length || 0} findings
${record.exploit_results.ssh_exploits?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No SSH exploits detected'}

RDP Exploits: ${record.exploit_results.rdp_exploits?.length || 0} findings
${record.exploit_results.rdp_exploits?.map((finding, i) => `${i + 1}. ${finding}`).join('\n') || 'No RDP exploits detected'}
` : ''}

COMPREHENSIVE RECOMMENDATIONS
============================
${analysis.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join('\n')}

END OF TECHNICAL ASSESSMENT REPORT
==================================
Report Generated: ${new Date().toLocaleString()}
Assessment Target: ${record.target}
Report Classification: CONFIDENTIAL
`;

    const blob = new Blob([technicalReport], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Technical_Report_${record.target.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const generateExecutiveReport = (record) => {
    const analysis = analyzeFindings(record);
    const confidence = calculateConfidenceScore(record);
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;
    const pageHeight = doc.internal.pageSize.height;
    const margin = 20;
    const maxWidth = pageWidth - (margin * 2);
    let yPosition = 30;

    const colors = {
      critical: [220, 53, 69],
      high: [245, 158, 11],
      medium: [40, 167, 69],
      low: [23, 162, 184],
      primary: [37, 99, 235],
      secondary: [100, 116, 139]
    };

    const checkPageBreak = (requiredSpace = 30) => {
      if (yPosition > pageHeight - requiredSpace) {
        doc.addPage();
        yPosition = 30;
        return true;
      }
      return false;
    };

    const addSection = (title, color = colors.primary) => {
      checkPageBreak(40);
      yPosition = addTextWithWrap(doc, title, margin, yPosition, maxWidth, { 
        fontSize: 16, bold: true, color, lineHeight: 8 
      });
      doc.setDrawColor(...color);
      doc.line(margin, yPosition, pageWidth - margin, yPosition);
      yPosition += 15;
    };

    const addBulletPoint = (text, indent = 0) => {
      checkPageBreak(20);
      const x = margin + indent;
      const bulletWidth = maxWidth - indent - 10;
      
      yPosition = addTextWithWrap(doc, '• ', x, yPosition, 10, { fontSize: 12, lineHeight: 6 });
      const textY = yPosition - 6;
      yPosition = addTextWithWrap(doc, text, x + 10, textY, bulletWidth, { fontSize: 12, lineHeight: 6 });
      yPosition += 4;
    };

    doc.text('EXECUTIVE SECURITY ASSESSMENT REPORT', pageWidth / 2, 30, { align: 'center' });
    doc.setFontSize(18);
    doc.setTextColor(...colors.primary);
    doc.setFont(undefined, 'bold');
    
    doc.text(`Target: ${record.target} | Generated: ${new Date().toLocaleString()}`, pageWidth / 2, 45, { align: 'center' });
    doc.setFontSize(10);
    doc.setTextColor(...colors.secondary);

    yPosition = 70;

    addSection('EXECUTIVE SUMMARY');
    yPosition = addTextWithWrap(doc, `Risk Level: ${record.risk}`, margin, yPosition, maxWidth, { 
      fontSize: 14, bold: true, 
      color: record.risk === 'Critical' ? colors.critical : 
             record.risk === 'High' ? colors.high : 
             record.risk === 'Medium' ? colors.medium : colors.low,
      lineHeight: 8
    });
    yPosition += 10;

    if (analysis.criticalIssues.length > 0) {
      addSection('CRITICAL SECURITY ISSUES REQUIRING IMMEDIATE ATTENTION');
      yPosition = addTextWithWrap(doc, `${analysis.criticalIssues.length} critical issues identified:`, margin, yPosition, maxWidth, { 
        color: colors.critical, bold: true, lineHeight: 8 
      });
      yPosition += 10;

      analysis.criticalIssues.forEach((issue, index) => {
        checkPageBreak(50);
        yPosition = addTextWithWrap(doc, `${index + 1}. ${issue.issue}`, margin, yPosition, maxWidth, { 
          bold: true, fontSize: 12, lineHeight: 8 
        });
        addBulletPoint(`Risk: ${issue.details}`, 5);
        addBulletPoint(`Impact: ${issue.impact}`, 5);
        addBulletPoint(`Recommendation: ${issue.recommendation}`, 5);
        if (issue.cve) {
          addBulletPoint(`Reference: ${issue.cve}`, 5);
        }
        yPosition += 5;
      });
    }

    if (analysis.highRiskIssues.length > 0) {
      addSection('HIGH PRIORITY SECURITY CONCERNS');
      yPosition = addTextWithWrap(doc, `${analysis.highRiskIssues.length} high-priority issues identified:`, margin, yPosition, maxWidth, { 
        color: colors.high, bold: true, lineHeight: 8 
      });
      yPosition += 10;

      analysis.highRiskIssues.forEach((issue, index) => {
        checkPageBreak(40);
        yPosition = addTextWithWrap(doc, `${index + 1}. ${issue.issue}`, margin, yPosition, maxWidth, { 
          bold: true, fontSize: 12, lineHeight: 8 
        });
        addBulletPoint(`Risk: ${issue.details}`, 5);
        addBulletPoint(`Impact: ${issue.impact}`, 5);
        addBulletPoint(`Recommendation: ${issue.recommendation}`, 5);
        yPosition += 5;
      });
    }

    if (analysis.mediumRiskIssues.length > 0) {
      addSection('MEDIUM RISK SECURITY FINDINGS');
      yPosition = addTextWithWrap(doc, `${analysis.mediumRiskIssues.length} medium-risk issues identified:`, margin, yPosition, maxWidth, { 
        color: colors.medium, bold: true, lineHeight: 8 
      });
      yPosition += 10;

      analysis.mediumRiskIssues.forEach((issue, index) => {
        checkPageBreak(30);
        yPosition = addTextWithWrap(doc, `${index + 1}. ${issue.issue}`, margin, yPosition, maxWidth, { 
          fontSize: 11, lineHeight: 7 
        });
        addBulletPoint(`Risk: ${issue.details}`, 5);
        addBulletPoint(`Recommendation: ${issue.recommendation}`, 5);
        yPosition += 3;
      });
    }

    addSection('STRATEGIC SECURITY RECOMMENDATIONS');
    
    yPosition = addTextWithWrap(doc, 'Immediate Actions (0-48 hours)', margin, yPosition, maxWidth, { 
      bold: true, fontSize: 13, lineHeight: 8 
    });
    yPosition += 5;
    
    const immediateActions = analysis.criticalIssues.length > 0 ? [
      'Isolate affected systems from network until critical patches applied',
      'Implement emergency monitoring for all critical vulnerabilities',
      'Activate incident response procedures and notify stakeholders',
      'Conduct emergency security briefing with technical teams'
    ] : [
      'Continue current security monitoring procedures',
      'Plan routine security patch deployment',
      'Maintain existing security controls'
    ];
    
    immediateActions.forEach(action => addBulletPoint(action, 10));
    yPosition += 10;

    yPosition = addTextWithWrap(doc, 'Long-term Strategic Initiatives (1-6 months)', margin, yPosition, maxWidth, { 
      bold: true, fontSize: 13, lineHeight: 8 
    });
    yPosition += 5;
    
    const longTermActions = [
      'Implement comprehensive security operations center',
      'Deploy network segmentation and access controls',
      'Establish threat intelligence capabilities',
      'Create business continuity plans',
      'Develop security governance framework'
    ];
    
    longTermActions.forEach(action => addBulletPoint(action, 10));

    checkPageBreak(30);
    yPosition = pageHeight - 20;
    doc.setFontSize(8);
    doc.setTextColor(...colors.secondary);
    doc.text(`VAPT Scanner Professional | ${new Date().toLocaleString()}`, pageWidth / 2, yPosition, { align: 'center' });

    const filename = `Executive_Report_${record.target.replace(/[^a-zA-Z0-9]/g, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename);
  };

  const generateBulkTechnicalReport = (results) => {
    const bulkAnalysis = {
      totalTargets: results.length,
      criticalTargets: results.filter(r => r.risk === 'Critical').length,
      highRiskTargets: results.filter(r => r.risk === 'High').length,
      mediumRiskTargets: results.filter(r => r.risk === 'Medium').length,
      lowRiskTargets: results.filter(r => r.risk === 'Low').length,
      normalTargets: results.filter(r => r.risk === 'Normal').length,
      totalVulnerabilities: results.reduce((sum, r) => sum + (r.total_vulnerabilities || 0), 0),
      totalPorts: results.reduce((sum, r) => sum + (r.ports_masscan?.length || 0), 0),
      avgScanTime: results.reduce((sum, r) => sum + (r.scan_time || 0), 0) / results.length,
      avgConfidence: results.reduce((sum, r) => sum + (calculateConfidenceScore(r).score || 0), 0) / results.length
    };
    
    const report = `
COMPREHENSIVE BULK VAPT TECHNICAL ASSESSMENT REPORT
==================================================

EXECUTIVE SUMMARY
================
Assessment Date: ${new Date().toLocaleString()}
Total Targets Assessed: ${bulkAnalysis.totalTargets}

OVERALL RISK DISTRIBUTION
=========================
Critical Risk Systems: ${bulkAnalysis.criticalTargets} (${((bulkAnalysis.criticalTargets / bulkAnalysis.totalTargets) * 100).toFixed(1)}%)
High Risk Systems: ${bulkAnalysis.highRiskTargets} (${((bulkAnalysis.highRiskTargets / bulkAnalysis.totalTargets) * 100).toFixed(1)}%)
Medium Risk Systems: ${bulkAnalysis.mediumRiskTargets} (${((bulkAnalysis.mediumRiskTargets / bulkAnalysis.totalTargets) * 100).toFixed(1)}%)
Low Risk Systems: ${bulkAnalysis.lowRiskTargets} (${((bulkAnalysis.lowRiskTargets / bulkAnalysis.totalTargets) * 100).toFixed(1)}%)
Normal Systems: ${bulkAnalysis.normalTargets} (${((bulkAnalysis.normalTargets / bulkAnalysis.totalTargets) * 100).toFixed(1)}%)

COMPREHENSIVE ASSESSMENT RESULTS BY TARGET
==========================================

${results.map((result, i) => {
  const analysis = analyzeFindings(result);
  const confidence = calculateConfidenceScore(result);
  
  return `
TARGET ${i + 1}: ${result.target}
${'='.repeat(50)}
Risk Classification: ${result.risk}
Assessment Confidence: ${confidence.score}/100 (${confidence.level})
Scan Duration: ${result.scan_time || 0} seconds
Total Vulnerabilities: ${result.total_vulnerabilities || 0}
Open Ports: ${result.ports_masscan?.length || 0}
Services: ${Object.keys(result.services || {}).length}

CRITICAL ISSUES (${analysis.criticalIssues.length}):
${analysis.criticalIssues.map((issue, idx) => `
${idx + 1}. ${issue.issue}
   Risk: ${issue.details}
   Impact: ${issue.impact}
   Recommendation: ${issue.recommendation}
   ${issue.cve ? `CVE: ${issue.cve}` : ''}
`).join('')}

HIGH RISK ISSUES (${analysis.highRiskIssues.length}):
${analysis.highRiskIssues.map((issue, idx) => `
${idx + 1}. ${issue.issue}
   Risk: ${issue.details}
   Impact: ${issue.impact}
   Recommendation: ${issue.recommendation}
`).join('')}

MEDIUM RISK ISSUES (${analysis.mediumRiskIssues.length}):
${analysis.mediumRiskIssues.map((issue, idx) => `
${idx + 1}. ${issue.issue}
   Risk: ${issue.details}
   Recommendation: ${issue.recommendation}
`).join('')}

NETWORK ANALYSIS:
Open Ports: ${result.ports_masscan?.join(', ') || 'None'}
Services: ${Object.entries(result.services || {}).map(([port, svc]) => `${port}/${svc.service}`).join(', ') || 'None'}

VULNERABILITY SCANNER RESULTS:
- Nuclei: ${result.nuclei?.length || 0} findings
- Nikto: ${result.nikto?.length || 0} findings
- Nmap Vulns: ${result.nmap_vulns?.length || 0} findings
- Custom Checks: ${result.custom_checks?.length || 0} findings

${result.exploit_results ? `
EXPLOIT TESTING RESULTS:
- EternalBlue: ${result.exploit_results.eternalblue?.length || 0} findings
- SQL Injection: ${result.exploit_results.sql_injection?.length || 0} findings
- Web Exploits: ${result.exploit_results.web_exploits?.length || 0} findings
- FTP Exploits: ${result.exploit_results.ftp_exploits?.length || 0} findings
- SSH Exploits: ${result.exploit_results.ssh_exploits?.length || 0} findings
- RDP Exploits: ${result.exploit_results.rdp_exploits?.length || 0} findings
` : 'Exploit testing: Disabled'}

CONFIDENCE ASSESSMENT:
Score: ${confidence.score}/100 (${confidence.level})
Factors: ${confidence.factors.join(', ')}

BUSINESS IMPACT:
- Data Breach Risk: ${analysis.businessImpact.dataBreachRisk}
- Operational Impact: ${analysis.businessImpact.operationalImpact}
- Financial Risk: ${analysis.businessImpact.financialRisk}

RECOMMENDATIONS FOR ${result.target}:
${analysis.recommendations.map((rec, idx) => `${idx + 1}. ${rec}`).join('\n')}

${'='.repeat(80)}
`;
}).join('\n')}

ENTERPRISE SECURITY RECOMMENDATIONS
===================================
${bulkAnalysis.criticalTargets > 0 ? `
IMMEDIATE ACTIONS (0-24 hours):
1. Isolate all ${bulkAnalysis.criticalTargets} critical-risk systems
2. Implement emergency patching procedures
3. Activate incident response team
4. Conduct executive security briefing
5. Implement enhanced monitoring

` : ''}
${bulkAnalysis.highRiskTargets > 0 ? `
PRIORITY ACTIONS (24-72 hours):
1. Remediate high-risk vulnerabilities on ${bulkAnalysis.highRiskTargets} systems
2. Implement additional security controls
3. Review security policies and procedures
4. Conduct security awareness training
5. Establish vulnerability assessment schedule

` : ''}
STRATEGIC INITIATIVES (1-6 months):
1. Deploy enterprise security operations center (SOC)
2. Implement network segmentation and zero-trust architecture
3. Establish threat intelligence program
4. Create business continuity plans
5. Develop security governance framework

COMPREHENSIVE STATISTICS
========================
Total Systems: ${bulkAnalysis.totalTargets}
Total Vulnerabilities: ${bulkAnalysis.totalVulnerabilities}
Total Open Ports: ${bulkAnalysis.totalPorts}
Average Scan Time: ${bulkAnalysis.avgScanTime.toFixed(2)} seconds
Average Confidence: ${bulkAnalysis.avgConfidence.toFixed(1)}/100

EXECUTIVE SUMMARY
================
${bulkAnalysis.criticalTargets > 0 ? `
CRITICAL SECURITY POSTURE: ${bulkAnalysis.criticalTargets} systems require immediate attention
- Emergency action required
- Consider external security incident response team
- Implement crisis communication plan
` : bulkAnalysis.highRiskTargets > 0 ? `
ELEVATED SECURITY CONCERNS: ${bulkAnalysis.highRiskTargets} systems need priority remediation
- Executive oversight recommended
- Accelerated security improvement program needed
- Regular progress reporting required
` : `
MANAGEABLE SECURITY POSTURE: Current controls appear adequate
- Continue current security practices
- Maintain regular assessment schedule
- Monitor for emerging threats
`}

      ...
END OF BULK TECHNICAL ASSESSMENT REPORT
=======================================
Report Generated: ${new Date().toLocaleString()}
Total Targets: ${bulkAnalysis.totalTargets}
Report ID: BULK-TECH-${new Date()
  .toISOString()
  .split('T')[0]}-${Math.random().toString(36).substr(2, 9).toUpperCase()}
`;

    const blob = new Blob([report], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `Bulk_Technical_Report_${new Date()
      .toISOString()
      .split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const showDetails = (record) => {
    setSelectedResult(record);
    setActiveView('details');
  };

  const getRiskStats = () => {
    if (results.length === 0) return [];
    const riskCounts = results.reduce((acc, result) => {
      const risk = result.risk || 'Normal';
      acc[risk] = (acc[risk] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(riskCounts);
  };

  const handleExploitToggle = (checked) => {
    setEnableExploits(checked);
    if (!checked) setExploitConfirmed(false);
  };

  const confirmExploitMode = () => {
    if (
      window.confirm(
        'You are enabling exploit (PoC-only) testing.\n' +
          'Use ONLY on systems you own or are authorised to test.\n\n' +
          'Continue?'
      )
    ) {
      setExploitConfirmed(true);
      addDebugLog('Exploit mode confirmed by user');
    } else {
      setEnableExploits(false);
      setExploitConfirmed(false);
      addDebugLog('Exploit mode cancelled by user');
    }
  };

  const generateBulkExecutiveReport = (results) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;
    const pageHeight = doc.internal.pageSize.height;
    const margin = 20;
    const maxWidth = pageWidth - (margin * 2);
    let yPosition = 30;

    const colors = {
      critical: [220, 53, 69],
      high: [255, 193, 7],
      primary: [37, 99, 235],
      secondary: [100, 116, 139]
    };

    const bulkAnalysis = {
      totalTargets: results.length,
      criticalTargets: results.filter(r => r.risk === 'Critical').length,
      highRiskTargets: results.filter(r => r.risk === 'High').length,
      mediumRiskTargets: results.filter(r => r.risk === 'Medium').length,
      lowRiskTargets: results.filter(r => r.risk === 'Low').length,
      normalTargets: results.filter(r => r.risk === 'Normal').length,
      totalVulnerabilities: results.reduce((sum, r) => sum + (r.total_vulnerabilities || 0), 0),
      avgConfidence: results.reduce((sum, r) => sum + (calculateConfidenceScore(r).score || 0), 0) / results.length
    };

    const checkPageBreak = (requiredSpace = 30) => {
      if (yPosition > pageHeight - requiredSpace) {
        doc.addPage();
        yPosition = 30;
        return true;
      }
      return false;
    };

    const addSection = (title, color = colors.primary) => {
      checkPageBreak(40);
      yPosition = addTextWithWrap(doc, title, margin, yPosition, maxWidth, { 
        fontSize: 16, bold: true, color, lineHeight: 8 
      });
      doc.setDrawColor(...color);
      doc.line(margin, yPosition, pageWidth - margin, yPosition);
      yPosition += 15;
    };

    const addBulletPoint = (text, indent = 0) => {
      checkPageBreak(20);
      const x = margin + indent;
      const bulletWidth = maxWidth - indent - 10;
      
      yPosition = addTextWithWrap(doc, '• ', x, yPosition, 10, { fontSize: 12, lineHeight: 6 });
      const textY = yPosition - 6;
      yPosition = addTextWithWrap(doc, text, x + 10, textY, bulletWidth, { fontSize: 12, lineHeight: 6 });
      yPosition += 4;
    };

    doc.text('ENTERPRISE SECURITY ASSESSMENT EXECUTIVE REPORT', pageWidth / 2, 30, { align: 'center' });
    doc.setFontSize(18);
    doc.setTextColor(...colors.primary);
    doc.setFont(undefined, 'bold');
    
    doc.text(`${results.length} Systems Assessed | Generated: ${new Date().toLocaleString()}`, pageWidth / 2, 45, { align: 'center' });
    doc.setFontSize(10);
    doc.setTextColor(...colors.secondary);

    yPosition = 70;

    addSection('EXECUTIVE SUMMARY');
    
    const overallRisk = bulkAnalysis.criticalTargets > 0 ? 'CRITICAL' : 
                        bulkAnalysis.highRiskTargets > 0 ? 'HIGH' : 'MODERATE';
    
    yPosition = addTextWithWrap(doc, `Overall Infrastructure Risk: ${overallRisk}`, margin, yPosition, maxWidth, { 
      fontSize: 14, bold: true, 
      color: overallRisk === 'CRITICAL' ? colors.critical : 
             overallRisk === 'HIGH' ? colors.high : colors.primary,
      lineHeight: 8
    });
    yPosition += 15;

    addSection('COMPREHENSIVE RISK ANALYSIS BY TARGET');
    
    results.forEach((result, index) => {
      const analysis = analyzeFindings(result);
      const confidence = calculateConfidenceScore(result);
      
      checkPageBreak(80);
      yPosition = addTextWithWrap(doc, `Target ${index + 1}: ${result.target}`, margin, yPosition, maxWidth, { 
        fontSize: 14, bold: true, lineHeight: 8 
      });
      yPosition += 5;
      
      addBulletPoint(`Risk Level: ${result.risk}`, 5);
      addBulletPoint(`Assessment Confidence: ${confidence.score}/100 (${confidence.level})`, 5);
      addBulletPoint(`Total Vulnerabilities: ${result.total_vulnerabilities || 0}`, 5);
      addBulletPoint(`Open Ports: ${result.ports_masscan?.length || 0}`, 5);
      addBulletPoint(`Critical Issues: ${analysis.criticalIssues.length}`, 5);
      addBulletPoint(`High-Risk Issues: ${analysis.highRiskIssues.length}`, 5);
      
      if (analysis.criticalIssues.length > 0) {
        addBulletPoint(`Critical Threats: ${analysis.criticalIssues.slice(0, 3).map(i => i.issue).join(', ')}`, 10);
      }
      
      if (analysis.highRiskIssues.length > 0) {
        addBulletPoint(`High-Risk Threats: ${analysis.highRiskIssues.slice(0, 3).map(i => i.issue).join(', ')}`, 10);
      }
      
      addBulletPoint(`Business Impact: ${analysis.businessImpact.operationalImpact}`, 5);
      addBulletPoint(`Data Breach Risk: ${analysis.businessImpact.dataBreachRisk}`, 5);
      
      yPosition += 15;
    });

    addSection('ENTERPRISE RISK DISTRIBUTION');
    
    Object.entries({
      Critical: bulkAnalysis.criticalTargets,
      High: bulkAnalysis.highRiskTargets,
      Medium: bulkAnalysis.mediumRiskTargets,
      Low: bulkAnalysis.lowRiskTargets,
      Normal: bulkAnalysis.normalTargets
    }).forEach(([risk, count]) => {
      if (count > 0) {
        const percentage = ((count / bulkAnalysis.totalTargets) * 100).toFixed(1);
        addBulletPoint(`${risk} Risk: ${count} systems (${percentage}%)`, 0);
      }
    });
    yPosition += 10;

    addSection('BUSINESS IMPACT ASSESSMENT');
    
    const businessImpact = bulkAnalysis.criticalTargets > 0 ? 'SEVERE' : 
                          bulkAnalysis.highRiskTargets > 0 ? 'MODERATE' : 'MINIMAL';
    
    yPosition = addTextWithWrap(doc, `Business Impact Level: ${businessImpact}`, margin, yPosition, maxWidth, { 
      fontSize: 13, bold: true, lineHeight: 8 
    });
    yPosition += 10;
    
    if (bulkAnalysis.criticalTargets > 0) {
      addBulletPoint('Immediate risk of data breach and system compromise', 0);
      addBulletPoint('Potential regulatory violations and compliance issues', 0);
      addBulletPoint('Significant operational disruption likely', 0);
      addBulletPoint('Reputational damage and customer trust erosion', 0);
    } else if (bulkAnalysis.highRiskTargets > 0) {
      addBulletPoint('Elevated risk of security incidents', 0);
      addBulletPoint('Potential compliance concerns', 0);
      addBulletPoint('Moderate operational impact possible', 0);
      addBulletPoint('Manageable reputational risk', 0);
    } else {
      addBulletPoint('Low risk of security incidents', 0);
      addBulletPoint('Compliance requirements generally met', 0);
      addBulletPoint('Minimal operational impact expected', 0);
      addBulletPoint('Stable security posture maintained', 0);
    }
    yPosition += 10;

    addSection('STRATEGIC RECOMMENDATIONS');
    
    if (bulkAnalysis.criticalTargets > 0) {
      yPosition = addTextWithWrap(doc, 'IMMEDIATE EXECUTIVE ACTION REQUIRED', margin, yPosition, maxWidth, { 
        fontSize: 13, bold: true, color: colors.critical, lineHeight: 8 
      });
      yPosition += 10;
      
      addBulletPoint('Activate emergency incident response procedures', 0);
      addBulletPoint('Isolate all critical-risk systems immediately', 0);
      addBulletPoint('Allocate emergency security budget and resources', 0);
      addBulletPoint('Engage external security incident response team', 0);
      addBulletPoint('Implement daily executive security briefings', 0);
      addBulletPoint('Prepare crisis communication plan', 0);
    } else if (bulkAnalysis.highRiskTargets > 0) {
      yPosition = addTextWithWrap(doc, 'PRIORITY EXECUTIVE OVERSIGHT RECOMMENDED', margin, yPosition, maxWidth, { 
        fontSize: 13, bold: true, color: colors.high, lineHeight: 8 
      });
      yPosition += 10;
      
      addBulletPoint('Accelerate security improvement program', 0);
      addBulletPoint('Allocate additional security resources', 0);
      addBulletPoint('Implement weekly security progress reviews', 0);
      addBulletPoint('Consider security consulting engagement', 0);
      addBulletPoint('Enhance security training programs', 0);
    } else {
      yPosition = addTextWithWrap(doc, 'MAINTAIN CURRENT SECURITY PRACTICES', margin, yPosition, maxWidth, { 
        fontSize: 13, bold: true, color: colors.primary, lineHeight: 8 
      });
      yPosition += 10;
      
      addBulletPoint('Continue regular security monitoring', 0);
      addBulletPoint('Maintain current security investment levels', 0);
      addBulletPoint('Schedule quarterly security assessments', 0);
      addBulletPoint('Monitor emerging security threats', 0);
      addBulletPoint('Plan gradual security enhancements', 0);
    }

    checkPageBreak(30);
    yPosition = pageHeight - 20;
    doc.setFontSize(8);
    doc.setTextColor(...colors.secondary);
    doc.text(`VAPT Scanner Professional | Enterprise Security Assessment | ${new Date().toLocaleString()}`, pageWidth / 2, yPosition, { align: 'center' });

    const filename = `Bulk_Executive_Report_${new Date().toISOString().split('T')[0]}.pdf`;
    doc.save(filename);
  };

  const getRiskIcon = (risk) => {
    switch (risk?.toLowerCase()) {
      case 'critical': return <AlertTriangle className="w-4 h-4" />;
      case 'high': return <AlertCircle className="w-4 h-4" />;
      case 'medium': return <Info className="w-4 h-4" />;
      case 'low': return <CheckCircle className="w-4 h-4" />;
      case 'normal': return <Shield className="w-4 h-4" />;
      default: return <XCircle className="w-4 h-4" />;
    }
  };

  const ConfidenceMeter = ({ result }) => {
    const confidence = calculateConfidenceScore(result);
    const getConfidenceColor = (score) => {
      if (score >= 90) return '#10b981';
      if (score >= 80) return '#3b82f6';
      if (score >= 70) return '#f59e0b';
      if (score >= 60) return '#f97316';
      return '#ef4444';
    };

    return (
      <div style={{
        marginBottom: '16px',
        padding: '12px',
        background: darkMode ? '#4a5568' : '#f1f5f9',
        borderRadius: '8px',
        border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <Gauge className="w-4 h-4" />
          <span style={{ fontSize: '12px', color: darkMode ? '#a0aec0' : '#64748b', fontWeight: 500 }}>
            Assessment Confidence
          </span>
          <span style={{ fontSize: '14px', fontWeight: 600, color: darkMode ? '#e2e8f0' : '#1e293b' }}>
            {confidence.score}/100
          </span>
        </div>
        <div style={{
          height: '6px',
          background: darkMode ? '#718096' : '#e2e8f0',
          borderRadius: '3px',
          overflow: 'hidden',
          marginBottom: '8px'
        }}>
          <div style={{
            height: '100%',
            width: `${confidence.score}%`,
            backgroundColor: getConfidenceColor(confidence.score),
            transition: 'width 0.3s ease'
          }} />
        </div>
        <div style={{
          fontSize: '11px',
          color: darkMode ? '#718096' : '#8b949e',
          textAlign: 'center',
          marginBottom: '8px'
        }}>
          {confidence.level}
        </div>
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '4px',
          maxHeight: '120px',
          overflowY: 'auto'
        }}>
          {confidence.factors.map((factor, index) => (
            <div key={index} style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '10px',
              color: darkMode ? '#a0aec0' : '#64748b'
            }}>
              <CheckCircle className="w-3 h-3" />
              <span>{factor}</span>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const styles = {
    appContainer: {
      display: 'flex',
      height: '100vh',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      background: darkMode ? '#1a202c' : '#f8fafc',
      color: darkMode ? '#e2e8f0' : '#1e293b',
      overflow: 'hidden'
    },
    sidebar: {
      width: sidebarCollapsed ? '70px' : '280px',
      background: '#2563eb',
      color: 'white',
      transition: 'width 0.3s ease',
      display: 'flex',
      flexDirection: 'column',
      boxShadow: '2px 0 8px rgba(0, 0, 0, 0.1)',
      overflow: 'hidden',
      flexShrink: 0
    },
    sidebarHeader: {
      padding: '20px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
      minHeight: '80px'
    },
    logo: {
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      overflow: 'hidden'
    },
    logoIcon: {
      width: '40px',
      height: '40px',
      background: darkMode ? '#2d3748' : '#ffffff',
      color: '#2563eb',
      borderRadius: '8px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontWeight: 'bold',
      flexShrink: 0
    },
    logoText: {
      fontSize: '18px',
      fontWeight: 600,
      whiteSpace: 'nowrap',
      opacity: sidebarCollapsed ? 0 : 1,
      transition: 'opacity 0.3s ease'
    },
    sidebarToggle: {
      background: 'rgba(255, 255, 255, 0.1)',
      border: 'none',
      color: 'white',
      padding: '8px',
      borderRadius: '4px',
      cursor: 'pointer',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      flexShrink: 0
    },
    sidebarNav: {
      flex: 1,
      padding: '20px 0',
      overflowY: 'auto',
      overflowX: 'hidden'
    },
    navSection: {
      marginBottom: '24px'
    },
    navSectionTitle: {
      fontSize: '11px',
      fontWeight: 600,
      color: 'rgba(255, 255, 255, 0.6)',
      textTransform: 'uppercase',
      letterSpacing: '0.5px',
      marginBottom: '8px',
      padding: '0 20px',
      opacity: sidebarCollapsed ? 0 : 1,
      height: sidebarCollapsed ? 0 : 'auto',
      transition: 'all 0.3s ease'
    },
    navItems: {
      display: 'flex',
      flexDirection: 'column',
      gap: '4px'
    },
    navItem: {
      display: 'flex',
      alignItems: 'center',
      gap: '12px',
      padding: '12px 20px',
      background: 'none',
      border: 'none',
      color: 'rgba(255, 255, 255, 0.8)',
      cursor: 'pointer',
      transition: 'all 0.2s ease',
      textAlign: 'left',
      width: '100%',
      minHeight: '44px'
    },
    navItemActive: {
      background: 'rgba(255, 255, 255, 0.15)',
      color: 'white',
      fontWeight: 600
    },
    navIcon: {
      width: '20px',
      height: '20px',
      flexShrink: 0
    },
    navText: {
      fontSize: '14px',
      whiteSpace: 'nowrap',
      opacity: sidebarCollapsed ? 0 : 1,
      transition: 'opacity 0.3s ease'
    },
    navBadge: {
      marginLeft: 'auto',
      background: '#ef4444',
      color: 'white',
      fontSize: '10px',
      padding: '2px 6px',
      borderRadius: '10px',
      fontWeight: 600,
      opacity: sidebarCollapsed ? 0 : 1,
      transition: 'opacity 0.3s ease'
    },
    sidebarFooter: {
      padding: '20px',
      borderTop: '1px solid rgba(255, 255, 255, 0.1)'
    },
    mainContent: {
      flex: 1,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden'
    },
    topBar: {
      background: darkMode ? '#2d3748' : '#ffffff',
      padding: '16px 24px',
      borderBottom: `1px solid ${darkMode ? '#4a5568' : '#e2e8f0'}`,
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      boxShadow: '0 1px 3px rgba(0, 0, 0, 0.1)',
      flexShrink: 0
    },
    contentArea: {
      flex: 1,
      overflowY: 'auto',
      overflowX: 'hidden',
      padding: '24px'
    },
    card: {
      background: darkMode ? '#2d3748' : '#ffffff',
      borderRadius: '12px',
      padding: '20px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
      border: `1px solid ${darkMode ? '#4a5568' : '#e2e8f0'}`,
      marginBottom: '24px',
      overflow: 'hidden',
      wordWrap: 'break-word'
    },
    btn: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: '8px',
      padding: '12px 24px',
      border: 'none',
      borderRadius: '8px',
      fontSize: '14px',
      fontWeight: 600,
      cursor: 'pointer',
      transition: 'all 0.2s ease',
      textDecoration: 'none',
      outline: 'none',
      fontFamily: 'inherit',
      whiteSpace: 'nowrap'
    },
    btnPrimary: {
      background: '#2563eb',
      color: 'white'
    },
    btnSecondary: {
      background: '#64748b',
      color: 'white'
    },
    btnOutline: {
      background: 'transparent',
      color: '#2563eb',
      border: '2px solid #2563eb'
    },
    inputField: {
      flex: 1,
      padding: '12px 16px',
      border: `2px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
      borderRadius: '8px',
      fontSize: '16px',
      color: darkMode ? '#e2e8f0' : '#1e293b',
      background: darkMode ? '#4a5568' : '#ffffff',
      transition: 'all 0.2s ease'
    },
    textareaField: {
      width: '100%',
      padding: '12px 16px',
      border: `2px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
      borderRadius: '8px',
      fontSize: '16px',
      color: darkMode ? '#e2e8f0' : '#1e293b',
      background: darkMode ? '#4a5568' : '#ffffff',
      minHeight: '120px',
      resize: 'vertical',
      fontFamily: 'inherit',
      transition: 'all 0.2s ease'
    },
    debugPanel: {
      background: darkMode ? '#2d3748' : '#ffffff',
      border: `1px solid ${darkMode ? '#4a5568' : '#e2e8f0'}`,
      borderRadius: '12px',
      marginBottom: '24px',
      overflow: 'hidden'
    },
    debugHeader: {
      padding: '16px 20px',
      background: darkMode ? '#1a202c' : '#f8fafc',
      borderBottom: `1px solid ${darkMode ? '#4a5568' : '#e2e8f0'}`,
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    },
    debugContent: {
      padding: '0',
      maxHeight: '400px',
      overflowY: 'auto',
      overflowX: 'hidden'
    },
    debugLogs: {
      background: '#1a1a1a',
      color: '#00ff00',
      fontFamily: '"Courier New", monospace',
      fontSize: '12px',
      padding: '12px',
      borderRadius: '6px',
      maxHeight: '200px',
      overflowY: 'auto',
      overflowX: 'hidden'
    },
    scrollableList: {
      maxHeight: '300px',
      overflowY: 'auto',
      overflowX: 'hidden'
    }
  };

  return (
    <div style={styles.appContainer}>
      <style>{`
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        .animate-spin {
          animation: spin 1s linear infinite;
        }
      `}</style>
      
      <div style={styles.sidebar}>
        <div style={styles.sidebarHeader}>
          <div style={styles.logo}>
            <div style={styles.logoIcon}>
              <Shield className="w-6 h-6" />
            </div>
            <span style={styles.logoText}>VAPT Scanner</span>
          </div>
          <button 
            style={styles.sidebarToggle}
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          >
            {sidebarCollapsed ? <Menu className="w-4 h-4" /> : <X className="w-4 h-4" />}
          </button>
        </div>

        <nav style={styles.sidebarNav}>
          <div style={styles.navSection}>
            <div style={styles.navSectionTitle}>Main</div>
            <div style={styles.navItems}>
              <button 
                style={{
                  ...styles.navItem,
                  ...(activeView === 'dashboard' ? styles.navItemActive : {})
                }}
                onClick={() => setActiveView('dashboard')}
              >
                <BarChart3 style={styles.navIcon} />
                <span style={styles.navText}>Dashboard</span>
              </button>
              <button 
                style={{
                  ...styles.navItem,
                  ...(activeView === 'single-scan' ? styles.navItemActive : {})
                }}
                onClick={() => setActiveView('single-scan')}
              >
                <Target style={styles.navIcon} />
                <span style={styles.navText}>Single Scan</span>
              </button>
              <button 
                style={{
                  ...styles.navItem,
                  ...(activeView === 'bulk-scan' ? styles.navItemActive : {})
                }}
                onClick={() => setActiveView('bulk-scan')}
              >
                <Layers style={styles.navIcon} />
                <span style={styles.navText}>Bulk Scan</span>
              </button>
              <button 
                style={{
                  ...styles.navItem,
                  ...(activeView === 'results' ? styles.navItemActive : {})
                }}
                onClick={() => setActiveView('results')}
              >
                <FileSpreadsheet style={styles.navIcon} />
                <span style={styles.navText}>Results</span>
                {results.length > 0 && (
                  <span style={styles.navBadge}>{results.length}</span>
                )}
              </button>
            </div>
          </div>

          <div style={styles.navSection}>
            <div style={styles.navSectionTitle}>Monitor</div>
            <div style={styles.navItems}>
              <button 
                style={{
                  ...styles.navItem,
                  ...(activeView === 'monitoring' ? styles.navItemActive : {})
                }}
                onClick={() => setActiveView('monitoring')}
              >
                <Monitor style={styles.navIcon} />
                <span style={styles.navText}>Live Monitor</span>
                {(singleJob || bulkJob) && (
                  <span style={styles.navBadge}>
                    <Activity className="w-3 h-3" />
                  </span>
                )}
              </button>
            </div>
          </div>
        </nav>

        <div style={styles.sidebarFooter}>
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '16px' }}>
            <button 
              style={styles.sidebarToggle}
              onClick={() => setDarkMode(!darkMode)}
            >
              {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>
          <div style={{ 
            display: 'flex', 
            gap: '12px', 
            justifyContent: 'center',
            opacity: sidebarCollapsed ? 0 : 1,
            transition: 'opacity 0.3s ease'
          }}>
            <div style={{ textAlign: 'center', flex: 1 }}>
              <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.6)' }}>Active</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: 'white' }}>
                {stats.active_jobs || 0}
              </div>
            </div>
            <div style={{ textAlign: 'center', flex: 1 }}>
              <div style={{ fontSize: '10px', color: 'rgba(255, 255, 255, 0.6)' }}>Bulk</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: 'white' }}>
                {stats.active_bulk_jobs || 0}
              </div>
            </div>
          </div>
        </div>
      </div>

      <div style={styles.mainContent}>
        <div style={styles.topBar}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '14px' }}>
            <span style={{ color: darkMode ? '#a0aec0' : '#64748b' }}>VAPT Scanner</span>
            <span style={{ color: darkMode ? '#718096' : '#8b949e' }}>/</span>
            <span style={{ color: darkMode ? '#e2e8f0' : '#1e293b', fontWeight: 600 }}>
              {activeView === 'dashboard' && 'Dashboard'}
              {activeView === 'single-scan' && 'Single Scan'}
              {activeView === 'bulk-scan' && 'Bulk Scan'}
              {activeView === 'results' && 'Results'}
              {activeView === 'monitoring' && 'Live Monitor'}
              {activeView === 'details' && 'Scan Details'}
            </span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: (singleJob || bulkJob) ? '#10b981' : '#8b949e',
                display: 'block'
              }}></span>
              <span style={{ fontSize: '12px', color: darkMode ? '#a0aec0' : '#64748b' }}>
                {(singleJob || bulkJob) ? 'Scanning' : 'Idle'}
              </span>
            </div>
          </div>
        </div>

        <div style={styles.contentArea}>
          {activeView === 'dashboard' && (
            <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
              <div style={{ textAlign: 'center', marginBottom: '32px' }}>
                <h1 style={{ 
                  fontSize: '32px', 
                  fontWeight: 700, 
                  color: darkMode ? '#e2e8f0' : '#1e293b', 
                  marginBottom: '8px' 
                }}>
                  Security Assessment Dashboard
                </h1>
                <p style={{ 
                  fontSize: '16px', 
                  color: darkMode ? '#a0aec0' : '#64748b' 
                }}>
                  Professional vulnerability assessment and penetration testing platform
                </p>
              </div>

              <div style={{ 
                display: 'grid', 
                gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
                gap: '24px', 
                marginBottom: '32px' 
              }}>
                <div style={{ 
                  ...styles.card, 
                  background: '#2563eb', 
                  color: 'white' 
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div style={{ 
                      padding: '12px', 
                      background: 'rgba(255, 255, 255, 0.2)', 
                      borderRadius: '12px' 
                    }}>
                      <Search className="w-6 h-6" />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '28px', fontWeight: 700, marginBottom: '4px' }}>
                        {results.length}
                      </div>
                      <div style={{ fontSize: '14px', opacity: 0.9 }}>Total Scans</div>
                    </div>
                  </div>
                </div>

                <div style={{ 
                  ...styles.card, 
                  background: '#10b981', 
                  color: 'white' 
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div style={{ 
                      padding: '12px', 
                      background: 'rgba(255, 255, 255, 0.2)', 
                      borderRadius: '12px' 
                    }}>
                      <Activity className="w-6 h-6" />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '28px', fontWeight: 700, marginBottom: '4px' }}>
                        {stats.active_jobs || 0}
                      </div>
                      <div style={{ fontSize: '14px', opacity: 0.9 }}>Active Jobs</div>
                    </div>
                  </div>
                </div>

                <div style={{ 
                  ...styles.card, 
                  background: '#f59e0b', 
                  color: 'white' 
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div style={{ 
                      padding: '12px', 
                      background: 'rgba(255, 255, 255, 0.2)', 
                      borderRadius: '12px' 
                    }}>
                      <Layers className="w-6 h-6" />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '28px', fontWeight: 700, marginBottom: '4px' }}>
                        {stats.active_bulk_jobs || 0}
                      </div>
                      <div style={{ fontSize: '14px', opacity: 0.9 }}>Bulk Jobs</div>
                    </div>
                  </div>
                </div>

                <div style={{ 
                  ...styles.card, 
                  background: '#ef4444', 
                  color: 'white' 
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div style={{ 
                      padding: '12px', 
                      background: 'rgba(255, 255, 255, 0.2)', 
                      borderRadius: '12px' 
                    }}>
                      <AlertTriangle className="w-6 h-6" />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '28px', fontWeight: 700, marginBottom: '4px' }}>
                        {results.filter(r => r.risk === 'Critical').length}
                      </div>
                      <div style={{ fontSize: '14px', opacity: 0.9 }}>Critical Risks</div>
                    </div>
                  </div>
                </div>
              </div>

              <div style={{ marginBottom: '32px' }}>
                <h3 style={{ 
                  marginBottom: '16px', 
                  color: darkMode ? '#e2e8f0' : '#1e293b', 
                  fontSize: '18px' 
                }}>
                  Quick Actions
                </h3>
                <div style={{ 
                  display: 'grid', 
                  gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', 
                  gap: '20px' 
                }}>
                  <div 
                    style={{ 
                      ...styles.card, 
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'transform 0.2s ease, box-shadow 0.2s ease'
                    }}
                    onClick={() => setActiveView('single-scan')}
                  >
                    <div style={{ color: '#2563eb', marginBottom: '16px' }}>
                      <Target className="w-8 h-8" style={{ margin: '0 auto' }} />
                    </div>
                    <div style={{ 
                      fontSize: '16px', 
                      fontWeight: 600, 
                      color: darkMode ? '#e2e8f0' : '#1e293b', 
                      marginBottom: '8px' 
                    }}>
                      Single Target Scan
                    </div>
                    <div style={{ 
                      fontSize: '14px', 
                      color: darkMode ? '#a0aec0' : '#64748b' 
                    }}>
                      Scan individual IP or domain
                    </div>
                  </div>
                  <div 
                    style={{ 
                      ...styles.card, 
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'transform 0.2s ease, box-shadow 0.2s ease'
                    }}
                    onClick={() => setActiveView('bulk-scan')}
                  >
                    <div style={{ color: '#2563eb', marginBottom: '16px' }}>
                      <Layers className="w-8 h-8" style={{ margin: '0 auto' }} />
                    </div>
                    <div style={{ 
                      fontSize: '16px', 
                      fontWeight: 600, 
                      color: darkMode ? '#e2e8f0' : '#1e293b', 
                      marginBottom: '8px' 
                    }}>
                      Bulk Assessment
                    </div>
                    <div style={{ 
                      fontSize: '14px', 
                      color: darkMode ? '#a0aec0' : '#64748b' 
                    }}>
                      Scan multiple targets
                    </div>
                  </div>
                  <div 
                    style={{ 
                      ...styles.card, 
                      cursor: 'pointer',
                      textAlign: 'center',
                      transition: 'transform 0.2s ease, box-shadow 0.2s ease'
                    }}
                    onClick={() => setActiveView('results')}
                  >
                    <div style={{ color: '#2563eb', marginBottom: '16px' }}>
                      <TrendingUp className="w-8 h-8" style={{ margin: '0 auto' }} />
                    </div>
                    <div style={{ 
                      fontSize: '16px', 
                      fontWeight: 600, 
                      color: darkMode ? '#e2e8f0' : '#1e293b', 
                      marginBottom: '8px' 
                    }}>
                      View Results
                    </div>
                    <div style={{ 
                      fontSize: '14px', 
                      color: darkMode ? '#a0aec0' : '#64748b' 
                    }}>
                      Browse scan results
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeView === 'single-scan' && (
            <div style={{ maxWidth: '800px', margin: '0 auto' }}>
              <div style={{ textAlign: 'center', marginBottom: '32px' }}>
                <h2 style={{ 
                  fontSize: '28px', 
                  fontWeight: 700, 
                  color: darkMode ? '#e2e8f0' : '#1e293b', 
                  marginBottom: '8px' 
                }}>
                  Single Target Security Assessment
                </h2>
                <p style={{ 
                  fontSize: '16px', 
                  color: darkMode ? '#a0aec0' : '#64748b' 
                }}>
                  Comprehensive vulnerability scan for individual targets
                </p>
              </div>

              <div style={styles.card}>
                <div style={{ marginBottom: '24px' }}>
                  <label style={{ 
                    display: 'block', 
                    fontSize: '14px', 
                    fontWeight: 600, 
                    color: darkMode ? '#e2e8f0' : '#1e293b', 
                    marginBottom: '8px' 
                  }}>
                    Target Configuration
                  </label>
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'stretch' }}>
                    <input
                      type="text"
                      value={singleTarget}
                      onChange={(e) => setSingleTarget(e.target.value)}
                      placeholder="Enter IP address or domain (e.g., 192.168.1.100)"
                      style={styles.inputField}
                    />
                    <button
                      onClick={startSingleScan}
                      disabled={loading || !singleTarget.trim()}
                      style={{
                        ...styles.btn,
                        ...styles.btnPrimary,
                        opacity: (loading || !singleTarget.trim()) ? 0.5 : 1
                      }}
                    >
                      {loading ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4" />
                          Start Scan
                        </>
                      )}
                    </button>
                  </div>
                </div>

                <div style={{ marginBottom: '24px' }}>
                  <label style={{ 
                    display: 'block', 
                    fontSize: '14px', 
                    fontWeight: 600, 
                    color: darkMode ? '#e2e8f0' : '#1e293b', 
                    marginBottom: '8px' 
                  }}>
                    Advanced Options
                  </label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <label style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '8px', 
                      cursor: 'pointer' 
                    }}>
                      <input
                        type="checkbox"
                        checked={enableExploits}
                        onChange={(e) => handleExploitToggle(e.target.checked)}
                        style={{ width: '18px', height: '18px', accentColor: '#2563eb' }}
                      />
                      <Lock className="w-4 h-4" />
                      <span style={{ 
                        fontSize: '14px', 
                        color: darkMode ? '#e2e8f0' : '#1e293b' 
                      }}>
                        Enable Exploit Testing (Safe PoC only)
                      </span>
                    </label>
                    {enableExploits && !exploitConfirmed && (
                      <button
                        onClick={confirmExploitMode}
                        style={{
                          ...styles.btn,
                          background: '#f59e0b',
                          color: 'white'
                        }}
                      >
                        <AlertTriangle className="w-4 h-4" />
                        Confirm Exploit Mode
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeView === 'bulk-scan' && (
            <div style={{ maxWidth: '800px', margin: '0 auto' }}>
              <div style={{ textAlign: 'center', marginBottom: '32px' }}>
                <h2 style={{ 
                  fontSize: '28px', 
                  fontWeight: 700, 
                  color: darkMode ? '#e2e8f0' : '#1e293b', 
                  marginBottom: '8px' 
                }}>
                  Bulk Security Assessment
                </h2>
                <p style={{ 
                  fontSize: '16px', 
                  color: darkMode ? '#a0aec0' : '#64748b' 
                }}>
                  Scan multiple targets simultaneously
                </p>
              </div>

              <div style={styles.card}>
                <div style={{ marginBottom: '24px' }}>
                  <label style={{ 
                    display: 'block', 
                    fontSize: '14px', 
                    fontWeight: 600, 
                    color: darkMode ? '#e2e8f0' : '#1e293b', 
                    marginBottom: '8px' 
                  }}>
                    Target List
                  </label>
                  <textarea
                    value={bulkTargets}
                    onChange={(e) => setBulkTargets(e.target.value)}
                    placeholder="Enter targets, one per line:&#10;192.168.1.1&#10;192.168.1.2&#10;example.com"
                    style={styles.textareaField}
                  />
                </div>

                <div style={{ 
                  display: 'flex', 
                  gap: '16px', 
                  alignItems: 'center', 
                  marginBottom: '24px' 
                }}>
                  <button
                    onClick={startBulkScan}
                    disabled={loading || !bulkTargets.trim()}
                    style={{
                      ...styles.btn,
                      ...styles.btnPrimary,
                      opacity: (loading || !bulkTargets.trim()) ? 0.5 : 1
                    }}
                  >
                    {loading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Starting Bulk Scan...
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" />
                        Start Bulk Scan
                      </>
                    )}
                  </button>
                  <label style={{ 
                    ...styles.btn, 
                    ...styles.btnSecondary, 
                    cursor: 'pointer' 
                  }}>
                    <Upload className="w-4 h-4" />
                    Upload File
                    <input
                      type="file"
                      accept=".txt,.csv"
                      onChange={handleFileUpload}
                      style={{ display: 'none' }}
                    />
                  </label>
                </div>

                <div style={{ marginBottom: '24px' }}>
                  <label style={{ 
                    display: 'block', 
                    fontSize: '14px', 
                    fontWeight: 600, 
                    color: darkMode ? '#e2e8f0' : '#1e293b', 
                    marginBottom: '8px' 
                  }}>
                    Advanced Options
                  </label>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    <label style={{ 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '8px', 
                      cursor: 'pointer' 
                    }}>
                      <input
                        type="checkbox"
                        checked={enableExploits}
                        onChange={(e) => handleExploitToggle(e.target.checked)}
                        style={{ width: '18px', height: '18px', accentColor: '#2563eb' }}
                      />
                      <Lock className="w-4 h-4" />
                      <span style={{ 
                        fontSize: '14px', 
                        color: darkMode ? '#e2e8f0' : '#1e293b' 
                      }}>
                        Enable Exploit Testing (Safe PoC only)
                      </span>
                    </label>
                    {enableExploits && !exploitConfirmed && (
                      <button
                        onClick={confirmExploitMode}
                        style={{
                          ...styles.btn,
                          background: '#f59e0b',
                          color: 'white'
                        }}
                      >
                        <AlertTriangle className="w-4 h-4" />
                        Confirm Exploit Mode
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeView === 'monitoring' && (
            <div style={{ maxWidth: '1000px', margin: '0 auto' }}>
              <div style={{ 
                textAlign: 'center', 
                marginBottom: '32px', 
                display: 'flex', 
                flexDirection: 'column', 
                alignItems: 'center', 
                gap: '16px' 
              }}>
                <h2 style={{ 
                  fontSize: '28px', 
                  fontWeight: 700, 
                  color: darkMode ? '#e2e8f0' : '#1e293b', 
                  marginBottom: '8px' 
                }}>
                  Live Scan Monitor
                </h2>
                <p style={{ 
                  fontSize: '16px', 
                  color: darkMode ? '#a0aec0' : '#64748b' 
                }}>
                  Real-time monitoring with progress tracking
                </p>
                <button
                  onClick={toggleDebugInfo}
                  style={{
                    ...styles.btn,
                    ...styles.btnOutline
                  }}
                >
                  <Bug className="w-4 h-4" />
                  {showDebugInfo ? 'Hide' : 'Show'} Debug Info
                </button>
              </div>

              {showDebugInfo && (
                <div style={styles.debugPanel}>
                  <div style={styles.debugHeader}>
                    <h3 style={{ 
                      margin: 0, 
                      fontSize: '16px', 
                      color: darkMode ? '#e2e8f0' : '#1e293b', 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '8px' 
                    }}>
                      <Bug className="w-4 h-4" />
                      Python Scanner Debug Logs
                    </h3>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        onClick={() => setBackendLogs([])}
                        style={{
                          ...styles.btn,
                          ...styles.btnSecondary,
                          padding: '6px 12px',
                          fontSize: '12px'
                        }}
                      >
                        <X className="w-4 h-4" />
                        Clear Logs
                      </button>
                    </div>
                  </div>
                  
                  <div style={styles.debugContent}>
                    <div style={{ 
                      padding: '16px 20px', 
                      borderBottom: `1px solid ${darkMode ? '#4a5568' : '#e2e8f0'}` 
                    }}>
                      <h4 style={{ 
                        margin: '0 0 12px 0', 
                        color: darkMode ? '#e2e8f0' : '#1e293b', 
                        fontSize: '14px', 
                        fontWeight: 600 
                      }}>
                        optimized_scan.py Logs ({backendLogs.length})
                      </h4>
                      <div style={styles.debugLogs}>
                        {backendLogs.length === 0 ? (
                          <p style={{ 
                            color: '#888', 
                            fontStyle: 'italic', 
                            textAlign: 'center', 
                            padding: '20px' 
                          }}>
                            No Python scanner logs available
                          </p>
                        ) : (
                          backendLogs.map((log, index) => (
                            <div key={index} style={{ 
                              marginBottom: '2px', 
                              color: '#ff9500', 
                              wordWrap: 'break-word', 
                              overflowWrap: 'break-word' 
                            }}>
                              <span>{log}</span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {singleJob && (
                <div style={styles.card}>
                  <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center', 
                    marginBottom: '20px' 
                  }}>
                    <h3 style={{ 
                      color: darkMode ? '#e2e8f0' : '#1e293b', 
                      fontSize: '18px', 
                      margin: 0, 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '8px' 
                    }}>
                      <Target className="w-5 h-5" />
                      Single Target Scan
                    </h3>
                    <div style={{
                      padding: '6px 12px',
                      borderRadius: '12px',
                      fontSize: '12px',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.5px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      background: singleJob.status === 'running' ? '#dbeafe' : 
                                 singleJob.status === 'finished' ? '#d1fae5' : 
                                 singleJob.status === 'failed' ? '#fee2e2' : '#fef3c7',
                      color: singleJob.status === 'running' ? '#1e40af' : 
                             singleJob.status === 'finished' ? '#065f46' : 
                             singleJob.status === 'failed' ? '#991b1b' : '#92400e'
                    }}>
                      {singleJob.status.toUpperCase()}
                    </div>
                  </div>
                  
                  <div style={{ marginBottom: '20px' }}>
                    <ProgressBar
                      progress={singleScanProgress}
                      status={singleJob.status}
                      label={scanPhase}
                      showPercentage={true}
                      animated={true}
                      height="12px"
                      darkMode={darkMode}
                    />
                  </div>
                  
                  <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center', 
                    gap: '20px' 
                  }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px', 
                        marginBottom: '8px' 
                      }}>
                        <Server className="w-4 h-4" />
                        <span style={{ 
                          fontWeight: 500, 
                          color: darkMode ? '#a0aec0' : '#64748b', 
                          minWidth: '80px' 
                        }}>
                          Target:
                        </span>
                        <span style={{ 
                          color: darkMode ? '#e2e8f0' : '#1e293b', 
                          fontFamily: 'monospace', 
                          fontSize: '13px',
                          wordBreak: 'break-all'
                        }}>
                          {singleJob.target}
                        </span>
                      </div>
                      
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px', 
                        marginBottom: '8px' 
                      }}>
                        <Activity className="w-4 h-4" />
                        <span style={{ 
                          fontWeight: 500, 
                          color: darkMode ? '#a0aec0' : '#64748b', 
                          minWidth: '80px' 
                        }}>
                          Progress:
                        </span>
                        <span style={{ 
                          color: darkMode ? '#e2e8f0' : '#1e293b', 
                          fontFamily: 'monospace', 
                          fontSize: '13px' 
                        }}>
                          {Math.round(singleScanProgress)}% - {scanPhase}
                        </span>
                      </div>
                      
                      {singleJob.exploit_mode && (
                        <div style={{ 
                          display: 'flex', 
                          alignItems: 'center', 
                          gap: '8px' 
                        }}>
                          <Lock className="w-4 h-4" />
                          <span style={{ 
                            fontWeight: 500, 
                            color: darkMode ? '#a0aec0' : '#64748b', 
                            minWidth: '80px' 
                          }}>
                            Mode:
                          </span>
                          <span style={{ 
                            color: '#ef4444', 
                            fontWeight: 600, 
                            display: 'flex', 
                            alignItems: 'center', 
                            gap: '4px' 
                          }}>
                            Exploit Testing Enabled
                          </span>
                        </div>
                      )}
                    </div>
                    
                    {singleJob.status === 'running' && (
                      <button
                        onClick={cancelScan}
                        style={{
                          ...styles.btn,
                          background: '#ef4444',
                          color: 'white'
                        }}
                      >
                        <Pause className="w-4 h-4" />
                        Cancel Scan
                      </button>
                    )}
                  </div>
                </div>
              )}

              {bulkJob && (
                <div style={styles.card}>
                  <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center', 
                    marginBottom: '20px' 
                  }}>
                    <h3 style={{ 
                      color: darkMode ? '#e2e8f0' : '#1e293b', 
                      fontSize: '18px', 
                      margin: 0, 
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '8px' 
                    }}>
                      <Layers className="w-5 h-5" />
                      Bulk Assessment
                    </h3>
                    <div style={{
                      padding: '6px 12px',
                      borderRadius: '12px',
                      fontSize: '12px',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '0.5px',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      background: bulkJob.status === 'running' ? '#dbeafe' : 
                                 bulkJob.status === 'finished' ? '#d1fae5' : 
                                 bulkJob.status === 'failed' ? '#fee2e2' : '#fef3c7',
                      color: bulkJob.status === 'running' ? '#1e40af' : 
                             bulkJob.status === 'finished' ? '#065f46' : 
                             bulkJob.status === 'failed' ? '#991b1b' : '#92400e'
                    }}>
                      {bulkJob.status.toUpperCase()}
                    </div>
                  </div>
                  <div style={{ marginBottom: '20px' }}>
                    <ProgressBar
                      progress={bulkScanProgress}
                      status={bulkJob.status}
                      label={scanPhase}
                      showPercentage={true}
                      animated={true}
                      height="12px"
                      darkMode={darkMode}
                    />
                  </div>
                  
                  <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center', 
                    gap: '20px' 
                  }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px', 
                        marginBottom: '8px' 
                      }}>
                        <Target className="w-4 h-4" />
                        <span style={{ 
                          fontWeight: 500, 
                          color: darkMode ? '#a0aec0' : '#64748b', 
                          minWidth: '80px' 
                        }}>
                          Targets:
                        </span>
                        <span style={{ 
                          color: darkMode ? '#e2e8f0' : '#1e293b', 
                          fontFamily: 'monospace', 
                          fontSize: '13px' 
                        }}>
                          {bulkJob.total_targets}
                        </span>
                      </div>
                      
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px', 
                        marginBottom: '8px' 
                      }}>
                        <CheckCircle className="w-4 h-4" />
                        <span style={{ 
                          fontWeight: 500, 
                          color: darkMode ? '#a0aec0' : '#64748b', 
                          minWidth: '80px' 
                        }}>
                          Completed:
                        </span>
                        <span style={{ 
                          color: darkMode ? '#e2e8f0' : '#1e293b', 
                          fontFamily: 'monospace', 
                          fontSize: '13px' 
                        }}>
                          {bulkJob.completed || 0} of {bulkJob.total_targets}
                        </span>
                      </div>
                      
                      <div style={{ 
                        display: 'flex', 
                        alignItems: 'center', 
                        gap: '8px' 
                      }}>
                        <TrendingUp className="w-4 h-4" />
                        <span style={{ 
                          fontWeight: 500, 
                          color: darkMode ? '#a0aec0' : '#64748b', 
                          minWidth: '80px' 
                        }}>
                          Progress:
                        </span>
                        <span style={{ 
                          color: darkMode ? '#e2e8f0' : '#1e293b', 
                          fontFamily: 'monospace', 
                          fontSize: '13px' 
                        }}>
                          {Math.round(bulkScanProgress)}% - {scanPhase}
                        </span>
                      </div>
                    </div>
                    
                    {bulkJob.status === 'running' && (
                      <button
                        onClick={cancelBulkScan}
                        style={{
                          ...styles.btn,
                          background: '#ef4444',
                          color: 'white'
                        }}
                      >
                        <Pause className="w-4 h-4" />
                        Cancel Bulk Scan
                      </button>
                    )}
                  </div>
                </div>
              )}

              {!singleJob && !bulkJob && (
                <div style={{ 
                  textAlign: 'center', 
                  padding: '60px 20px', 
                  background: darkMode ? '#2d3748' : '#ffffff', 
                  borderRadius: '12px', 
                  boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)', 
                  border: `1px solid ${darkMode ? '#4a5568' : '#e2e8f0'}` 
                }}>
                  <div style={{ 
                    color: darkMode ? '#718096' : '#8b949e', 
                    marginBottom: '16px' 
                  }}>
                    <Search className="w-12 h-12" style={{ margin: '0 auto' }} />
                  </div>
                  <h3 style={{ 
                    color: darkMode ? '#e2e8f0' : '#1e293b', 
                    fontSize: '20px', 
                    marginBottom: '8px' 
                  }}>
                    No Active Scans
                  </h3>
                  <p style={{ 
                    color: darkMode ? '#a0aec0' : '#64748b', 
                    marginBottom: '24px' 
                  }}>
                    Start a scan to monitor it in real-time
                  </p>
                  <div style={{ display: 'flex', gap: '16px', justifyContent: 'center' }}>
                    <button
                      onClick={() => setActiveView('single-scan')}
                      style={{
                        ...styles.btn,
                        ...styles.btnPrimary
                      }}
                    >
                      <Target className="w-4 h-4" />
                      Start Single Scan
                    </button>
                    <button
                      onClick={() => setActiveView('bulk-scan')}
                      style={{
                        ...styles.btn,
                        ...styles.btnSecondary
                      }}
                    >
                      <Layers className="w-4 h-4" />
                      Start Bulk Scan
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeView === 'results' && (
            <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
              <div style={{ 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'center', 
                marginBottom: '24px' 
              }}>
                <h2 style={{ 
                  color: darkMode ? '#e2e8f0' : '#1e293b', 
                  fontSize: '24px', 
                  margin: 0 
                }}>
                  Scan Results ({results.length})
                </h2>
                <div style={{ display: 'flex', gap: '12px' }}>
                  {results.length > 0 && (
                    <>
                      <button
                        onClick={() => generateBulkTechnicalReport(results)}
                        style={{
                          ...styles.btn,
                          ...styles.btnOutline
                        }}
                      >
                        <FileText className="w-4 h-4" />
                        Bulk Technical Report
                      </button>
                      <button
                        onClick={() => generateBulkExecutiveReport(results)}
                        style={{
                          ...styles.btn,
                          ...styles.btnOutline
                        }}
                      >
                        <BookOpen className="w-4 h-4" />
                        Bulk Executive Report
                      </button>
                    </>
                  )}
                </div>
              </div>

              {results.length === 0 ? (
                <div style={{ 
                  textAlign: 'center', 
                  padding: '60px 20px', 
                  background: darkMode ? '#2d3748' : '#ffffff', 
                  borderRadius: '12px', 
                  boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)', 
                  border: `1px solid ${darkMode ? '#4a5568' : '#e2e8f0'}` 
                }}>
                  <div style={{ 
                    color: darkMode ? '#718096' : '#8b949e', 
                    marginBottom: '16px' 
                  }}>
                    <BarChart3 className="w-12 h-12" style={{ margin: '0 auto' }} />
                  </div>
                  <h3 style={{ 
                    color: darkMode ? '#e2e8f0' : '#1e293b', 
                    fontSize: '20px', 
                    marginBottom: '8px' 
                  }}>
                    No Scan Results
                  </h3>
                  <p style={{ 
                    color: darkMode ? '#a0aec0' : '#64748b', 
                    marginBottom: '24px' 
                  }}>
                    Run a security assessment to see results here
                  </p>
                  <div style={{ display: 'flex', gap: '16px', justifyContent: 'center' }}>
                    <button
                      onClick={() => setActiveView('single-scan')}
                      style={{
                        ...styles.btn,
                        ...styles.btnPrimary
                      }}
                    >
                      <Target className="w-4 h-4" />
                      Start Single Scan
                    </button>
                    <button
                      onClick={() => setActiveView('bulk-scan')}
                      style={{
                        ...styles.btn,
                        ...styles.btnSecondary
                      }}
                    >
                      <Layers className="w-4 h-4" />
                      Start Bulk Scan
                    </button>
                  </div>
                </div>
              ) : (
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))',
                  gap: '24px',
                  overflow: 'hidden'
                }}>
                  {results.map((result, index) => (
                    <div key={index} style={{
                      ...styles.card,
                      transition: 'transform 0.2s ease, box-shadow 0.2s ease'
                    }}>
                      <div style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        marginBottom: '16px'
                      }}>
                        <div style={{
                          fontSize: '16px',
                          fontWeight: 600,
                          color: darkMode ? '#e2e8f0' : '#1e293b',
                          fontFamily: 'monospace',
                          wordBreak: 'break-all',
                          overflowWrap: 'break-word',
                          maxWidth: '60%'
                        }}>
                          {result.target}
                        </div>
                        <div style={{
                          padding: '4px 8px',
                          borderRadius: '8px',
                          fontSize: '10px',
                          fontWeight: 600,
                          textTransform: 'uppercase',
                          letterSpacing: '0.5px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          background: result.risk === 'Critical' ? '#ef4444' :
                                     result.risk === 'High' ? '#f59e0b' :
                                     result.risk === 'Medium' ? '#f97316' :
                                     result.risk === 'Low' ? '#10b981' : '#3b82f6',
                          color: 'white'
                        }}>
                          {getRiskIcon(result.risk)}
                          {result.risk}
                        </div>
                      </div>
                      
                      <ConfidenceMeter result={result} />
                      
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(2, 1fr)',
                        gap: '16px',
                        marginBottom: '16px'
                      }}>
                        <div style={{
                          textAlign: 'center',
                          padding: '12px',
                          background: darkMode ? '#4a5568' : '#f8fafc',
                          borderRadius: '8px',
                          border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`
                        }}>
                          <div style={{
                            color: darkMode ? '#718096' : '#8b949e',
                            marginBottom: '4px'
                          }}>
                            <Bug className="w-4 h-4" style={{ margin: '0 auto' }} />
                          </div>
                          <div style={{
                            fontSize: '20px',
                            fontWeight: 700,
                            color: darkMode ? '#e2e8f0' : '#1e293b',
                            marginBottom: '4px'
                          }}>
                            {result.total_vulnerabilities || 0}
                          </div>
                          <div style={{
                            fontSize: '12px',
                            color: darkMode ? '#a0aec0' : '#64748b'
                          }}>
                            Vulnerabilities
                          </div>
                        </div>
                        <div style={{
                          textAlign: 'center',
                          padding: '12px',
                          background: darkMode ? '#4a5568' : '#f8fafc',
                          borderRadius: '8px',
                          border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`
                        }}>
                          <div style={{
                            color: darkMode ? '#718096' : '#8b949e',
                            marginBottom: '4px'
                          }}>
                            <Wifi className="w-4 h-4" style={{ margin: '0 auto' }} />
                          </div>
                          <div style={{
                            fontSize: '20px',
                            fontWeight: 700,
                            color: darkMode ? '#e2e8f0' : '#1e293b',
                            marginBottom: '4px'
                          }}>
                            {result.ports_masscan?.length || 0}
                          </div>
                          <div style={{
                            fontSize: '12px',
                            color: darkMode ? '#a0aec0' : '#64748b'
                          }}>
                            Ports
                          </div>
                        </div>
                      </div>
                      
                      <div style={{
                        display: 'flex',
                        gap: '8px',
                        flexWrap: 'wrap'
                      }}>
                        <button
                          onClick={() => showDetails(result)}
                          style={{
                            ...styles.btn,
                            ...styles.btnOutline,
                            padding: '8px 16px',
                            fontSize: '12px'
                          }}
                        >
                          <Eye className="w-4 h-4" />
                          Details
                        </button>
                        <button
                          onClick={() => generateTechnicalReport(result)}
                          style={{
                            ...styles.btn,
                            ...styles.btnSecondary,
                            padding: '8px 16px',
                            fontSize: '12px'
                          }}
                        >
                          <FileText className="w-4 h-4" />
                          Technical
                        </button>
                        <button
                          onClick={() => generateExecutiveReport(result)}
                          style={{
                            ...styles.btn,
                            ...styles.btnPrimary,
                            padding: '8px 16px',
                            fontSize: '12px'
                          }}
                        >
                          <BookOpen className="w-4 h-4" />
                          Executive
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeView === 'details' && selectedResult && (
            <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '24px',
                flexWrap: 'wrap',
                gap: '16px'
              }}>
                <button
                  onClick={() => setActiveView('results')}
                  style={{
                    ...styles.btn,
                    background: 'transparent',
                    color: darkMode ? '#a0aec0' : '#64748b',
                    padding: '8px 16px'
                  }}
                >
                  ← Back to Results
                </button>
                <h2 style={{
                  color: darkMode ? '#e2e8f0' : '#1e293b',
                  fontSize: '24px',
                  margin: 0,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <Server className="w-5 h-5" />
                  Scan Details: {selectedResult.target}
                </h2>
                <div style={{
                  padding: '8px 16px',
                  borderRadius: '12px',
                  fontSize: '14px',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  background: selectedResult.risk === 'Critical' ? '#ef4444' :
                             selectedResult.risk === 'High' ? '#f59e0b' :
                             selectedResult.risk === 'Medium' ? '#f97316' :
                             selectedResult.risk === 'Low' ? '#10b981' : '#3b82f6',
                  color: 'white'
                }}>
                  {getRiskIcon(selectedResult.risk)}
                  {selectedResult.risk} Risk
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <div style={{ width: '100%' }}>
                  <div style={styles.card}>
                    <h3 style={{
                      color: darkMode ? '#e2e8f0' : '#1e293b',
                      fontSize: '18px',
                      marginBottom: '16px'
                    }}>
                      Assessment Overview
                    </h3>
                    <ConfidenceMeter result={selectedResult} />
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: '16px',
                      marginBottom: '16px'
                    }}>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '12px',
                        background: darkMode ? '#4a5568' : '#f8fafc',
                        borderRadius: '8px',
                        border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`
                      }}>
                        <Bug className="w-4 h-4" />
                        <span style={{
                          fontSize: '14px',
                          color: darkMode ? '#a0aec0' : '#64748b',
                          fontWeight: 500
                        }}>
                          Total Vulnerabilities
                        </span>
                        <span style={{
                          fontSize: '18px',
                          fontWeight: 700,
                          color: darkMode ? '#e2e8f0' : '#1e293b',
                          marginLeft: 'auto'
                        }}>
                          {selectedResult.total_vulnerabilities || 0}
                        </span>
                      </div>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '12px',
                        background: darkMode ? '#4a5568' : '#f8fafc',
                        borderRadius: '8px',
                        border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`
                      }}>
                        <Wifi className="w-4 h-4" />
                        <span style={{
                          fontSize: '14px',
                          color: darkMode ? '#a0aec0' : '#64748b',
                          fontWeight: 500
                        }}>
                          Open Ports
                        </span>
                        <span style={{
                          fontSize: '18px',
                          fontWeight: 700,
                          color: darkMode ? '#e2e8f0' : '#1e293b',
                          marginLeft: 'auto'
                        }}>
                          {selectedResult.ports_masscan?.length || 0}
                        </span>
                      </div>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '12px',
                        background: darkMode ? '#4a5568' : '#f8fafc',
                        borderRadius: '8px',
                        border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`
                      }}>
                        <HardDrive className="w-4 h-4" />
                        <span style={{
                          fontSize: '14px',
                          color: darkMode ? '#a0aec0' : '#64748b',
                          fontWeight: 500
                        }}>
                          Services
                        </span>
                        <span style={{
                          fontSize: '18px',
                          fontWeight: 700,
                          color: darkMode ? '#e2e8f0' : '#1e293b',
                          marginLeft: 'auto'
                        }}>
                          {Object.keys(selectedResult.services || {}).length}
                        </span>
                      </div>
                      <div style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '12px',
                        padding: '12px',
                        background: darkMode ? '#4a5568' : '#f8fafc',
                        borderRadius: '8px',
                        border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`
                      }}>
                        <Clock className="w-4 h-4" />
                        <span style={{
                          fontSize: '14px',
                          color: darkMode ? '#a0aec0' : '#64748b',
                          fontWeight: 500
                        }}>
                          Scan Time
                        </span>
                        <span style={{
                          fontSize: '18px',
                          fontWeight: 700,
                          color: darkMode ? '#e2e8f0' : '#1e293b',
                          marginLeft: 'auto'
                        }}>
                          {selectedResult.scan_time || 0}s
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))',
                  gap: '24px'
                }}>
                  {selectedResult.ports_masscan && selectedResult.ports_masscan.length > 0 && (
                    <div style={styles.card}>
                      <h3 style={{
                        color: darkMode ? '#e2e8f0' : '#1e293b',
                        fontSize: '16px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <Wifi className="w-4 h-4" />
                        Open Ports ({selectedResult.ports_masscan.length})
                      </h3>
                      <div style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fill, minmax(80px, 1fr))',
                        gap: '8px',
                        ...styles.scrollableList
                      }}>
                        {selectedResult.ports_masscan.map((port, index) => (
                          <div key={index} style={{
                            background: darkMode ? '#4a5568' : '#f8fafc',
                            border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
                            borderRadius: '6px',
                            padding: '8px',
                            textAlign: 'center',
                            fontSize: '12px',
                            fontWeight: 600,
                            color: darkMode ? '#e2e8f0' : '#1e293b',
                            fontFamily: 'monospace',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: '4px'
                          }}>
                            <Network className="w-3 h-3" />
                            {port}/tcp
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedResult.services && Object.keys(selectedResult.services).length > 0 && (
                    <div style={styles.card}>
                      <h3 style={{
                        color: darkMode ? '#e2e8f0' : '#1e293b',
                        fontSize: '16px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <HardDrive className="w-4 h-4" />
                        Services ({Object.keys(selectedResult.services).length})
                      </h3>
                      <div style={{
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '8px',
                        ...styles.scrollableList
                      }}>
                        {Object.entries(selectedResult.services).map(([port, service]) => (
                          <div key={port} style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '12px',
                            padding: '12px',
                            background: darkMode ? '#4a5568' : '#f8fafc',
                            border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
                            borderRadius: '8px'
                          }}>
                            <div style={{
                              fontSize: '12px',
                              fontWeight: 600,
                              color: '#2563eb',
                              fontFamily: 'monospace',
                              minWidth: '60px',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}>
                              <Network className="w-3 h-3" />
                              {port}/tcp
                            </div>
                            <div style={{
                              fontSize: '14px',
                              fontWeight: 600,
                              color: darkMode ? '#e2e8f0' : '#1e293b',
                              flex: 1,
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}>
                              <Server className="w-3 h-3" />
                              {service.service}
                            </div>
                            <div style={{
                              fontSize: '12px',
                              color: darkMode ? '#a0aec0' : '#64748b',
                              fontFamily: 'monospace',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px'
                            }}>
                              <Info className="w-3 h-3" />
                              {service.version}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedResult.nuclei && selectedResult.nuclei.length > 0 && (
                    <div style={styles.card}>
                      <h3 style={{
                        color: darkMode ? '#e2e8f0' : '#1e293b',
                        fontSize: '16px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <Zap className="w-4 h-4" />
                        Nuclei Findings ({selectedResult.nuclei.length})
                      </h3>
                      <div style={styles.scrollableList}>
                        {selectedResult.nuclei.map((finding, index) => (
                          <div key={index} style={{
                            padding: '12px',
                            background: darkMode ? '#4a5568' : '#f8fafc',
                            border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
                            borderRadius: '8px',
                            fontSize: '12px',
                            color: darkMode ? '#e2e8f0' : '#1e293b',
                            fontFamily: 'monospace',
                            lineHeight: 1.4,
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: '8px',
                            wordWrap: 'break-word',
                            overflowWrap: 'break-word',
                            marginBottom: '8px'
                          }}>
                            <Bug className="w-3 h-3" />
                            {finding}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedResult.nikto && selectedResult.nikto.length > 0 && (
                    <div style={styles.card}>
                      <h3 style={{
                        color: darkMode ? '#e2e8f0' : '#1e293b',
                        fontSize: '16px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <Globe className="w-4 h-4" />
                        Nikto Findings ({selectedResult.nikto.length})
                      </h3>
                      <div style={styles.scrollableList}>
                        {selectedResult.nikto.map((finding, index) => (
                          <div key={index} style={{
                            padding: '12px',
                            background: darkMode ? '#4a5568' : '#f8fafc',
                            border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
                            borderRadius: '8px',
                            fontSize: '12px',
                            color: darkMode ? '#e2e8f0' : '#1e293b',
                            fontFamily: 'monospace',
                            lineHeight: 1.4,
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: '8px',
                            wordWrap: 'break-word',
                            overflowWrap: 'break-word',
                            marginBottom: '8px'
                          }}>
                            <Globe className="w-3 h-3" />
                            {finding}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedResult.nmap_vulns && selectedResult.nmap_vulns.length > 0 && (
                    <div style={styles.card}>
                      <h3 style={{
                        color: darkMode ? '#e2e8f0' : '#1e293b',
                        fontSize: '16px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <Shield className="w-4 h-4" />
                        Nmap Vulnerabilities ({selectedResult.nmap_vulns.length})
                      </h3>
                      <div style={styles.scrollableList}>
                        {selectedResult.nmap_vulns.map((finding, index) => (
                          <div key={index} style={{
                            padding: '12px',
                            background: darkMode ? '#4a5568' : '#f8fafc',
                            border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
                            borderRadius: '8px',
                            fontSize: '12px',
                            color: darkMode ? '#e2e8f0' : '#1e293b',
                            fontFamily: 'monospace',
                            lineHeight: 1.4,
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: '8px',
                            wordWrap: 'break-word',
                            overflowWrap: 'break-word',
                            marginBottom: '8px'
                          }}>
                            <Shield className="w-3 h-3" />
                            {finding}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedResult.custom_checks && selectedResult.custom_checks.length > 0 && (
                    <div style={styles.card}>
                      <h3 style={{
                        color: darkMode ? '#e2e8f0' : '#1e293b',
                        fontSize: '16px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <Settings className="w-4 h-4" />
                        Custom Checks ({selectedResult.custom_checks.length})
                      </h3>
                      <div style={styles.scrollableList}>
                        {selectedResult.custom_checks.map((finding, index) => (
                          <div key={index} style={{
                            padding: '12px',
                            background: darkMode ? '#4a5568' : '#f8fafc',
                            border: `1px solid ${darkMode ? '#718096' : '#e2e8f0'}`,
                            borderRadius: '8px',
                            fontSize: '12px',
                            color: darkMode ? '#e2e8f0' : '#1e293b',
                            fontFamily: 'monospace',
                            lineHeight: 1.4,
                            display: 'flex',
                            alignItems: 'flex-start',
                            gap: '8px',
                            wordWrap: 'break-word',
                            overflowWrap: 'break-word',
                            marginBottom: '8px'
                          }}>
                            <Settings className="w-3 h-3" />
                            {finding}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedResult.exploit_results && (
                    <div style={styles.card}>
                      <h3 style={{
                        color: darkMode ? '#e2e8f0' : '#1e293b',
                        fontSize: '16px',
                        marginBottom: '16px',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px'
                      }}>
                        <Lock className="w-4 h-4" />
                        Exploit Testing Results
                      </h3>
                      <div style={{
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '16px',
                        ...styles.scrollableList
                      }}>
                        {Object.entries(selectedResult.exploit_results).map(([category, findings]) => (
                          findings.length > 0 && (
                            <div key={category} style={{
                              background: '#fef2f2',
                              border: '1px solid #fecaca',
                              borderRadius: '8px',
                              padding: '16px'
                            }}>
                              <h4 style={{
                                color: '#991b1b',
                                fontSize: '14px',
                                marginBottom: '12px',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px'
                              }}>
                                <AlertTriangle className="w-4 h-4" />
                                {category.replace('_', ' ').toUpperCase()}
                              </h4>
                              <div style={{
                                display: 'flex',
                                flexDirection: 'column',
                                gap: '8px'
                              }}>
                                {findings.map((finding, index) => (
                                  <div key={index} style={{
                                    padding: '8px',
                                    background: 'white',
                                    border: '1px solid #fecaca',
                                    borderRadius: '6px',
                                    fontSize: '12px',
                                    color: '#7f1d1d',
                                    fontFamily: 'monospace',
                                    lineHeight: 1.4,
                                    display: 'flex',
                                    alignItems: 'flex-start',
                                    gap: '8px',
                                    wordWrap: 'break-word',
                                    overflowWrap: 'break-word'
                                  }}>
                                    <Lock className="w-3 h-3" />
                                    {finding}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div style={{
                  display: 'flex',
                  gap: '16px',
                  justifyContent: 'center',
                  marginTop: '24px'
                }}>
                  <button
                    onClick={() => generateTechnicalReport(selectedResult)}
                    style={{
                      ...styles.btn,
                      ...styles.btnPrimary
                    }}
                  >
                    <FileText className="w-4 h-4" />
                    Generate Technical Report
                  </button>
                  <button
                    onClick={() => generateExecutiveReport(selectedResult)}
                    style={{
                      ...styles.btn,
                      ...styles.btnSecondary
                    }}
                  >
                    <BookOpen className="w-4 h-4" />
                    Generate Executive Report
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
