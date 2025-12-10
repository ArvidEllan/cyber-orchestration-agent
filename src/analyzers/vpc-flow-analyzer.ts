/**
 * VPC Flow Log Analyzer
 * Analyzes VPC Flow Logs for network security threats
 */

import {
  S3Client,
  GetObjectCommand,
  ListObjectsV2Command,
} from '@aws-sdk/client-s3';
import {
  CloudWatchLogsClient,
  FilterLogEventsCommand,
} from '@aws-sdk/client-cloudwatch-logs';
import {
  SecurityEvent,
  LogSource,
  LogType,
  ThreatFinding,
  Severity,
  Category,
  FindingStatus,
  ResourceSource,
} from '../types';

export interface VPCFlowLogRecord {
  version: number;
  accountId: string;
  interfaceId: string;
  srcAddr: string;
  dstAddr: string;
  srcPort: number;
  dstPort: number;
  protocol: number;
  packets: number;
  bytes: number;
  start: number;
  end: number;
  action: 'ACCEPT' | 'REJECT';
  logStatus: string;
}

export class VPCFlowLogAnalyzer {
  private s3Client: S3Client;
  private cloudWatchClient: CloudWatchLogsClient;

  constructor(region: string = 'us-east-1') {
    this.s3Client = new S3Client({ region });
    this.cloudWatchClient = new CloudWatchLogsClient({ region });
  }

  /**
   * Analyze VPC Flow Logs from a log source
   */
  async analyzeLogs(logSource: LogSource): Promise<ThreatFinding[]> {
    if (logSource.type !== LogType.VPC_FLOW) {
      throw new Error('Invalid log source type for VPC Flow Log analyzer');
    }

    const records = await this.fetchLogs(logSource);
    const securityEvents = records.map((r) => this.normalizeRecord(r));
    return this.detectThreats(securityEvents);
  }

  /**
   * Fetch VPC Flow Logs from S3 or CloudWatch Logs
   */
  private async fetchLogs(logSource: LogSource): Promise<VPCFlowLogRecord[]> {
    if (logSource.location.startsWith('s3://')) {
      return this.fetchFromS3(logSource);
    } else if (logSource.location.startsWith('cloudwatch://')) {
      return this.fetchFromCloudWatch(logSource);
    } else {
      throw new Error('Unsupported log location format');
    }
  }

  /**
   * Fetch logs from S3
   */
  private async fetchFromS3(
    logSource: LogSource
  ): Promise<VPCFlowLogRecord[]> {
    const url = new URL(logSource.location);
    const bucket = url.hostname;
    const prefix = url.pathname.slice(1);

    const records: VPCFlowLogRecord[] = [];

    try {
      const listCommand = new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
      });

      const listResponse = await this.s3Client.send(listCommand);

      if (!listResponse.Contents) {
        return records;
      }

      for (const object of listResponse.Contents) {
        if (!object.Key) continue;

        const getCommand = new GetObjectCommand({
          Bucket: bucket,
          Key: object.Key,
        });

        const response = await this.s3Client.send(getCommand);
        const body = await response.Body?.transformToString();

        if (body) {
          const lines = body.split('\n');
          for (const line of lines) {
            if (line.trim() && !line.startsWith('version')) {
              const record = this.parseFlowLogLine(line);
              if (record) {
                records.push(record);
              }
            }
          }
        }
      }
    } catch (error) {
      console.error('Error fetching VPC Flow Logs from S3:', error);
    }

    return this.filterByTimeRange(records, logSource.timeRange);
  }

  /**
   * Fetch logs from CloudWatch Logs
   */
  private async fetchFromCloudWatch(
    logSource: LogSource
  ): Promise<VPCFlowLogRecord[]> {
    const logGroupName = logSource.location.replace('cloudwatch://', '');
    const records: VPCFlowLogRecord[] = [];

    try {
      const command = new FilterLogEventsCommand({
        logGroupName,
        startTime: logSource.timeRange.start.getTime(),
        endTime: logSource.timeRange.end.getTime(),
      });

      const response = await this.cloudWatchClient.send(command);

      if (response.events) {
        for (const event of response.events) {
          if (event.message) {
            const record = this.parseFlowLogLine(event.message);
            if (record) {
              records.push(record);
            }
          }
        }
      }
    } catch (error) {
      console.error('Error fetching VPC Flow Logs from CloudWatch:', error);
    }

    return records;
  }

  /**
   * Parse a VPC Flow Log line
   */
  private parseFlowLogLine(line: string): VPCFlowLogRecord | null {
    const parts = line.trim().split(/\s+/);

    if (parts.length < 14) {
      return null;
    }

    try {
      return {
        version: parseInt(parts[0]),
        accountId: parts[1],
        interfaceId: parts[2],
        srcAddr: parts[3],
        dstAddr: parts[4],
        srcPort: parseInt(parts[5]),
        dstPort: parseInt(parts[6]),
        protocol: parseInt(parts[7]),
        packets: parseInt(parts[8]),
        bytes: parseInt(parts[9]),
        start: parseInt(parts[10]),
        end: parseInt(parts[11]),
        action: parts[12] as 'ACCEPT' | 'REJECT',
        logStatus: parts[13],
      };
    } catch {
      return null;
    }
  }

  /**
   * Filter records by time range
   */
  private filterByTimeRange(
    records: VPCFlowLogRecord[],
    timeRange: { start: Date; end: Date }
  ): VPCFlowLogRecord[] {
    const startTime = timeRange.start.getTime() / 1000;
    const endTime = timeRange.end.getTime() / 1000;

    return records.filter(
      (record) => record.start >= startTime && record.end <= endTime
    );
  }

  /**
   * Normalize VPC Flow Log record to SecurityEvent
   */
  normalizeRecord(record: VPCFlowLogRecord): SecurityEvent {
    return {
      id: `${record.interfaceId}-${record.start}-${record.srcAddr}`,
      timestamp: new Date(record.start * 1000),
      eventType: 'NetworkTraffic',
      source: record.srcAddr,
      principal: record.accountId,
      resource: record.interfaceId,
      action: record.action,
      result: record.action === 'ACCEPT' ? 'success' : 'failure',
      details: {
        srcAddr: record.srcAddr,
        dstAddr: record.dstAddr,
        srcPort: record.srcPort,
        dstPort: record.dstPort,
        protocol: record.protocol,
        packets: record.packets,
        bytes: record.bytes,
        interfaceId: record.interfaceId,
      },
    };
  }

  /**
   * Detect network threats in flow logs
   */
  private detectThreats(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Detect port scanning
    findings.push(...this.detectPortScanning(events));

    // Detect DDoS patterns
    findings.push(...this.detectDDoS(events));

    // Detect data exfiltration
    findings.push(...this.detectDataExfiltration(events));

    // Detect suspicious connections
    findings.push(...this.detectSuspiciousConnections(events));

    return findings;
  }

  /**
   * Detect port scanning activity
   */
  private detectPortScanning(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Group by source IP
    const bySourceIP = new Map<string, SecurityEvent[]>();
    for (const event of events) {
      const srcIP = event.details.srcAddr;
      if (!bySourceIP.has(srcIP)) {
        bySourceIP.set(srcIP, []);
      }
      bySourceIP.get(srcIP)!.push(event);
    }

    // Check for port scanning patterns (many different destination ports)
    for (const [srcIP, ipEvents] of bySourceIP.entries()) {
      const uniquePorts = new Set(ipEvents.map((e) => e.details.dstPort));

      if (uniquePorts.size >= 20 && ipEvents.length >= 50) {
        findings.push({
          id: `vpc-port-scan-${srcIP}-${Date.now()}`,
          ruleId: 'VPC-001',
          resource: {
            id: `source-${srcIP}`,
            type: 'Network::SourceIP',
            service: 'vpc',
            region: 'unknown',
            account: ipEvents[0].principal,
            properties: { sourceIP: srcIP },
            tags: {},
            relationships: [],
            source: ResourceSource.LIVE,
            timestamp: new Date(),
          },
          severity: Severity.HIGH,
          category: Category.NETWORK,
          title: 'Port Scanning Detected',
          description: `Source IP ${srcIP} attempted to connect to ${uniquePorts.size} different ports`,
          evidence: {
            description: 'VPC Flow Logs show port scanning pattern',
            details: {
              sourceIP: srcIP,
              uniquePorts: uniquePorts.size,
              totalAttempts: ipEvents.length,
              rejectedConnections: ipEvents.filter((e) => e.result === 'failure')
                .length,
            },
          },
          remediation: {
            description: 'Block suspicious IP and investigate',
            steps: [
              'Add source IP to network ACL deny list',
              'Review security group rules',
              'Check if any connections were successful',
              'Enable VPC Flow Logs if not already enabled',
              'Consider using AWS Network Firewall',
            ],
          },
          complianceMapping: [],
          riskScore: 75,
          status: FindingStatus.OPEN,
          createdAt: new Date(),
          updatedAt: new Date(),
          correlatedEvents: ipEvents.slice(0, 10),
        });
      }
    }

    return findings;
  }

  /**
   * Detect DDoS patterns
   */
  private detectDDoS(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Group by destination IP and port
    const byDestination = new Map<string, SecurityEvent[]>();
    for (const event of events) {
      const key = `${event.details.dstAddr}:${event.details.dstPort}`;
      if (!byDestination.has(key)) {
        byDestination.set(key, []);
      }
      byDestination.get(key)!.push(event);
    }

    // Check for high volume of connections to same destination
    for (const [destination, destEvents] of byDestination.entries()) {
      const uniqueSources = new Set(destEvents.map((e) => e.details.srcAddr));

      if (uniqueSources.size >= 50 && destEvents.length >= 1000) {
        const [dstAddr, dstPort] = destination.split(':');

        findings.push({
          id: `vpc-ddos-${destination}-${Date.now()}`,
          ruleId: 'VPC-002',
          resource: {
            id: `destination-${dstAddr}`,
            type: 'Network::DestinationIP',
            service: 'vpc',
            region: 'unknown',
            account: destEvents[0].principal,
            properties: { destinationIP: dstAddr, port: dstPort },
            tags: {},
            relationships: [],
            source: ResourceSource.LIVE,
            timestamp: new Date(),
          },
          severity: Severity.CRITICAL,
          category: Category.NETWORK,
          title: 'Potential DDoS Attack Detected',
          description: `Destination ${destination} received ${destEvents.length} connections from ${uniqueSources.size} unique sources`,
          evidence: {
            description: 'VPC Flow Logs show DDoS pattern',
            details: {
              destination,
              uniqueSources: uniqueSources.size,
              totalConnections: destEvents.length,
              timeRange: {
                start: new Date(Math.min(...destEvents.map((e) => e.timestamp.getTime()))),
                end: new Date(Math.max(...destEvents.map((e) => e.timestamp.getTime()))),
              },
            },
          },
          remediation: {
            description: 'Enable DDoS protection and investigate',
            steps: [
              'Enable AWS Shield for DDoS protection',
              'Review and adjust security group rules',
              'Consider using AWS WAF',
              'Scale resources if legitimate traffic',
              'Contact AWS Support if attack is ongoing',
            ],
          },
          complianceMapping: [],
          riskScore: 90,
          status: FindingStatus.OPEN,
          createdAt: new Date(),
          updatedAt: new Date(),
          correlatedEvents: destEvents.slice(0, 10),
        });
      }
    }

    return findings;
  }

  /**
   * Detect data exfiltration via network
   */
  private detectDataExfiltration(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Group by source interface
    const byInterface = new Map<string, SecurityEvent[]>();
    for (const event of events) {
      const interfaceId = event.details.interfaceId;
      if (!byInterface.has(interfaceId)) {
        byInterface.set(interfaceId, []);
      }
      byInterface.get(interfaceId)!.push(event);
    }

    // Check for high volume of outbound data
    for (const [interfaceId, interfaceEvents] of byInterface.entries()) {
      const totalBytes = interfaceEvents.reduce(
        (sum, e) => sum + (e.details.bytes || 0),
        0
      );

      // Flag if more than 10GB transferred
      if (totalBytes > 10 * 1024 * 1024 * 1024) {
        findings.push({
          id: `vpc-exfiltration-${interfaceId}-${Date.now()}`,
          ruleId: 'VPC-003',
          resource: {
            id: interfaceId,
            type: 'EC2::NetworkInterface',
            service: 'ec2',
            region: 'unknown',
            account: interfaceEvents[0].principal,
            properties: { interfaceId },
            tags: {},
            relationships: [],
            source: ResourceSource.LIVE,
            timestamp: new Date(),
          },
          severity: Severity.HIGH,
          category: Category.NETWORK,
          title: 'High Volume Data Transfer Detected',
          description: `Network interface ${interfaceId} transferred ${(totalBytes / (1024 * 1024 * 1024)).toFixed(2)} GB`,
          evidence: {
            description: 'VPC Flow Logs show high volume data transfer',
            details: {
              interfaceId,
              totalBytes,
              totalGB: (totalBytes / (1024 * 1024 * 1024)).toFixed(2),
              connectionCount: interfaceEvents.length,
            },
          },
          remediation: {
            description: 'Investigate unusual data transfer',
            steps: [
              'Identify the EC2 instance using this network interface',
              'Review application logs for the instance',
              'Verify if data transfer is legitimate',
              'Check destination IPs for suspicious locations',
              'Enable VPC Flow Logs analysis alerts',
            ],
          },
          complianceMapping: [],
          riskScore: 70,
          status: FindingStatus.OPEN,
          createdAt: new Date(),
          updatedAt: new Date(),
          correlatedEvents: interfaceEvents.slice(0, 10),
        });
      }
    }

    return findings;
  }

  /**
   * Detect suspicious connections
   */
  private detectSuspiciousConnections(
    events: SecurityEvent[]
  ): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Known suspicious ports
    const suspiciousPorts = [
      22, // SSH
      3389, // RDP
      23, // Telnet
      445, // SMB
      1433, // SQL Server
      3306, // MySQL
      5432, // PostgreSQL
      6379, // Redis
      27017, // MongoDB
    ];

    // Check for connections to suspicious ports from external IPs
    const suspiciousConnections = events.filter((e) => {
      const srcAddr = e.details.srcAddr;
      const dstPort = e.details.dstPort;

      // Check if source is external (not private IP)
      const isExternal = !this.isPrivateIP(srcAddr);

      return isExternal && suspiciousPorts.includes(dstPort) && e.result === 'success';
    });

    if (suspiciousConnections.length > 0) {
      // Group by destination port
      const byPort = new Map<number, SecurityEvent[]>();
      for (const event of suspiciousConnections) {
        const port = event.details.dstPort;
        if (!byPort.has(port)) {
          byPort.set(port, []);
        }
        byPort.get(port)!.push(event);
      }

      for (const [port, portEvents] of byPort.entries()) {
        findings.push({
          id: `vpc-suspicious-${port}-${Date.now()}`,
          ruleId: 'VPC-004',
          resource: {
            id: `port-${port}`,
            type: 'Network::Port',
            service: 'vpc',
            region: 'unknown',
            account: portEvents[0].principal,
            properties: { port },
            tags: {},
            relationships: [],
            source: ResourceSource.LIVE,
            timestamp: new Date(),
          },
          severity: Severity.MEDIUM,
          category: Category.NETWORK,
          title: 'Suspicious External Connection Detected',
          description: `${portEvents.length} external connection(s) to sensitive port ${port}`,
          evidence: {
            description: 'VPC Flow Logs show external connections to sensitive ports',
            details: {
              port,
              connectionCount: portEvents.length,
              uniqueSources: new Set(portEvents.map((e) => e.details.srcAddr)).size,
              sampleSources: Array.from(
                new Set(portEvents.map((e) => e.details.srcAddr))
              ).slice(0, 5),
            },
          },
          remediation: {
            description: 'Restrict access to sensitive ports',
            steps: [
              'Review security group rules for this port',
              'Restrict access to known IP ranges only',
              'Consider using VPN or bastion host',
              'Enable connection logging',
              'Implement network segmentation',
            ],
          },
          complianceMapping: [],
          riskScore: 60,
          status: FindingStatus.OPEN,
          createdAt: new Date(),
          updatedAt: new Date(),
          correlatedEvents: portEvents.slice(0, 5),
        });
      }
    }

    return findings;
  }

  /**
   * Check if IP is private
   */
  private isPrivateIP(ip: string): boolean {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4) return false;

    // 10.0.0.0/8
    if (parts[0] === 10) return true;

    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;

    return false;
  }
}
