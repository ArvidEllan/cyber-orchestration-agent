/**
 * CloudTrail Log Analyzer
 * Parses and analyzes AWS CloudTrail logs for security events
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
  Finding,
  Severity,
  Category,
  FindingStatus,
  ResourceSource,
} from '../types';

export interface CloudTrailEvent {
  eventVersion: string;
  userIdentity: any;
  eventTime: string;
  eventSource: string;
  eventName: string;
  awsRegion: string;
  sourceIPAddress: string;
  userAgent: string;
  requestParameters?: any;
  responseElements?: any;
  errorCode?: string;
  errorMessage?: string;
  resources?: any[];
}

export class CloudTrailAnalyzer {
  private s3Client: S3Client;
  private cloudWatchClient: CloudWatchLogsClient;

  constructor(region: string = 'us-east-1') {
    this.s3Client = new S3Client({ region });
    this.cloudWatchClient = new CloudWatchLogsClient({ region });
  }

  /**
   * Analyze CloudTrail logs from a log source
   */
  async analyzeLogs(logSource: LogSource): Promise<ThreatFinding[]> {
    if (logSource.type !== LogType.CLOUDTRAIL) {
      throw new Error('Invalid log source type for CloudTrail analyzer');
    }

    const events = await this.fetchLogs(logSource);
    const securityEvents = events.map((e) => this.normalizeEvent(e));
    return this.detectAnomalies(securityEvents);
  }

  /**
   * Fetch CloudTrail logs from S3 or CloudWatch Logs
   */
  private async fetchLogs(logSource: LogSource): Promise<CloudTrailEvent[]> {
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
  private async fetchFromS3(logSource: LogSource): Promise<CloudTrailEvent[]> {
    const url = new URL(logSource.location);
    const bucket = url.hostname;
    const prefix = url.pathname.slice(1);

    const events: CloudTrailEvent[] = [];

    try {
      // List objects in the S3 bucket
      const listCommand = new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
      });

      const listResponse = await this.s3Client.send(listCommand);

      if (!listResponse.Contents) {
        return events;
      }

      // Fetch and parse each log file
      for (const object of listResponse.Contents) {
        if (!object.Key) continue;

        const getCommand = new GetObjectCommand({
          Bucket: bucket,
          Key: object.Key,
        });

        const response = await this.s3Client.send(getCommand);
        const body = await response.Body?.transformToString();

        if (body) {
          const logData = JSON.parse(body);
          if (logData.Records) {
            events.push(...logData.Records);
          }
        }
      }
    } catch (error) {
      console.error('Error fetching CloudTrail logs from S3:', error);
    }

    return this.filterByTimeRange(events, logSource.timeRange);
  }

  /**
   * Fetch logs from CloudWatch Logs
   */
  private async fetchFromCloudWatch(
    logSource: LogSource
  ): Promise<CloudTrailEvent[]> {
    const logGroupName = logSource.location.replace('cloudwatch://', '');
    const events: CloudTrailEvent[] = [];

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
            try {
              const parsed = JSON.parse(event.message);
              events.push(parsed);
            } catch {
              // Skip malformed events
            }
          }
        }
      }
    } catch (error) {
      console.error('Error fetching CloudTrail logs from CloudWatch:', error);
    }

    return events;
  }

  /**
   * Filter events by time range
   */
  private filterByTimeRange(
    events: CloudTrailEvent[],
    timeRange: { start: Date; end: Date }
  ): CloudTrailEvent[] {
    return events.filter((event) => {
      const eventTime = new Date(event.eventTime);
      return eventTime >= timeRange.start && eventTime <= timeRange.end;
    });
  }

  /**
   * Normalize CloudTrail event to SecurityEvent
   */
  normalizeEvent(event: CloudTrailEvent): SecurityEvent {
    return {
      id: `${event.eventTime}-${event.eventName}`,
      timestamp: new Date(event.eventTime),
      eventType: event.eventName,
      source: event.eventSource,
      principal: this.extractPrincipal(event.userIdentity),
      resource: this.extractResource(event),
      action: event.eventName,
      result: event.errorCode ? 'failure' : 'success',
      details: {
        userIdentity: event.userIdentity,
        sourceIPAddress: event.sourceIPAddress,
        userAgent: event.userAgent,
        requestParameters: event.requestParameters,
        responseElements: event.responseElements,
        errorCode: event.errorCode,
        errorMessage: event.errorMessage,
        awsRegion: event.awsRegion,
      },
    };
  }

  /**
   * Extract principal from user identity
   */
  private extractPrincipal(userIdentity: any): string {
    if (userIdentity.type === 'Root') {
      return 'root';
    } else if (userIdentity.type === 'IAMUser') {
      return userIdentity.userName || userIdentity.principalId;
    } else if (userIdentity.type === 'AssumedRole') {
      return userIdentity.sessionContext?.sessionIssuer?.userName || userIdentity.principalId;
    } else if (userIdentity.type === 'AWSService') {
      return userIdentity.invokedBy || 'aws-service';
    }
    return userIdentity.principalId || 'unknown';
  }

  /**
   * Extract resource from event
   */
  private extractResource(event: CloudTrailEvent): string {
    if (event.resources && event.resources.length > 0) {
      return event.resources[0].ARN || event.resources[0].accountId || 'unknown';
    }
    return event.eventSource;
  }

  /**
   * Detect anomalies and suspicious patterns in security events
   */
  private detectAnomalies(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    // Detect root account usage
    findings.push(...this.detectRootAccountUsage(events));

    // Detect failed authentication attempts
    findings.push(...this.detectFailedAuthentication(events));

    // Detect privilege escalation attempts
    findings.push(...this.detectPrivilegeEscalation(events));

    // Detect unusual API calls
    findings.push(...this.detectUnusualAPICalls(events));

    // Detect data exfiltration patterns
    findings.push(...this.detectDataExfiltration(events));

    return findings;
  }

  /**
   * Detect root account usage
   */
  private detectRootAccountUsage(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    const rootEvents = events.filter((e) => e.principal === 'root');

    if (rootEvents.length > 0) {
      findings.push({
        id: `cloudtrail-root-${Date.now()}`,
        ruleId: 'CLOUDTRAIL-001',
        resource: {
          id: 'root-account',
          type: 'IAM::Root',
          service: 'iam',
          region: 'global',
          account: rootEvents[0].details.awsRegion || 'unknown',
          properties: {},
          tags: {},
          relationships: [],
          source: ResourceSource.LIVE,
          timestamp: new Date(),
        },
        severity: Severity.CRITICAL,
        category: Category.IAM,
        title: 'Root Account Usage Detected',
        description: `Root account was used ${rootEvents.length} time(s) in the analyzed period`,
        evidence: {
          description: 'CloudTrail logs show root account activity',
          details: {
            eventCount: rootEvents.length,
            events: rootEvents.slice(0, 5).map((e) => ({
              timestamp: e.timestamp,
              action: e.action,
              sourceIP: e.details.sourceIPAddress,
            })),
          },
        },
        remediation: {
          description: 'Avoid using root account for daily operations',
          steps: [
            'Create IAM users with appropriate permissions',
            'Enable MFA on root account',
            'Use IAM roles for programmatic access',
            'Review root account activity regularly',
          ],
        },
        complianceMapping: [],
        riskScore: 95,
        status: FindingStatus.OPEN,
        createdAt: new Date(),
        updatedAt: new Date(),
        correlatedEvents: rootEvents,
      });
    }

    return findings;
  }

  /**
   * Detect failed authentication attempts
   */
  private detectFailedAuthentication(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    const failedLogins = events.filter(
      (e) =>
        e.result === 'failure' &&
        (e.action.includes('ConsoleLogin') ||
          e.action.includes('GetSessionToken') ||
          e.action.includes('AssumeRole'))
    );

    // Group by source IP
    const byIP = new Map<string, SecurityEvent[]>();
    for (const event of failedLogins) {
      const ip = event.details.sourceIPAddress;
      if (!byIP.has(ip)) {
        byIP.set(ip, []);
      }
      byIP.get(ip)!.push(event);
    }

    // Flag IPs with multiple failed attempts
    for (const [ip, ipEvents] of byIP.entries()) {
      if (ipEvents.length >= 5) {
        findings.push({
          id: `cloudtrail-failed-auth-${ip}-${Date.now()}`,
          ruleId: 'CLOUDTRAIL-002',
          resource: {
            id: `source-${ip}`,
            type: 'Network::SourceIP',
            service: 'network',
            region: 'global',
            account: ipEvents[0].details.awsRegion || 'unknown',
            properties: { sourceIP: ip },
            tags: {},
            relationships: [],
            source: ResourceSource.LIVE,
            timestamp: new Date(),
          },
          severity: Severity.HIGH,
          category: Category.IAM,
          title: 'Multiple Failed Authentication Attempts',
          description: `${ipEvents.length} failed authentication attempts from IP ${ip}`,
          evidence: {
            description: 'CloudTrail logs show repeated failed authentication',
            details: {
              sourceIP: ip,
              attemptCount: ipEvents.length,
              events: ipEvents.slice(0, 5).map((e) => ({
                timestamp: e.timestamp,
                action: e.action,
                principal: e.principal,
                errorCode: e.details.errorCode,
              })),
            },
          },
          remediation: {
            description: 'Investigate and block suspicious IP addresses',
            steps: [
              'Review authentication logs for the source IP',
              'Check if IP is from expected location',
              'Consider blocking IP at network level',
              'Enable MFA for all users',
              'Review IAM password policies',
            ],
          },
          complianceMapping: [],
          riskScore: 80,
          status: FindingStatus.OPEN,
          createdAt: new Date(),
          updatedAt: new Date(),
          correlatedEvents: ipEvents,
        });
      }
    }

    return findings;
  }

  /**
   * Detect privilege escalation attempts
   */
  private detectPrivilegeEscalation(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    const escalationActions = [
      'PutUserPolicy',
      'PutRolePolicy',
      'AttachUserPolicy',
      'AttachRolePolicy',
      'CreateAccessKey',
      'UpdateAssumeRolePolicy',
      'AddUserToGroup',
    ];

    const escalationEvents = events.filter((e) =>
      escalationActions.some((action) => e.action.includes(action))
    );

    if (escalationEvents.length > 0) {
      // Group by principal
      const byPrincipal = new Map<string, SecurityEvent[]>();
      for (const event of escalationEvents) {
        const principal = event.principal;
        if (!byPrincipal.has(principal)) {
          byPrincipal.set(principal, []);
        }
        byPrincipal.get(principal)!.push(event);
      }

      for (const [principal, principalEvents] of byPrincipal.entries()) {
        if (principalEvents.length >= 3) {
          findings.push({
            id: `cloudtrail-escalation-${principal}-${Date.now()}`,
            ruleId: 'CLOUDTRAIL-003',
            resource: {
              id: `principal-${principal}`,
              type: 'IAM::Principal',
              service: 'iam',
              region: 'global',
              account: principalEvents[0].details.awsRegion || 'unknown',
              properties: { principal },
              tags: {},
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            },
            severity: Severity.CRITICAL,
            category: Category.IAM,
            title: 'Potential Privilege Escalation Detected',
            description: `Principal ${principal} performed ${principalEvents.length} privilege escalation actions`,
            evidence: {
              description: 'CloudTrail logs show suspicious IAM permission changes',
              details: {
                principal,
                actionCount: principalEvents.length,
                events: principalEvents.map((e) => ({
                  timestamp: e.timestamp,
                  action: e.action,
                  resource: e.resource,
                })),
              },
            },
            remediation: {
              description: 'Investigate and revoke unauthorized permissions',
              steps: [
                'Review all IAM changes made by this principal',
                'Verify if changes were authorized',
                'Revoke unauthorized permissions immediately',
                'Rotate credentials if compromise is suspected',
                'Enable CloudTrail alerts for IAM changes',
              ],
            },
            complianceMapping: [],
            riskScore: 90,
            status: FindingStatus.OPEN,
            createdAt: new Date(),
            updatedAt: new Date(),
            correlatedEvents: principalEvents,
          });
        }
      }
    }

    return findings;
  }

  /**
   * Detect unusual API calls
   */
  private detectUnusualAPICalls(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    const dangerousActions = [
      'DeleteTrail',
      'StopLogging',
      'DeleteFlowLogs',
      'DisableSecurityHub',
      'DeleteDetector',
      'PutBucketPolicy',
      'ModifyDBInstance',
    ];

    const dangerousEvents = events.filter((e) =>
      dangerousActions.some((action) => e.action.includes(action))
    );

    for (const event of dangerousEvents) {
      findings.push({
        id: `cloudtrail-dangerous-${event.id}`,
        ruleId: 'CLOUDTRAIL-004',
        resource: {
          id: event.resource,
          type: 'AWS::Resource',
          service: event.source,
          region: event.details.awsRegion || 'unknown',
          account: event.details.awsRegion || 'unknown',
          properties: {},
          tags: {},
          relationships: [],
          source: ResourceSource.LIVE,
          timestamp: new Date(),
        },
        severity: Severity.HIGH,
        category: Category.LOGGING,
        title: 'Dangerous API Call Detected',
        description: `Potentially dangerous action ${event.action} was performed`,
        evidence: {
          description: 'CloudTrail logs show security-sensitive API call',
          details: {
            action: event.action,
            principal: event.principal,
            timestamp: event.timestamp,
            sourceIP: event.details.sourceIPAddress,
            result: event.result,
          },
        },
        remediation: {
          description: 'Verify if action was authorized and restore if needed',
          steps: [
            'Verify if the action was authorized',
            'Check if security services are still enabled',
            'Restore deleted resources if unauthorized',
            'Review IAM permissions for the principal',
            'Enable alerts for security-sensitive actions',
          ],
        },
        complianceMapping: [],
        riskScore: 75,
        status: FindingStatus.OPEN,
        createdAt: new Date(),
        updatedAt: new Date(),
        correlatedEvents: [event],
      });
    }

    return findings;
  }

  /**
   * Detect data exfiltration patterns
   */
  private detectDataExfiltration(events: SecurityEvent[]): ThreatFinding[] {
    const findings: ThreatFinding[] = [];

    const exfiltrationActions = [
      'GetObject',
      'CopyObject',
      'CreateSnapshot',
      'CopySnapshot',
      'CreateDBSnapshot',
      'CopyDBSnapshot',
    ];

    const exfiltrationEvents = events.filter((e) =>
      exfiltrationActions.some((action) => e.action.includes(action))
    );

    // Group by principal and count
    const byPrincipal = new Map<string, SecurityEvent[]>();
    for (const event of exfiltrationEvents) {
      const principal = event.principal;
      if (!byPrincipal.has(principal)) {
        byPrincipal.set(principal, []);
      }
      byPrincipal.get(principal)!.push(event);
    }

    // Flag principals with high volume of data access
    for (const [principal, principalEvents] of byPrincipal.entries()) {
      if (principalEvents.length >= 100) {
        findings.push({
          id: `cloudtrail-exfiltration-${principal}-${Date.now()}`,
          ruleId: 'CLOUDTRAIL-005',
          resource: {
            id: `principal-${principal}`,
            type: 'IAM::Principal',
            service: 'iam',
            region: 'global',
            account: principalEvents[0].details.awsRegion || 'unknown',
            properties: { principal },
            tags: {},
            relationships: [],
            source: ResourceSource.LIVE,
            timestamp: new Date(),
          },
          severity: Severity.HIGH,
          category: Category.STORAGE,
          title: 'Potential Data Exfiltration Detected',
          description: `Principal ${principal} performed ${principalEvents.length} data access operations`,
          evidence: {
            description: 'CloudTrail logs show high volume of data access',
            details: {
              principal,
              operationCount: principalEvents.length,
              timeRange: {
                start: principalEvents[0].timestamp,
                end: principalEvents[principalEvents.length - 1].timestamp,
              },
            },
          },
          remediation: {
            description: 'Investigate unusual data access patterns',
            steps: [
              'Review all data access by this principal',
              'Verify if access pattern is legitimate',
              'Check destination of copied data',
              'Revoke access if unauthorized',
              'Enable S3 access logging and monitoring',
            ],
          },
          complianceMapping: [],
          riskScore: 70,
          status: FindingStatus.OPEN,
          createdAt: new Date(),
          updatedAt: new Date(),
          correlatedEvents: principalEvents.slice(0, 10),
        });
      }
    }

    return findings;
  }
}
