/**
 * Event Correlator
 * Identifies related security events and detects attack patterns
 */

import {
  SecurityEvent,
  CorrelatedThreat,
  AttackPattern,
  Timeline,
  TimelineEvent,
  Severity,
  Resource,
} from '../types';

export interface CorrelationRule {
  name: string;
  description: string;
  timeWindowMs: number;
  minEvents: number;
  pattern: (events: SecurityEvent[]) => boolean;
  severity: Severity;
  attackPattern: AttackPattern;
}

export class EventCorrelator {
  private correlationRules: CorrelationRule[];

  constructor() {
    this.correlationRules = this.initializeRules();
  }

  /**
   * Correlate security events to identify threats
   */
  correlateEvents(events: SecurityEvent[]): CorrelatedThreat[] {
    const threats: CorrelatedThreat[] = [];

    // Sort events by timestamp
    const sortedEvents = [...events].sort(
      (a, b) => a.timestamp.getTime() - b.timestamp.getTime()
    );

    // Apply each correlation rule
    for (const rule of this.correlationRules) {
      const ruleThreats = this.applyRule(rule, sortedEvents);
      threats.push(...ruleThreats);
    }

    // Deduplicate threats
    return this.deduplicateThreats(threats);
  }

  /**
   * Apply a correlation rule to events
   */
  private applyRule(
    rule: CorrelationRule,
    events: SecurityEvent[]
  ): CorrelatedThreat[] {
    const threats: CorrelatedThreat[] = [];

    // Use sliding time window
    for (let i = 0; i < events.length; i++) {
      const windowStart = events[i].timestamp.getTime();
      const windowEnd = windowStart + rule.timeWindowMs;

      // Get events within time window
      const windowEvents: SecurityEvent[] = [];
      for (let j = i; j < events.length; j++) {
        const eventTime = events[j].timestamp.getTime();
        if (eventTime <= windowEnd) {
          windowEvents.push(events[j]);
        } else {
          break;
        }
      }

      // Check if pattern matches
      if (
        windowEvents.length >= rule.minEvents &&
        rule.pattern(windowEvents)
      ) {
        const threat = this.createThreat(rule, windowEvents);
        threats.push(threat);

        // Skip ahead to avoid overlapping detections
        i += windowEvents.length - 1;
      }
    }

    return threats;
  }

  /**
   * Create a CorrelatedThreat from matched events
   */
  private createThreat(
    rule: CorrelationRule,
    events: SecurityEvent[]
  ): CorrelatedThreat {
    const timeline = this.createTimeline(events);
    const affectedResources = this.extractAffectedResources(events);

    return {
      id: `threat-${rule.name}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      events,
      attackPattern: rule.attackPattern,
      severity: rule.severity,
      timeline,
      affectedResources,
    };
  }

  /**
   * Create timeline from events
   */
  private createTimeline(events: SecurityEvent[]): Timeline {
    const timelineEvents: TimelineEvent[] = events.map((event) => ({
      timestamp: event.timestamp,
      description: `${event.action} by ${event.principal} on ${event.resource}`,
      severity: this.inferEventSeverity(event),
    }));

    return {
      events: timelineEvents,
      startTime: events[0].timestamp,
      endTime: events[events.length - 1].timestamp,
    };
  }

  /**
   * Infer severity from event
   */
  private inferEventSeverity(event: SecurityEvent): Severity {
    if (event.result === 'failure') {
      return Severity.MEDIUM;
    }

    const dangerousActions = [
      'DeleteTrail',
      'StopLogging',
      'PutUserPolicy',
      'AttachUserPolicy',
      'CreateAccessKey',
      'DeleteBucket',
    ];

    if (dangerousActions.some((action) => event.action.includes(action))) {
      return Severity.HIGH;
    }

    return Severity.LOW;
  }

  /**
   * Extract affected resources from events
   */
  private extractAffectedResources(events: SecurityEvent[]): Resource[] {
    const resourceMap = new Map<string, Resource>();

    for (const event of events) {
      if (!resourceMap.has(event.resource)) {
        resourceMap.set(event.resource, {
          id: event.resource,
          type: 'AWS::Resource',
          service: event.source,
          region: event.details.awsRegion || 'unknown',
          account: event.principal,
          properties: {},
          tags: {},
          relationships: [],
          source: 'live' as any,
          timestamp: event.timestamp,
        });
      }
    }

    return Array.from(resourceMap.values());
  }

  /**
   * Deduplicate threats
   */
  private deduplicateThreats(threats: CorrelatedThreat[]): CorrelatedThreat[] {
    const seen = new Set<string>();
    const unique: CorrelatedThreat[] = [];

    for (const threat of threats) {
      // Create signature from event IDs
      const signature = threat.events
        .map((e) => e.id)
        .sort()
        .join('|');

      if (!seen.has(signature)) {
        seen.add(signature);
        unique.push(threat);
      }
    }

    return unique;
  }

  /**
   * Initialize correlation rules
   */
  private initializeRules(): CorrelationRule[] {
    return [
      this.createPrivilegeEscalationRule(),
      this.createAccessKeyCreationRule(),
      this.createSuspiciousIAMActivityRule(),
      this.createNetworkChangeAfterCompromiseRule(),
      this.createDataExfiltrationRule(),
      this.createSecurityServiceDisablementRule(),
      this.createBruteForceRule(),
      this.createLateralMovementRule(),
    ];
  }

  /**
   * Rule: Privilege escalation attempts
   */
  private createPrivilegeEscalationRule(): CorrelationRule {
    return {
      name: 'privilege-escalation',
      description: 'Detect privilege escalation attempts',
      timeWindowMs: 3600000, // 1 hour
      minEvents: 3,
      pattern: (events: SecurityEvent[]) => {
        const escalationActions = [
          'PutUserPolicy',
          'PutRolePolicy',
          'AttachUserPolicy',
          'AttachRolePolicy',
          'UpdateAssumeRolePolicy',
          'AddUserToGroup',
        ];

        const escalationEvents = events.filter((e) =>
          escalationActions.some((action) => e.action.includes(action))
        );

        // Check if same principal performed multiple escalation actions
        if (escalationEvents.length >= 3) {
          const principals = new Set(escalationEvents.map((e) => e.principal));
          return principals.size === 1;
        }

        return false;
      },
      severity: Severity.CRITICAL,
      attackPattern: {
        name: 'Privilege Escalation',
        description: 'Attacker attempting to gain higher privileges',
        mitreId: 'T1078',
        tactics: ['Privilege Escalation', 'Persistence'],
        techniques: ['Valid Accounts', 'Account Manipulation'],
      },
    };
  }

  /**
   * Rule: Privilege escalation followed by access key creation
   */
  private createAccessKeyCreationRule(): CorrelationRule {
    return {
      name: 'escalation-then-access-key',
      description: 'Privilege escalation followed by access key creation',
      timeWindowMs: 1800000, // 30 minutes
      minEvents: 2,
      pattern: (events: SecurityEvent[]) => {
        const escalationActions = [
          'PutUserPolicy',
          'AttachUserPolicy',
          'AddUserToGroup',
        ];

        const hasEscalation = events.some((e) =>
          escalationActions.some((action) => e.action.includes(action))
        );

        const hasAccessKeyCreation = events.some((e) =>
          e.action.includes('CreateAccessKey')
        );

        return hasEscalation && hasAccessKeyCreation;
      },
      severity: Severity.CRITICAL,
      attackPattern: {
        name: 'Privilege Escalation with Persistence',
        description:
          'Attacker escalates privileges and creates access key for persistence',
        mitreId: 'T1098',
        tactics: ['Privilege Escalation', 'Persistence'],
        techniques: ['Account Manipulation', 'Create Account'],
      },
    };
  }

  /**
   * Rule: Suspicious IAM activity
   */
  private createSuspiciousIAMActivityRule(): CorrelationRule {
    return {
      name: 'suspicious-iam-activity',
      description: 'Multiple suspicious IAM actions in short time',
      timeWindowMs: 1800000, // 30 minutes
      minEvents: 5,
      pattern: (events: SecurityEvent[]) => {
        const suspiciousActions = [
          'CreateUser',
          'CreateRole',
          'CreatePolicy',
          'AttachPolicy',
          'PutPolicy',
          'CreateAccessKey',
          'UpdateLoginProfile',
        ];

        const suspiciousEvents = events.filter((e) =>
          suspiciousActions.some((action) => e.action.includes(action))
        );

        return suspiciousEvents.length >= 5;
      },
      severity: Severity.HIGH,
      attackPattern: {
        name: 'IAM Manipulation',
        description: 'Rapid IAM changes indicating potential compromise',
        mitreId: 'T1098',
        tactics: ['Persistence', 'Privilege Escalation'],
        techniques: ['Account Manipulation'],
      },
    };
  }

  /**
   * Rule: Network changes after IAM compromise
   */
  private createNetworkChangeAfterCompromiseRule(): CorrelationRule {
    return {
      name: 'network-change-after-compromise',
      description: 'Network configuration changes after suspicious IAM activity',
      timeWindowMs: 3600000, // 1 hour
      minEvents: 2,
      pattern: (events: SecurityEvent[]) => {
        const iamActions = [
          'CreateAccessKey',
          'PutUserPolicy',
          'AttachUserPolicy',
        ];
        const networkActions = [
          'AuthorizeSecurityGroupIngress',
          'CreateSecurityGroup',
          'ModifyDBInstance',
          'ModifyInstanceAttribute',
        ];

        const hasIAMActivity = events.some((e) =>
          iamActions.some((action) => e.action.includes(action))
        );

        const hasNetworkChange = events.some((e) =>
          networkActions.some((action) => e.action.includes(action))
        );

        return hasIAMActivity && hasNetworkChange;
      },
      severity: Severity.HIGH,
      attackPattern: {
        name: 'Post-Compromise Network Modification',
        description:
          'Attacker modifies network rules after gaining access',
        mitreId: 'T1562',
        tactics: ['Defense Evasion', 'Persistence'],
        techniques: ['Impair Defenses', 'Modify Cloud Compute Infrastructure'],
      },
    };
  }

  /**
   * Rule: Data exfiltration pattern
   */
  private createDataExfiltrationRule(): CorrelationRule {
    return {
      name: 'data-exfiltration',
      description: 'High volume of data access operations',
      timeWindowMs: 1800000, // 30 minutes
      minEvents: 50,
      pattern: (events: SecurityEvent[]) => {
        const exfiltrationActions = [
          'GetObject',
          'CopyObject',
          'CreateSnapshot',
          'CopySnapshot',
          'CreateDBSnapshot',
        ];

        const exfiltrationEvents = events.filter((e) =>
          exfiltrationActions.some((action) => e.action.includes(action))
        );

        // Check if same principal performed many data access operations
        if (exfiltrationEvents.length >= 50) {
          const principals = new Set(exfiltrationEvents.map((e) => e.principal));
          return principals.size <= 2; // One or two principals
        }

        return false;
      },
      severity: Severity.HIGH,
      attackPattern: {
        name: 'Data Exfiltration',
        description: 'High volume data access indicating exfiltration',
        mitreId: 'T1537',
        tactics: ['Exfiltration'],
        techniques: ['Transfer Data to Cloud Account'],
      },
    };
  }

  /**
   * Rule: Security service disablement
   */
  private createSecurityServiceDisablementRule(): CorrelationRule {
    return {
      name: 'security-service-disablement',
      description: 'Multiple security services disabled',
      timeWindowMs: 1800000, // 30 minutes
      minEvents: 2,
      pattern: (events: SecurityEvent[]) => {
        const disablementActions = [
          'DeleteTrail',
          'StopLogging',
          'DeleteFlowLogs',
          'DisableSecurityHub',
          'DeleteDetector',
          'DisableOrganizationAdminAccount',
        ];

        const disablementEvents = events.filter((e) =>
          disablementActions.some((action) => e.action.includes(action))
        );

        return disablementEvents.length >= 2;
      },
      severity: Severity.CRITICAL,
      attackPattern: {
        name: 'Defense Evasion',
        description: 'Attacker disabling security monitoring',
        mitreId: 'T1562',
        tactics: ['Defense Evasion'],
        techniques: ['Impair Defenses', 'Disable Cloud Logs'],
      },
    };
  }

  /**
   * Rule: Brute force authentication
   */
  private createBruteForceRule(): CorrelationRule {
    return {
      name: 'brute-force-authentication',
      description: 'Multiple failed authentication attempts',
      timeWindowMs: 600000, // 10 minutes
      minEvents: 10,
      pattern: (events: SecurityEvent[]) => {
        const authEvents = events.filter(
          (e) =>
            e.result === 'failure' &&
            (e.action.includes('ConsoleLogin') ||
              e.action.includes('GetSessionToken') ||
              e.action.includes('AssumeRole'))
        );

        // Check if from same source IP
        if (authEvents.length >= 10) {
          const sourceIPs = authEvents.map((e) => e.details.sourceIPAddress);
          const uniqueIPs = new Set(sourceIPs);
          return uniqueIPs.size <= 3; // From few IPs
        }

        return false;
      },
      severity: Severity.HIGH,
      attackPattern: {
        name: 'Brute Force',
        description: 'Repeated authentication attempts',
        mitreId: 'T1110',
        tactics: ['Credential Access'],
        techniques: ['Brute Force'],
      },
    };
  }

  /**
   * Rule: Lateral movement
   */
  private createLateralMovementRule(): CorrelationRule {
    return {
      name: 'lateral-movement',
      description: 'AssumeRole across multiple accounts',
      timeWindowMs: 3600000, // 1 hour
      minEvents: 3,
      pattern: (events: SecurityEvent[]) => {
        const assumeRoleEvents = events.filter((e) =>
          e.action.includes('AssumeRole')
        );

        if (assumeRoleEvents.length >= 3) {
          // Check if same principal assuming different roles
          const principals = new Set(assumeRoleEvents.map((e) => e.principal));
          const roles = new Set(
            assumeRoleEvents.map((e) => e.details.requestParameters?.roleArn)
          );

          return principals.size === 1 && roles.size >= 3;
        }

        return false;
      },
      severity: Severity.HIGH,
      attackPattern: {
        name: 'Lateral Movement',
        description: 'Moving across accounts and roles',
        mitreId: 'T1550',
        tactics: ['Lateral Movement'],
        techniques: ['Use Alternate Authentication Material'],
      },
    };
  }

  /**
   * Add custom correlation rule
   */
  addRule(rule: CorrelationRule): void {
    this.correlationRules.push(rule);
  }

  /**
   * Get all correlation rules
   */
  getRules(): CorrelationRule[] {
    return [...this.correlationRules];
  }
}
