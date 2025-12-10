/**
 * Tests for Event Correlator
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { EventCorrelator } from '../event-correlator';
import { SecurityEvent, Severity } from '../../types';

describe('EventCorrelator', () => {
  let correlator: EventCorrelator;

  beforeEach(() => {
    correlator = new EventCorrelator();
  });

  describe('correlateEvents', () => {
    it('should detect privilege escalation pattern', () => {
      const events: SecurityEvent[] = [
        {
          id: '1',
          timestamp: new Date('2024-01-01T12:00:00Z'),
          eventType: 'PutUserPolicy',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'PutUserPolicy',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
        {
          id: '2',
          timestamp: new Date('2024-01-01T12:05:00Z'),
          eventType: 'AttachUserPolicy',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'AttachUserPolicy',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
        {
          id: '3',
          timestamp: new Date('2024-01-01T12:10:00Z'),
          eventType: 'AddUserToGroup',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'AddUserToGroup',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
      ];

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const escalationThreat = threats.find(
        (t) => t.attackPattern.name === 'Privilege Escalation'
      );
      expect(escalationThreat).toBeDefined();
      expect(escalationThreat?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect escalation followed by access key creation', () => {
      const events: SecurityEvent[] = [
        {
          id: '1',
          timestamp: new Date('2024-01-01T12:00:00Z'),
          eventType: 'PutUserPolicy',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'PutUserPolicy',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
        {
          id: '2',
          timestamp: new Date('2024-01-01T12:10:00Z'),
          eventType: 'CreateAccessKey',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'CreateAccessKey',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
      ];

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const persistenceThreat = threats.find(
        (t) => t.attackPattern.name === 'Privilege Escalation with Persistence'
      );
      expect(persistenceThreat).toBeDefined();
      expect(persistenceThreat?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect suspicious IAM activity', () => {
      const events: SecurityEvent[] = Array.from({ length: 5 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(`2024-01-01T12:${i.toString().padStart(2, '0')}:00Z`),
        eventType: 'CreateUser',
        source: 'iam.amazonaws.com',
        principal: 'attacker',
        resource: `user/newuser${i}`,
        action: 'CreateUser',
        result: 'success',
        details: { awsRegion: 'us-east-1' },
      }));

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const iamThreat = threats.find(
        (t) => t.attackPattern.name === 'IAM Manipulation'
      );
      expect(iamThreat).toBeDefined();
      expect(iamThreat?.severity).toBe(Severity.HIGH);
    });

    it('should detect network changes after compromise', () => {
      const events: SecurityEvent[] = [
        {
          id: '1',
          timestamp: new Date('2024-01-01T12:00:00Z'),
          eventType: 'CreateAccessKey',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'CreateAccessKey',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
        {
          id: '2',
          timestamp: new Date('2024-01-01T12:30:00Z'),
          eventType: 'AuthorizeSecurityGroupIngress',
          source: 'ec2.amazonaws.com',
          principal: 'attacker',
          resource: 'sg-123',
          action: 'AuthorizeSecurityGroupIngress',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
      ];

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const networkThreat = threats.find(
        (t) => t.attackPattern.name === 'Post-Compromise Network Modification'
      );
      expect(networkThreat).toBeDefined();
      expect(networkThreat?.severity).toBe(Severity.HIGH);
    });

    it('should detect data exfiltration pattern', () => {
      const events: SecurityEvent[] = Array.from({ length: 50 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(`2024-01-01T12:00:${i.toString().padStart(2, '0')}Z`),
        eventType: 'GetObject',
        source: 's3.amazonaws.com',
        principal: 'attacker',
        resource: 'bucket/data',
        action: 'GetObject',
        result: 'success',
        details: { awsRegion: 'us-east-1' },
      }));

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const exfilThreat = threats.find(
        (t) => t.attackPattern.name === 'Data Exfiltration'
      );
      expect(exfilThreat).toBeDefined();
      expect(exfilThreat?.severity).toBe(Severity.HIGH);
    });

    it('should detect security service disablement', () => {
      const events: SecurityEvent[] = [
        {
          id: '1',
          timestamp: new Date('2024-01-01T12:00:00Z'),
          eventType: 'DeleteTrail',
          source: 'cloudtrail.amazonaws.com',
          principal: 'attacker',
          resource: 'trail/mytrail',
          action: 'DeleteTrail',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
        {
          id: '2',
          timestamp: new Date('2024-01-01T12:05:00Z'),
          eventType: 'DisableSecurityHub',
          source: 'securityhub.amazonaws.com',
          principal: 'attacker',
          resource: 'securityhub',
          action: 'DisableSecurityHub',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
      ];

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const evasionThreat = threats.find(
        (t) => t.attackPattern.name === 'Defense Evasion'
      );
      expect(evasionThreat).toBeDefined();
      expect(evasionThreat?.severity).toBe(Severity.CRITICAL);
    });

    it('should detect brute force authentication', () => {
      const events: SecurityEvent[] = Array.from({ length: 10 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(`2024-01-01T12:00:${i.toString().padStart(2, '0')}Z`),
        eventType: 'ConsoleLogin',
        source: 'signin.amazonaws.com',
        principal: 'testuser',
        resource: 'AWS::Account',
        action: 'ConsoleLogin',
        result: 'failure',
        details: {
          awsRegion: 'us-east-1',
          sourceIPAddress: '1.2.3.4',
          errorCode: 'InvalidPassword',
        },
      }));

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const bruteForceThreat = threats.find(
        (t) => t.attackPattern.name === 'Brute Force'
      );
      expect(bruteForceThreat).toBeDefined();
      expect(bruteForceThreat?.severity).toBe(Severity.HIGH);
    });

    it('should detect lateral movement', () => {
      const events: SecurityEvent[] = [
        {
          id: '1',
          timestamp: new Date('2024-01-01T12:00:00Z'),
          eventType: 'AssumeRole',
          source: 'sts.amazonaws.com',
          principal: 'attacker',
          resource: 'role/role1',
          action: 'AssumeRole',
          result: 'success',
          details: {
            awsRegion: 'us-east-1',
            requestParameters: { roleArn: 'arn:aws:iam::123456789012:role/role1' },
          },
        },
        {
          id: '2',
          timestamp: new Date('2024-01-01T12:10:00Z'),
          eventType: 'AssumeRole',
          source: 'sts.amazonaws.com',
          principal: 'attacker',
          resource: 'role/role2',
          action: 'AssumeRole',
          result: 'success',
          details: {
            awsRegion: 'us-east-1',
            requestParameters: { roleArn: 'arn:aws:iam::123456789012:role/role2' },
          },
        },
        {
          id: '3',
          timestamp: new Date('2024-01-01T12:20:00Z'),
          eventType: 'AssumeRole',
          source: 'sts.amazonaws.com',
          principal: 'attacker',
          resource: 'role/role3',
          action: 'AssumeRole',
          result: 'success',
          details: {
            awsRegion: 'us-east-1',
            requestParameters: { roleArn: 'arn:aws:iam::123456789012:role/role3' },
          },
        },
      ];

      const threats = correlator.correlateEvents(events);

      expect(threats.length).toBeGreaterThan(0);
      const lateralThreat = threats.find(
        (t) => t.attackPattern.name === 'Lateral Movement'
      );
      expect(lateralThreat).toBeDefined();
      expect(lateralThreat?.severity).toBe(Severity.HIGH);
    });

    it('should not create threats for normal activity', () => {
      const events: SecurityEvent[] = [
        {
          id: '1',
          timestamp: new Date('2024-01-01T12:00:00Z'),
          eventType: 'GetObject',
          source: 's3.amazonaws.com',
          principal: 'normaluser',
          resource: 'bucket/data',
          action: 'GetObject',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
      ];

      const threats = correlator.correlateEvents(events);

      expect(threats).toHaveLength(0);
    });
  });

  describe('addRule', () => {
    it('should allow adding custom correlation rules', () => {
      const customRule = {
        name: 'custom-rule',
        description: 'Custom test rule',
        timeWindowMs: 3600000,
        minEvents: 2,
        pattern: (events: SecurityEvent[]) => events.length >= 2,
        severity: Severity.MEDIUM,
        attackPattern: {
          name: 'Custom Attack',
          description: 'Custom attack pattern',
          tactics: ['Test'],
          techniques: ['Test'],
        },
      };

      correlator.addRule(customRule);

      const rules = correlator.getRules();
      expect(rules).toContainEqual(customRule);
    });
  });

  describe('deduplication', () => {
    it('should deduplicate identical threats', () => {
      const events: SecurityEvent[] = [
        {
          id: '1',
          timestamp: new Date('2024-01-01T12:00:00Z'),
          eventType: 'PutUserPolicy',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'PutUserPolicy',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
        {
          id: '2',
          timestamp: new Date('2024-01-01T12:05:00Z'),
          eventType: 'AttachUserPolicy',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'AttachUserPolicy',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
        {
          id: '3',
          timestamp: new Date('2024-01-01T12:10:00Z'),
          eventType: 'AddUserToGroup',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'AddUserToGroup',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
      ];

      // Correlate twice with same events
      const threats1 = correlator.correlateEvents(events);
      const threats2 = correlator.correlateEvents(events);

      // Should produce same number of threats
      expect(threats1.length).toBe(threats2.length);
    });
  });
});
