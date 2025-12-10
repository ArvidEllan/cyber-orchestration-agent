/**
 * Tests for CloudTrail Analyzer
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { CloudTrailAnalyzer } from '../cloudtrail-analyzer';
import { LogType, Severity } from '../../types';

describe('CloudTrailAnalyzer', () => {
  let analyzer: CloudTrailAnalyzer;

  beforeEach(() => {
    analyzer = new CloudTrailAnalyzer('us-east-1');
  });

  describe('normalizeEvent', () => {
    it('should normalize CloudTrail event to SecurityEvent', () => {
      const cloudTrailEvent = {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          userName: 'testuser',
          principalId: 'AIDAI123456',
        },
        eventTime: '2024-01-01T12:00:00Z',
        eventSource: 'iam.amazonaws.com',
        eventName: 'CreateUser',
        awsRegion: 'us-east-1',
        sourceIPAddress: '192.168.1.1',
        userAgent: 'aws-cli/2.0',
        requestParameters: { userName: 'newuser' },
        responseElements: null,
      };

      const securityEvent = analyzer.normalizeEvent(cloudTrailEvent);

      expect(securityEvent.id).toContain('CreateUser');
      expect(securityEvent.eventType).toBe('CreateUser');
      expect(securityEvent.source).toBe('iam.amazonaws.com');
      expect(securityEvent.principal).toBe('testuser');
      expect(securityEvent.action).toBe('CreateUser');
      expect(securityEvent.result).toBe('success');
      expect(securityEvent.details.sourceIPAddress).toBe('192.168.1.1');
    });

    it('should handle root user identity', () => {
      const cloudTrailEvent = {
        eventVersion: '1.08',
        userIdentity: {
          type: 'Root',
          principalId: 'ROOT',
        },
        eventTime: '2024-01-01T12:00:00Z',
        eventSource: 'iam.amazonaws.com',
        eventName: 'ConsoleLogin',
        awsRegion: 'us-east-1',
        sourceIPAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      };

      const securityEvent = analyzer.normalizeEvent(cloudTrailEvent);

      expect(securityEvent.principal).toBe('root');
    });

    it('should handle failed events', () => {
      const cloudTrailEvent = {
        eventVersion: '1.08',
        userIdentity: {
          type: 'IAMUser',
          userName: 'testuser',
        },
        eventTime: '2024-01-01T12:00:00Z',
        eventSource: 'iam.amazonaws.com',
        eventName: 'CreateUser',
        awsRegion: 'us-east-1',
        sourceIPAddress: '192.168.1.1',
        userAgent: 'aws-cli/2.0',
        errorCode: 'AccessDenied',
        errorMessage: 'User is not authorized',
      };

      const securityEvent = analyzer.normalizeEvent(cloudTrailEvent);

      expect(securityEvent.result).toBe('failure');
      expect(securityEvent.details.errorCode).toBe('AccessDenied');
    });
  });

  describe('detectRootAccountUsage', () => {
    it('should detect root account usage', () => {
      const events = [
        {
          id: '1',
          timestamp: new Date(),
          eventType: 'ConsoleLogin',
          source: 'signin.amazonaws.com',
          principal: 'root',
          resource: 'AWS::Account',
          action: 'ConsoleLogin',
          result: 'success',
          details: { awsRegion: 'us-east-1', sourceIPAddress: '1.2.3.4' },
        },
      ];

      const findings = (analyzer as any).detectRootAccountUsage(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.CRITICAL);
      expect(findings[0].title).toBe('Root Account Usage Detected');
      expect(findings[0].riskScore).toBe(95);
    });

    it('should not create finding when no root usage', () => {
      const events = [
        {
          id: '1',
          timestamp: new Date(),
          eventType: 'ConsoleLogin',
          source: 'signin.amazonaws.com',
          principal: 'testuser',
          resource: 'AWS::Account',
          action: 'ConsoleLogin',
          result: 'success',
          details: { awsRegion: 'us-east-1', sourceIPAddress: '1.2.3.4' },
        },
      ];

      const findings = (analyzer as any).detectRootAccountUsage(events);

      expect(findings).toHaveLength(0);
    });
  });

  describe('detectFailedAuthentication', () => {
    it('should detect multiple failed authentication attempts from same IP', () => {
      const events = Array.from({ length: 5 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
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

      const findings = (analyzer as any).detectFailedAuthentication(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.HIGH);
      expect(findings[0].title).toBe('Multiple Failed Authentication Attempts');
      expect(findings[0].evidence.details.attemptCount).toBe(5);
    });

    it('should not flag fewer than 5 attempts', () => {
      const events = Array.from({ length: 3 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
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

      const findings = (analyzer as any).detectFailedAuthentication(events);

      expect(findings).toHaveLength(0);
    });
  });

  describe('detectPrivilegeEscalation', () => {
    it('should detect privilege escalation attempts', () => {
      const events = [
        {
          id: '1',
          timestamp: new Date(),
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
          timestamp: new Date(),
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
          timestamp: new Date(),
          eventType: 'CreateAccessKey',
          source: 'iam.amazonaws.com',
          principal: 'attacker',
          resource: 'user/victim',
          action: 'CreateAccessKey',
          result: 'success',
          details: { awsRegion: 'us-east-1' },
        },
      ];

      const findings = (analyzer as any).detectPrivilegeEscalation(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.CRITICAL);
      expect(findings[0].title).toBe('Potential Privilege Escalation Detected');
    });
  });

  describe('detectUnusualAPICalls', () => {
    it('should detect dangerous API calls', () => {
      const events = [
        {
          id: '1',
          timestamp: new Date(),
          eventType: 'DeleteTrail',
          source: 'cloudtrail.amazonaws.com',
          principal: 'attacker',
          resource: 'trail/mytrail',
          action: 'DeleteTrail',
          result: 'success',
          details: { awsRegion: 'us-east-1', sourceIPAddress: '1.2.3.4' },
        },
      ];

      const findings = (analyzer as any).detectUnusualAPICalls(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.HIGH);
      expect(findings[0].title).toBe('Dangerous API Call Detected');
    });
  });

  describe('detectDataExfiltration', () => {
    it('should detect high volume data access', () => {
      const events = Array.from({ length: 100 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
        eventType: 'GetObject',
        source: 's3.amazonaws.com',
        principal: 'attacker',
        resource: 'bucket/mydata',
        action: 'GetObject',
        result: 'success',
        details: { awsRegion: 'us-east-1' },
      }));

      const findings = (analyzer as any).detectDataExfiltration(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.HIGH);
      expect(findings[0].title).toBe('Potential Data Exfiltration Detected');
    });

    it('should not flag normal data access', () => {
      const events = Array.from({ length: 50 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
        eventType: 'GetObject',
        source: 's3.amazonaws.com',
        principal: 'normaluser',
        resource: 'bucket/mydata',
        action: 'GetObject',
        result: 'success',
        details: { awsRegion: 'us-east-1' },
      }));

      const findings = (analyzer as any).detectDataExfiltration(events);

      expect(findings).toHaveLength(0);
    });
  });
});
