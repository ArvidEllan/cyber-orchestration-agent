/**
 * Tests for VPC Flow Log Analyzer
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { VPCFlowLogAnalyzer } from '../vpc-flow-analyzer';
import { Severity } from '../../types';

describe('VPCFlowLogAnalyzer', () => {
  let analyzer: VPCFlowLogAnalyzer;

  beforeEach(() => {
    analyzer = new VPCFlowLogAnalyzer('us-east-1');
  });

  describe('parseFlowLogLine', () => {
    it('should parse valid VPC flow log line', () => {
      const line =
        '2 123456789012 eni-1234567890abcdef0 192.168.1.1 10.0.0.1 443 80 6 10 5000 1234567890 1234567900 ACCEPT OK';

      const record = (analyzer as any).parseFlowLogLine(line);

      expect(record).toBeDefined();
      expect(record?.version).toBe(2);
      expect(record?.accountId).toBe('123456789012');
      expect(record?.interfaceId).toBe('eni-1234567890abcdef0');
      expect(record?.srcAddr).toBe('192.168.1.1');
      expect(record?.dstAddr).toBe('10.0.0.1');
      expect(record?.srcPort).toBe(443);
      expect(record?.dstPort).toBe(80);
      expect(record?.protocol).toBe(6);
      expect(record?.packets).toBe(10);
      expect(record?.bytes).toBe(5000);
      expect(record?.action).toBe('ACCEPT');
    });

    it('should return null for invalid line', () => {
      const line = 'invalid line';

      const record = (analyzer as any).parseFlowLogLine(line);

      expect(record).toBeNull();
    });
  });

  describe('normalizeRecord', () => {
    it('should normalize VPC flow log record to SecurityEvent', () => {
      const record = {
        version: 2,
        accountId: '123456789012',
        interfaceId: 'eni-1234567890abcdef0',
        srcAddr: '192.168.1.1',
        dstAddr: '10.0.0.1',
        srcPort: 443,
        dstPort: 80,
        protocol: 6,
        packets: 10,
        bytes: 5000,
        start: 1234567890,
        end: 1234567900,
        action: 'ACCEPT' as const,
        logStatus: 'OK',
      };

      const event = analyzer.normalizeRecord(record);

      expect(event.source).toBe('192.168.1.1');
      expect(event.principal).toBe('123456789012');
      expect(event.resource).toBe('eni-1234567890abcdef0');
      expect(event.action).toBe('ACCEPT');
      expect(event.result).toBe('success');
      expect(event.details.srcAddr).toBe('192.168.1.1');
      expect(event.details.dstAddr).toBe('10.0.0.1');
    });

    it('should mark rejected connections as failure', () => {
      const record = {
        version: 2,
        accountId: '123456789012',
        interfaceId: 'eni-1234567890abcdef0',
        srcAddr: '192.168.1.1',
        dstAddr: '10.0.0.1',
        srcPort: 443,
        dstPort: 80,
        protocol: 6,
        packets: 0,
        bytes: 0,
        start: 1234567890,
        end: 1234567900,
        action: 'REJECT' as const,
        logStatus: 'OK',
      };

      const event = analyzer.normalizeRecord(record);

      expect(event.result).toBe('failure');
    });
  });

  describe('detectPortScanning', () => {
    it('should detect port scanning activity', () => {
      const events = Array.from({ length: 50 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
        eventType: 'NetworkTraffic',
        source: '1.2.3.4',
        principal: '123456789012',
        resource: 'eni-123',
        action: 'REJECT',
        result: 'failure',
        details: {
          srcAddr: '1.2.3.4',
          dstAddr: '10.0.0.1',
          srcPort: 50000 + i,
          dstPort: 1000 + i, // Different ports
          protocol: 6,
          packets: 1,
          bytes: 40,
          interfaceId: 'eni-123',
        },
      }));

      const findings = (analyzer as any).detectPortScanning(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.HIGH);
      expect(findings[0].title).toBe('Port Scanning Detected');
    });

    it('should not flag normal traffic', () => {
      const events = Array.from({ length: 10 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
        eventType: 'NetworkTraffic',
        source: '1.2.3.4',
        principal: '123456789012',
        resource: 'eni-123',
        action: 'ACCEPT',
        result: 'success',
        details: {
          srcAddr: '1.2.3.4',
          dstAddr: '10.0.0.1',
          srcPort: 50000,
          dstPort: 443, // Same port
          protocol: 6,
          packets: 10,
          bytes: 5000,
          interfaceId: 'eni-123',
        },
      }));

      const findings = (analyzer as any).detectPortScanning(events);

      expect(findings).toHaveLength(0);
    });
  });

  describe('detectDDoS', () => {
    it('should detect DDoS patterns', () => {
      const events = Array.from({ length: 1000 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
        eventType: 'NetworkTraffic',
        source: `1.2.3.${i % 100}`, // 100 unique sources
        principal: '123456789012',
        resource: 'eni-123',
        action: 'ACCEPT',
        result: 'success',
        details: {
          srcAddr: `1.2.3.${i % 100}`,
          dstAddr: '10.0.0.1',
          srcPort: 50000 + i,
          dstPort: 80,
          protocol: 6,
          packets: 1,
          bytes: 100,
          interfaceId: 'eni-123',
        },
      }));

      const findings = (analyzer as any).detectDDoS(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.CRITICAL);
      expect(findings[0].title).toBe('Potential DDoS Attack Detected');
    });
  });

  describe('detectDataExfiltration', () => {
    it('should detect high volume data transfer', () => {
      const events = Array.from({ length: 100 }, (_, i) => ({
        id: `${i}`,
        timestamp: new Date(),
        eventType: 'NetworkTraffic',
        source: '10.0.0.1',
        principal: '123456789012',
        resource: 'eni-123',
        action: 'ACCEPT',
        result: 'success',
        details: {
          srcAddr: '10.0.0.1',
          dstAddr: '1.2.3.4',
          srcPort: 443,
          dstPort: 50000 + i,
          protocol: 6,
          packets: 1000,
          bytes: 200 * 1024 * 1024, // 200 MB per connection
          interfaceId: 'eni-123',
        },
      }));

      const findings = (analyzer as any).detectDataExfiltration(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.HIGH);
      expect(findings[0].title).toBe('High Volume Data Transfer Detected');
    });
  });

  describe('detectSuspiciousConnections', () => {
    it('should detect external SSH connections', () => {
      const events = [
        {
          id: '1',
          timestamp: new Date(),
          eventType: 'NetworkTraffic',
          source: '1.2.3.4', // External IP
          principal: '123456789012',
          resource: 'eni-123',
          action: 'ACCEPT',
          result: 'success',
          details: {
            srcAddr: '1.2.3.4',
            dstAddr: '10.0.0.1',
            srcPort: 50000,
            dstPort: 22, // SSH
            protocol: 6,
            packets: 10,
            bytes: 5000,
            interfaceId: 'eni-123',
          },
        },
      ];

      const findings = (analyzer as any).detectSuspiciousConnections(events);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe(Severity.MEDIUM);
      expect(findings[0].title).toBe('Suspicious External Connection Detected');
    });

    it('should not flag internal connections', () => {
      const events = [
        {
          id: '1',
          timestamp: new Date(),
          eventType: 'NetworkTraffic',
          source: '10.0.0.2', // Internal IP
          principal: '123456789012',
          resource: 'eni-123',
          action: 'ACCEPT',
          result: 'success',
          details: {
            srcAddr: '10.0.0.2',
            dstAddr: '10.0.0.1',
            srcPort: 50000,
            dstPort: 22,
            protocol: 6,
            packets: 10,
            bytes: 5000,
            interfaceId: 'eni-123',
          },
        },
      ];

      const findings = (analyzer as any).detectSuspiciousConnections(events);

      expect(findings).toHaveLength(0);
    });
  });

  describe('isPrivateIP', () => {
    it('should identify private IPs', () => {
      expect((analyzer as any).isPrivateIP('10.0.0.1')).toBe(true);
      expect((analyzer as any).isPrivateIP('172.16.0.1')).toBe(true);
      expect((analyzer as any).isPrivateIP('192.168.1.1')).toBe(true);
    });

    it('should identify public IPs', () => {
      expect((analyzer as any).isPrivateIP('1.2.3.4')).toBe(false);
      expect((analyzer as any).isPrivateIP('8.8.8.8')).toBe(false);
    });
  });
});
