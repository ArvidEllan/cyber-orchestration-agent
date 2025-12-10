/**
 * Tests for SecurityServicesAuditor
 */

import { describe, it, expect } from 'vitest';
import { SecurityServicesAuditor } from '../security-services-auditor';
import { AWSClient } from '../aws-client';
import { SecurityServicesAudit } from '../../types';

describe('SecurityServicesAuditor', () => {
  const awsClient = new AWSClient();
  const securityServicesAuditor = new SecurityServicesAuditor(awsClient);

  it('should validate when all security services are enabled', () => {
    const audit: SecurityServicesAudit = {
      cloudTrail: {
        enabled: true,
        trails: [
          {
            name: 'main-trail',
            s3BucketName: 'cloudtrail-bucket',
            isMultiRegionTrail: true,
            logFileValidationEnabled: true,
          },
        ],
      },
      config: {
        enabled: true,
        recorders: [
          {
            name: 'default',
            roleArn: 'arn:aws:iam::123456789012:role/ConfigRole',
            recordingGroup: {},
          },
        ],
      },
      securityHub: {
        enabled: true,
        standards: [
          {
            standardsArn: 'arn:aws:securityhub:us-east-1::standards/cis-aws-foundations-benchmark/v/1.2.0',
            enabled: true,
          },
        ],
      },
      guardDuty: {
        enabled: true,
        detectorId: 'detector-123',
      },
    };

    const validation = securityServicesAuditor.validateSecurityServices(audit, 'us-east-1');

    expect(validation.valid).toBe(true);
    expect(validation.issues).toHaveLength(0);
  });

  it('should detect when CloudTrail is not enabled', () => {
    const audit: SecurityServicesAudit = {
      cloudTrail: {
        enabled: false,
        trails: [],
      },
      config: {
        enabled: true,
        recorders: [],
      },
      securityHub: {
        enabled: true,
        standards: [],
      },
      guardDuty: {
        enabled: true,
      },
    };

    const validation = securityServicesAuditor.validateSecurityServices(audit, 'us-east-1');

    expect(validation.valid).toBe(false);
    expect(validation.issues.some(issue => issue.includes('CloudTrail is not enabled'))).toBe(true);
  });

  it('should detect when multi-region trail is missing', () => {
    const audit: SecurityServicesAudit = {
      cloudTrail: {
        enabled: true,
        trails: [
          {
            name: 'single-region-trail',
            s3BucketName: 'cloudtrail-bucket',
            isMultiRegionTrail: false,
            logFileValidationEnabled: true,
          },
        ],
      },
      config: {
        enabled: true,
        recorders: [],
      },
      securityHub: {
        enabled: true,
        standards: [],
      },
      guardDuty: {
        enabled: true,
      },
    };

    const validation = securityServicesAuditor.validateSecurityServices(audit, 'us-east-1');

    expect(validation.valid).toBe(false);
    expect(validation.issues.some(issue => issue.includes('No multi-region CloudTrail'))).toBe(true);
  });

  it('should detect when Security Hub has no standards', () => {
    const audit: SecurityServicesAudit = {
      cloudTrail: {
        enabled: true,
        trails: [
          {
            name: 'main-trail',
            s3BucketName: 'cloudtrail-bucket',
            isMultiRegionTrail: true,
            logFileValidationEnabled: true,
          },
        ],
      },
      config: {
        enabled: true,
        recorders: [],
      },
      securityHub: {
        enabled: true,
        standards: [],
      },
      guardDuty: {
        enabled: true,
      },
    };

    const validation = securityServicesAuditor.validateSecurityServices(audit, 'us-east-1');

    expect(validation.valid).toBe(false);
    expect(validation.issues.some(issue => issue.includes('no standards are active'))).toBe(true);
  });

  it('should detect when GuardDuty is not enabled', () => {
    const audit: SecurityServicesAudit = {
      cloudTrail: {
        enabled: true,
        trails: [
          {
            name: 'main-trail',
            s3BucketName: 'cloudtrail-bucket',
            isMultiRegionTrail: true,
            logFileValidationEnabled: true,
          },
        ],
      },
      config: {
        enabled: true,
        recorders: [],
      },
      securityHub: {
        enabled: true,
        standards: [],
      },
      guardDuty: {
        enabled: false,
      },
    };

    const validation = securityServicesAuditor.validateSecurityServices(audit, 'us-east-1');

    expect(validation.valid).toBe(false);
    expect(validation.issues.some(issue => issue.includes('GuardDuty is not enabled'))).toBe(true);
  });
});
