/**
 * Tests for OrganizationsAuditor
 */

import { describe, it, expect } from 'vitest';
import { OrganizationsAuditor } from '../organizations-auditor';
import { AWSClient } from '../aws-client';

describe('OrganizationsAuditor', () => {
  const awsClient = new AWSClient();
  const organizationsAuditor = new OrganizationsAuditor(awsClient);

  it('should validate overly permissive SCPs', () => {
    const scps = [
      {
        id: 'scp-1',
        name: 'FullAccess',
        content: {
          Statement: [
            {
              Effect: 'Allow',
              Action: '*',
              Resource: '*',
            },
          ],
        },
        targets: ['ou-123'],
      },
    ];

    const validation = organizationsAuditor.validateServiceControlPolicies(scps);

    expect(validation.valid).toBe(false);
    expect(validation.issues.length).toBeGreaterThan(0);
    expect(validation.issues.some(issue => issue.includes('overly permissive'))).toBe(true);
  });

  it('should detect SCPs without targets', () => {
    const scps = [
      {
        id: 'scp-1',
        name: 'TestPolicy',
        content: {
          Statement: [
            {
              Effect: 'Deny',
              Action: 's3:*',
              Resource: '*',
            },
          ],
        },
        targets: [],
      },
    ];

    const validation = organizationsAuditor.validateServiceControlPolicies(scps);

    expect(validation.valid).toBe(false);
    expect(validation.issues.some(issue => issue.includes('no targets'))).toBe(true);
  });

  it('should validate SCPs with deny statements', () => {
    const scps = [
      {
        id: 'scp-1',
        name: 'RegionRestriction',
        content: {
          Statement: [
            {
              Effect: 'Deny',
              Action: '*',
              Resource: '*',
              Condition: {
                StringNotEquals: {
                  'aws:RequestedRegion': ['us-east-1', 'us-west-2'],
                },
              },
            },
          ],
        },
        targets: ['ou-123'],
      },
    ];

    const validation = organizationsAuditor.validateServiceControlPolicies(scps);

    expect(validation.valid).toBe(true);
    expect(validation.issues).toHaveLength(0);
  });

  it('should warn when no SCPs are found', () => {
    const scps: any[] = [];

    const validation = organizationsAuditor.validateServiceControlPolicies(scps);

    expect(validation.valid).toBe(false);
    expect(validation.issues.some(issue => issue.includes('No Service Control Policies'))).toBe(true);
  });
});
