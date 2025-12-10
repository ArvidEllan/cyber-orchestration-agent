/**
 * AWS Organizations Auditor for account enumeration and SCP validation
 */

import {
  OrganizationsClient,
  ListAccountsCommand,
  DescribeOrganizationCommand,
  ListPoliciesCommand,
  DescribePolicyCommand,
  ListTargetsForPolicyCommand,
  PolicyType,
} from '@aws-sdk/client-organizations';
import {
  AWSAccount,
  OrganizationAudit,
  ServiceControlPolicy,
  AWSCredentials,
} from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class OrganizationsAuditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * List all accounts in the organization
   */
  async listAccounts(): Promise<AWSAccount[]> {
    try {
      const orgClient = this.awsClient.getServiceClient(OrganizationsClient, 'us-east-1');
      const accounts: AWSAccount[] = [];
      let nextToken: string | undefined;

      do {
        const command = new ListAccountsCommand({
          NextToken: nextToken,
        });

        const response = await orgClient.send(command);

        if (response.Accounts) {
          accounts.push(
            ...response.Accounts.map(account => ({
              id: account.Id || '',
              name: account.Name || '',
              email: account.Email || '',
              status: account.Status || '',
            }))
          );
        }

        nextToken = response.NextToken;
      } while (nextToken);

      return accounts;
    } catch (error: any) {
      // If Organizations is not enabled or accessible, return current account only
      if (error.name === 'AWSOrganizationsNotInUseException' || 
          error.name === 'AccessDeniedException') {
        return await this.getCurrentAccountAsSingleAccount();
      }

      throw new SecurityAgentError(
        `Failed to list accounts: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { error: error.message }
      );
    }
  }

  /**
   * Get current account as a single-account list (fallback when Organizations not available)
   */
  private async getCurrentAccountAsSingleAccount(): Promise<AWSAccount[]> {
    const identity = await this.awsClient.getCallerIdentity();
    return [
      {
        id: identity.account,
        name: 'Current Account',
        email: '',
        status: 'ACTIVE',
      },
    ];
  }

  /**
   * Audit the organization structure and policies
   */
  async auditOrganization(): Promise<OrganizationAudit> {
    try {
      const orgClient = this.awsClient.getServiceClient(OrganizationsClient, 'us-east-1');

      // Get organization details
      const describeCommand = new DescribeOrganizationCommand({});
      const orgResponse = await orgClient.send(describeCommand);

      const organizationId = orgResponse.Organization?.Id || '';

      // List all accounts
      const accounts = await this.listAccounts();

      // List and describe SCPs
      const scps = await this.listServiceControlPolicies(orgClient);

      return {
        organizationId,
        accounts,
        scps,
      };
    } catch (error: any) {
      // If Organizations is not enabled, return minimal audit
      if (error.name === 'AWSOrganizationsNotInUseException' || 
          error.name === 'AccessDeniedException') {
        const accounts = await this.getCurrentAccountAsSingleAccount();
        return {
          organizationId: '',
          accounts,
          scps: [],
        };
      }

      throw new SecurityAgentError(
        `Failed to audit organization: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { error: error.message }
      );
    }
  }

  /**
   * List all Service Control Policies
   */
  private async listServiceControlPolicies(orgClient: OrganizationsClient): Promise<ServiceControlPolicy[]> {
    try {
      const scps: ServiceControlPolicy[] = [];
      let nextToken: string | undefined;

      do {
        const listCommand = new ListPoliciesCommand({
          Filter: PolicyType.SERVICE_CONTROL_POLICY,
          NextToken: nextToken,
        });

        const response = await orgClient.send(listCommand);

        if (response.Policies) {
          for (const policy of response.Policies) {
            if (policy.Id) {
              const scpDetails = await this.getServiceControlPolicyDetails(orgClient, policy.Id);
              if (scpDetails) {
                scps.push(scpDetails);
              }
            }
          }
        }

        nextToken = response.NextToken;
      } while (nextToken);

      return scps;
    } catch (error) {
      // Return empty array if SCPs cannot be listed
      return [];
    }
  }

  /**
   * Get detailed information about a specific SCP
   */
  private async getServiceControlPolicyDetails(
    orgClient: OrganizationsClient,
    policyId: string
  ): Promise<ServiceControlPolicy | null> {
    try {
      const describeCommand = new DescribePolicyCommand({
        PolicyId: policyId,
      });

      const response = await orgClient.send(describeCommand);

      if (!response.Policy) {
        return null;
      }

      // Get targets for this policy
      const targets = await this.listPolicyTargets(orgClient, policyId);

      return {
        id: response.Policy.PolicySummary?.Id || '',
        name: response.Policy.PolicySummary?.Name || '',
        content: response.Policy.Content ? JSON.parse(response.Policy.Content) : {},
        targets,
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * List targets (accounts/OUs) for a policy
   */
  private async listPolicyTargets(orgClient: OrganizationsClient, policyId: string): Promise<string[]> {
    try {
      const targets: string[] = [];
      let nextToken: string | undefined;

      do {
        const command = new ListTargetsForPolicyCommand({
          PolicyId: policyId,
          NextToken: nextToken,
        });

        const response = await orgClient.send(command);

        if (response.Targets) {
          targets.push(...response.Targets.map(t => t.TargetId || '').filter(Boolean));
        }

        nextToken = response.NextToken;
      } while (nextToken);

      return targets;
    } catch (error) {
      return [];
    }
  }

  /**
   * Assume role in a different account for cross-account access
   */
  async assumeRoleInAccount(accountId: string, roleName: string): Promise<AWSCredentials> {
    const roleArn = `arn:aws:iam::${accountId}:role/${roleName}`;
    return await this.awsClient.assumeRole(roleArn, `InfraSecurityAgent-${accountId}`);
  }

  /**
   * Validate SCP configuration against best practices
   */
  validateServiceControlPolicies(scps: ServiceControlPolicy[]): {
    valid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    if (scps.length === 0) {
      issues.push('No Service Control Policies found. Consider implementing SCPs for guardrails.');
    }

    scps.forEach(scp => {
      // Check for overly permissive SCPs
      if (this.isOverlyPermissive(scp.content)) {
        issues.push(`SCP "${scp.name}" (${scp.id}) appears to be overly permissive`);
      }

      // Check if SCP has targets
      if (scp.targets.length === 0) {
        issues.push(`SCP "${scp.name}" (${scp.id}) has no targets attached`);
      }

      // Check for required deny statements
      if (!this.hasRequiredDenyStatements(scp.content)) {
        issues.push(`SCP "${scp.name}" (${scp.id}) is missing recommended deny statements`);
      }
    });

    return {
      valid: issues.length === 0,
      issues,
    };
  }

  /**
   * Check if SCP is overly permissive
   */
  private isOverlyPermissive(policyContent: Record<string, any>): boolean {
    if (!policyContent.Statement || !Array.isArray(policyContent.Statement)) {
      return false;
    }

    // Check for statements that allow all actions
    return policyContent.Statement.some((statement: any) => {
      return (
        statement.Effect === 'Allow' &&
        (statement.Action === '*' || (Array.isArray(statement.Action) && statement.Action.includes('*'))) &&
        (statement.Resource === '*' || (Array.isArray(statement.Resource) && statement.Resource.includes('*')))
      );
    });
  }

  /**
   * Check if SCP has required deny statements for security
   */
  private hasRequiredDenyStatements(policyContent: Record<string, any>): boolean {
    if (!policyContent.Statement || !Array.isArray(policyContent.Statement)) {
      return false;
    }

    const denyStatements = policyContent.Statement.filter((s: any) => s.Effect === 'Deny');

    // Check for common security deny patterns
    const hasRegionRestriction = denyStatements.some((s: any) => 
      s.Condition && s.Condition.StringNotEquals && s.Condition.StringNotEquals['aws:RequestedRegion']
    );

    const hasRootAccountProtection = denyStatements.some((s: any) =>
      JSON.stringify(s).includes('root')
    );

    // At least one recommended deny statement should be present
    return hasRegionRestriction || hasRootAccountProtection || denyStatements.length > 0;
  }
}
