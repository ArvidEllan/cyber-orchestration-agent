/**
 * IAM Auditor for users, roles, policies, and access keys
 */

import {
  IAMClient,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListRolesCommand,
  ListAttachedRolePoliciesCommand,
  ListPoliciesCommand,
  GetPolicyCommand,
  GetPolicyVersionCommand,
  GetUserCommand,
} from '@aws-sdk/client-iam';
import {
  Resource,
  ResourceSource,
  IAMUser,
  IAMRole,
  IAMPolicy,
  AccessKey,
  IdentityAudit,
} from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class IAMAuditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit IAM resources in an account
   */
  async auditIdentity(accountId: string, region: string = 'us-east-1'): Promise<IdentityAudit> {
    try {
      const iamClient = this.awsClient.getServiceClient(IAMClient, region);

      const [users, roles, policies] = await Promise.all([
        this.listUsers(iamClient),
        this.listRoles(iamClient),
        this.listPolicies(iamClient),
      ]);

      return {
        users,
        roles,
        policies,
      };
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit IAM: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId, region }
      );
    }
  }

  /**
   * List all IAM users with their access keys
   */
  private async listUsers(iamClient: IAMClient): Promise<IAMUser[]> {
    const users: IAMUser[] = [];
    let marker: string | undefined;

    do {
      const command = new ListUsersCommand({ Marker: marker });
      const response = await iamClient.send(command);

      if (response.Users) {
        for (const user of response.Users) {
          if (user.UserName) {
            const accessKeys = await this.listAccessKeys(iamClient, user.UserName);
            
            // Get password last used
            let passwordLastUsed: Date | undefined;
            try {
              const getUserCommand = new GetUserCommand({ UserName: user.UserName });
              const userDetails = await iamClient.send(getUserCommand);
              passwordLastUsed = userDetails.User?.PasswordLastUsed;
            } catch (error) {
              // Ignore errors getting password last used
            }

            users.push({
              userName: user.UserName,
              userId: user.UserId || '',
              arn: user.Arn || '',
              createDate: user.CreateDate || new Date(),
              passwordLastUsed,
              accessKeys,
            });
          }
        }
      }

      marker = response.Marker;
    } while (marker);

    return users;
  }

  /**
   * List access keys for a user
   */
  private async listAccessKeys(iamClient: IAMClient, userName: string): Promise<AccessKey[]> {
    try {
      const command = new ListAccessKeysCommand({ UserName: userName });
      const response = await iamClient.send(command);

      if (!response.AccessKeyMetadata) {
        return [];
      }

      const accessKeys: AccessKey[] = [];

      for (const keyMetadata of response.AccessKeyMetadata) {
        if (keyMetadata.AccessKeyId) {
          let lastUsedDate: Date | undefined;

          try {
            const lastUsedCommand = new GetAccessKeyLastUsedCommand({
              AccessKeyId: keyMetadata.AccessKeyId,
            });
            const lastUsedResponse = await iamClient.send(lastUsedCommand);
            lastUsedDate = lastUsedResponse.AccessKeyLastUsed?.LastUsedDate;
          } catch (error) {
            // Ignore errors getting last used date
          }

          accessKeys.push({
            accessKeyId: keyMetadata.AccessKeyId,
            status: keyMetadata.Status || '',
            createDate: keyMetadata.CreateDate || new Date(),
            lastUsedDate,
          });
        }
      }

      return accessKeys;
    } catch (error) {
      return [];
    }
  }

  /**
   * List all IAM roles
   */
  private async listRoles(iamClient: IAMClient): Promise<IAMRole[]> {
    const roles: IAMRole[] = [];
    let marker: string | undefined;

    do {
      const command = new ListRolesCommand({ Marker: marker });
      const response = await iamClient.send(command);

      if (response.Roles) {
        for (const role of response.Roles) {
          if (role.RoleName) {
            const attachedPolicies = await this.listAttachedRolePolicies(iamClient, role.RoleName);

            roles.push({
              roleName: role.RoleName,
              roleId: role.RoleId || '',
              arn: role.Arn || '',
              assumeRolePolicyDocument: role.AssumeRolePolicyDocument
                ? JSON.parse(decodeURIComponent(role.AssumeRolePolicyDocument))
                : {},
              attachedPolicies,
            });
          }
        }
      }

      marker = response.Marker;
    } while (marker);

    return roles;
  }

  /**
   * List attached policies for a role
   */
  private async listAttachedRolePolicies(iamClient: IAMClient, roleName: string): Promise<string[]> {
    try {
      const command = new ListAttachedRolePoliciesCommand({ RoleName: roleName });
      const response = await iamClient.send(command);

      return response.AttachedPolicies?.map(p => p.PolicyArn || '').filter(Boolean) || [];
    } catch (error) {
      return [];
    }
  }

  /**
   * List customer-managed IAM policies
   */
  private async listPolicies(iamClient: IAMClient): Promise<IAMPolicy[]> {
    const policies: IAMPolicy[] = [];
    let marker: string | undefined;

    do {
      const command = new ListPoliciesCommand({
        Scope: 'Local', // Only customer-managed policies
        Marker: marker,
      });
      const response = await iamClient.send(command);

      if (response.Policies) {
        for (const policy of response.Policies) {
          if (policy.Arn) {
            const policyDocument = await this.getPolicyDocument(iamClient, policy.Arn);

            policies.push({
              policyName: policy.PolicyName || '',
              policyId: policy.PolicyId || '',
              arn: policy.Arn,
              document: policyDocument,
            });
          }
        }
      }

      marker = response.Marker;
    } while (marker);

    return policies;
  }

  /**
   * Get policy document for a policy
   */
  private async getPolicyDocument(iamClient: IAMClient, policyArn: string): Promise<Record<string, any>> {
    try {
      const getPolicyCommand = new GetPolicyCommand({ PolicyArn: policyArn });
      const policyResponse = await iamClient.send(getPolicyCommand);

      if (!policyResponse.Policy?.DefaultVersionId) {
        return {};
      }

      const getVersionCommand = new GetPolicyVersionCommand({
        PolicyArn: policyArn,
        VersionId: policyResponse.Policy.DefaultVersionId,
      });
      const versionResponse = await iamClient.send(getVersionCommand);

      if (versionResponse.PolicyVersion?.Document) {
        return JSON.parse(decodeURIComponent(versionResponse.PolicyVersion.Document));
      }

      return {};
    } catch (error) {
      return {};
    }
  }

  /**
   * Convert IAM resources to Resource format
   */
  convertToResources(identityAudit: IdentityAudit, accountId: string, region: string): Resource[] {
    const resources: Resource[] = [];
    const timestamp = new Date();

    // Convert users
    identityAudit.users.forEach(user => {
      resources.push({
        id: user.arn,
        type: 'AWS::IAM::User',
        service: 'iam',
        region,
        account: accountId,
        properties: {
          userName: user.userName,
          userId: user.userId,
          createDate: user.createDate,
          passwordLastUsed: user.passwordLastUsed,
          accessKeys: user.accessKeys,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp,
      });
    });

    // Convert roles
    identityAudit.roles.forEach(role => {
      resources.push({
        id: role.arn,
        type: 'AWS::IAM::Role',
        service: 'iam',
        region,
        account: accountId,
        properties: {
          roleName: role.roleName,
          roleId: role.roleId,
          assumeRolePolicyDocument: role.assumeRolePolicyDocument,
          attachedPolicies: role.attachedPolicies,
        },
        tags: {},
        relationships: role.attachedPolicies.map(policyArn => ({
          type: 'ATTACHED_POLICY',
          targetId: policyArn,
        })),
        source: ResourceSource.LIVE,
        timestamp,
      });
    });

    // Convert policies
    identityAudit.policies.forEach(policy => {
      resources.push({
        id: policy.arn,
        type: 'AWS::IAM::Policy',
        service: 'iam',
        region,
        account: accountId,
        properties: {
          policyName: policy.policyName,
          policyId: policy.policyId,
          document: policy.document,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp,
      });
    });

    return resources;
  }
}
