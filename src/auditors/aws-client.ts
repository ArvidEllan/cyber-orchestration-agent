/**
 * AWS Client wrapper for credential management and SDK integration
 */

import { STSClient, GetCallerIdentityCommand, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { EC2Client, DescribeRegionsCommand } from '@aws-sdk/client-ec2';
import { fromEnv, fromIni } from '@aws-sdk/credential-providers';
import { AWSCredentials } from '../types';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class AWSClient {
  private stsClient: STSClient | null = null;
  private credentials: AWSCredentials | null = null;
  private regions: string[] = [];

  /**
   * Connect to AWS using provided credentials
   */
  async connect(credentials: AWSCredentials): Promise<void> {
    this.credentials = credentials;

    try {
      // Create STS client with appropriate credential provider
      const credentialProvider = this.getCredentialProvider(credentials);
      
      this.stsClient = new STSClient({
        credentials: credentialProvider,
      });

      // Verify credentials by calling GetCallerIdentity
      const command = new GetCallerIdentityCommand({});
      await this.stsClient.send(command);
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to connect to AWS: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        false,
        { credentials: this.sanitizeCredentials(credentials) }
      );
    }
  }

  /**
   * Get credential provider based on provided credentials
   */
  private getCredentialProvider(credentials: AWSCredentials) {
    // Priority: explicit credentials > profile > environment variables
    if (credentials.accessKeyId && credentials.secretAccessKey) {
      return {
        accessKeyId: credentials.accessKeyId,
        secretAccessKey: credentials.secretAccessKey,
        sessionToken: credentials.sessionToken,
      };
    }

    if (credentials.profile) {
      return fromIni({ profile: credentials.profile });
    }

    // Default to environment variables
    return fromEnv();
  }

  /**
   * Assume a role and return temporary credentials
   */
  async assumeRole(roleArn: string, sessionName: string = 'InfraSecurityAgent'): Promise<AWSCredentials> {
    if (!this.stsClient) {
      throw new SecurityAgentError(
        'AWS client not connected. Call connect() first.',
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        false
      );
    }

    try {
      const command = new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName: sessionName,
        DurationSeconds: 3600, // 1 hour
      });

      const response = await this.stsClient.send(command);

      if (!response.Credentials) {
        throw new Error('No credentials returned from AssumeRole');
      }

      return {
        accessKeyId: response.Credentials.AccessKeyId,
        secretAccessKey: response.Credentials.SecretAccessKey,
        sessionToken: response.Credentials.SessionToken,
      };
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to assume role ${roleArn}: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        true,
        { roleArn }
      );
    }
  }

  /**
   * Get caller identity information
   */
  async getCallerIdentity(): Promise<{ account: string; arn: string; userId: string }> {
    if (!this.stsClient) {
      throw new SecurityAgentError(
        'AWS client not connected. Call connect() first.',
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        false
      );
    }

    try {
      const command = new GetCallerIdentityCommand({});
      const response = await this.stsClient.send(command);

      return {
        account: response.Account || '',
        arn: response.Arn || '',
        userId: response.UserId || '',
      };
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to get caller identity: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true
      );
    }
  }

  /**
   * Enumerate all available AWS regions
   */
  async enumerateRegions(): Promise<string[]> {
    if (this.regions.length > 0) {
      return this.regions;
    }

    try {
      const credentialProvider = this.credentials 
        ? this.getCredentialProvider(this.credentials)
        : fromEnv();

      const ec2Client = new EC2Client({
        region: 'us-east-1', // Use us-east-1 to enumerate all regions
        credentials: credentialProvider,
      });

      const command = new DescribeRegionsCommand({
        AllRegions: false, // Only enabled regions
      });

      const response = await ec2Client.send(command);
      this.regions = response.Regions?.map(r => r.RegionName || '').filter(Boolean) || [];

      return this.regions;
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to enumerate regions: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true
      );
    }
  }

  /**
   * Get regions to audit based on configuration
   */
  async getRegionsToAudit(requestedRegions?: string[]): Promise<string[]> {
    const allRegions = await this.enumerateRegions();

    if (!requestedRegions || requestedRegions.length === 0) {
      return allRegions;
    }

    // Validate requested regions
    const invalidRegions = requestedRegions.filter(r => !allRegions.includes(r));
    if (invalidRegions.length > 0) {
      throw new SecurityAgentError(
        `Invalid regions specified: ${invalidRegions.join(', ')}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.INPUT,
        false,
        { invalidRegions, availableRegions: allRegions }
      );
    }

    return requestedRegions;
  }

  /**
   * Create a service client with current credentials
   */
  getServiceClient<T>(ClientClass: new (config: any) => T, region: string): T {
    if (!this.credentials) {
      throw new SecurityAgentError(
        'AWS client not connected. Call connect() first.',
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        false
      );
    }

    const credentialProvider = this.getCredentialProvider(this.credentials);

    return new ClientClass({
      region,
      credentials: credentialProvider,
    });
  }

  /**
   * Sanitize credentials for logging (remove sensitive data)
   */
  private sanitizeCredentials(credentials: AWSCredentials): Partial<AWSCredentials> {
    return {
      profile: credentials.profile,
      roleArn: credentials.roleArn,
      accessKeyId: credentials.accessKeyId ? '***' : undefined,
    };
  }

  /**
   * Check if client is connected
   */
  isConnected(): boolean {
    return this.stsClient !== null;
  }
}
