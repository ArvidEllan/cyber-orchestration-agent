/**
 * Main AWS Auditor implementation
 */

import {
  AWSAuditor,
  AWSCredentials,
  AWSAccount,
  AccountAudit,
  ServiceAudit,
  DriftReport,
  Resource,
} from '../types';
import { AWSClient } from './aws-client';
import { OrganizationsAuditor } from './organizations-auditor';
import { DriftDetector } from './drift-detector';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class AWSAuditorImpl implements AWSAuditor {
  private awsClient: AWSClient;
  private organizationsAuditor: OrganizationsAuditor;
  private driftDetector: DriftDetector;

  constructor() {
    this.awsClient = new AWSClient();
    this.organizationsAuditor = new OrganizationsAuditor(this.awsClient);
    this.driftDetector = new DriftDetector();
  }

  /**
   * Connect to AWS using provided credentials
   */
  async connect(credentials: AWSCredentials): Promise<void> {
    await this.awsClient.connect(credentials);
  }

  /**
   * List all accounts in the organization
   */
  async listAccounts(): Promise<AWSAccount[]> {
    if (!this.awsClient.isConnected()) {
      throw new SecurityAgentError(
        'AWS client not connected. Call connect() first.',
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        false
      );
    }

    return await this.organizationsAuditor.listAccounts();
  }

  /**
   * Audit a specific AWS account
   */
  async auditAccount(_accountId: string): Promise<AccountAudit> {
    if (!this.awsClient.isConnected()) {
      throw new SecurityAgentError(
        'AWS client not connected. Call connect() first.',
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        false
      );
    }

    // This will be implemented in subsequent subtasks
    throw new Error('auditAccount not yet implemented');
  }

  /**
   * Audit a specific service in an account
   */
  async auditService(_accountId: string, _service: string): Promise<ServiceAudit> {
    if (!this.awsClient.isConnected()) {
      throw new SecurityAgentError(
        'AWS client not connected. Call connect() first.',
        ErrorCode.AWS_AUTH_ERROR,
        ErrorCategory.API,
        false
      );
    }

    // This will be implemented in subsequent subtasks
    throw new Error('auditService not yet implemented');
  }

  /**
   * Detect drift between IaC resources and live AWS resources
   */
  detectDrift(iacResources: Resource[], liveResources: Resource[]): DriftReport {
    return this.driftDetector.detectDrift(iacResources, liveResources);
  }

  /**
   * Get the underlying AWS client
   */
  getClient(): AWSClient {
    return this.awsClient;
  }
}
