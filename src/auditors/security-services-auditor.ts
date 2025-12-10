/**
 * Security Services Auditor for CloudTrail, Config, Security Hub, and GuardDuty
 */

import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
  GetEventSelectorsCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand,
} from '@aws-sdk/client-config-service';
import {
  SecurityHubClient,
  DescribeHubCommand,
  GetEnabledStandardsCommand,
} from '@aws-sdk/client-securityhub';
import {
  GuardDutyClient,
  ListDetectorsCommand,
  GetDetectorCommand,
} from '@aws-sdk/client-guardduty';
import {
  SecurityServicesAudit,
  CloudTrailStatus,
  ConfigStatus,
  SecurityHubStatus,
  GuardDutyStatus,
  Trail,
  ConfigRecorder,
  Standard,
} from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class SecurityServicesAuditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit security services in a region
   */
  async auditSecurityServices(accountId: string, region: string): Promise<SecurityServicesAudit> {
    try {
      const [cloudTrail, config, securityHub, guardDuty] = await Promise.all([
        this.auditCloudTrail(region),
        this.auditConfig(region),
        this.auditSecurityHub(region),
        this.auditGuardDuty(region),
      ]);

      return {
        cloudTrail,
        config,
        securityHub,
        guardDuty,
      };
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit security services: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId, region }
      );
    }
  }

  /**
   * Audit CloudTrail configuration
   */
  private async auditCloudTrail(region: string): Promise<CloudTrailStatus> {
    try {
      const cloudTrailClient = this.awsClient.getServiceClient(CloudTrailClient, region);

      const describeCommand = new DescribeTrailsCommand({});
      const describeResponse = await cloudTrailClient.send(describeCommand);

      if (!describeResponse.trailList || describeResponse.trailList.length === 0) {
        return {
          enabled: false,
          trails: [],
        };
      }

      const trails: Trail[] = [];

      for (const trail of describeResponse.trailList) {
        if (trail.Name) {
          // Get trail status
          let isLogging = false;
          try {
            const statusCommand = new GetTrailStatusCommand({ Name: trail.Name });
            const statusResponse = await cloudTrailClient.send(statusCommand);
            isLogging = statusResponse.IsLogging || false;
          } catch (error) {
            // Trail may not be accessible
          }

          // Get event selectors
          let logFileValidationEnabled = false;
          try {
            const selectorsCommand = new GetEventSelectorsCommand({ TrailName: trail.Name });
            await cloudTrailClient.send(selectorsCommand);
            logFileValidationEnabled = trail.LogFileValidationEnabled || false;
          } catch (error) {
            // Event selectors may not be accessible
          }

          if (isLogging) {
            trails.push({
              name: trail.Name,
              s3BucketName: trail.S3BucketName || '',
              isMultiRegionTrail: trail.IsMultiRegionTrail || false,
              logFileValidationEnabled,
            });
          }
        }
      }

      return {
        enabled: trails.length > 0,
        trails,
      };
    } catch (error) {
      return {
        enabled: false,
        trails: [],
      };
    }
  }

  /**
   * Audit AWS Config configuration
   */
  private async auditConfig(region: string): Promise<ConfigStatus> {
    try {
      const configClient = this.awsClient.getServiceClient(ConfigServiceClient, region);

      const describeCommand = new DescribeConfigurationRecordersCommand({});
      const describeResponse = await configClient.send(describeCommand);

      if (!describeResponse.ConfigurationRecorders || describeResponse.ConfigurationRecorders.length === 0) {
        return {
          enabled: false,
          recorders: [],
        };
      }

      // Get recorder status
      const statusCommand = new DescribeConfigurationRecorderStatusCommand({});
      const statusResponse = await configClient.send(statusCommand);

      const recorders: ConfigRecorder[] = [];

      for (const recorder of describeResponse.ConfigurationRecorders) {
        if (recorder.name) {
          const status = statusResponse.ConfigurationRecordersStatus?.find(
            s => s.name === recorder.name
          );

          if (status?.recording) {
            recorders.push({
              name: recorder.name,
              roleArn: recorder.roleARN || '',
              recordingGroup: recorder.recordingGroup || {},
            });
          }
        }
      }

      return {
        enabled: recorders.length > 0,
        recorders,
      };
    } catch (error) {
      return {
        enabled: false,
        recorders: [],
      };
    }
  }

  /**
   * Audit Security Hub configuration
   */
  private async auditSecurityHub(region: string): Promise<SecurityHubStatus> {
    try {
      const securityHubClient = this.awsClient.getServiceClient(SecurityHubClient, region);

      // Check if Security Hub is enabled
      const describeCommand = new DescribeHubCommand({});
      await securityHubClient.send(describeCommand);

      // Get enabled standards
      const standardsCommand = new GetEnabledStandardsCommand({});
      const standardsResponse = await securityHubClient.send(standardsCommand);

      const standards: Standard[] = [];

      if (standardsResponse.StandardsSubscriptions) {
        for (const subscription of standardsResponse.StandardsSubscriptions) {
          if (subscription.StandardsArn && subscription.StandardsStatus === 'READY') {
            standards.push({
              standardsArn: subscription.StandardsArn,
              enabled: true,
            });
          }
        }
      }

      return {
        enabled: true,
        standards,
      };
    } catch (error: any) {
      // Security Hub is not enabled if we get InvalidAccessException
      if (error.name === 'InvalidAccessException') {
        return {
          enabled: false,
          standards: [],
        };
      }
      return {
        enabled: false,
        standards: [],
      };
    }
  }

  /**
   * Audit GuardDuty configuration
   */
  private async auditGuardDuty(region: string): Promise<GuardDutyStatus> {
    try {
      const guardDutyClient = this.awsClient.getServiceClient(GuardDutyClient, region);

      const listCommand = new ListDetectorsCommand({});
      const listResponse = await guardDutyClient.send(listCommand);

      if (!listResponse.DetectorIds || listResponse.DetectorIds.length === 0) {
        return {
          enabled: false,
        };
      }

      // Check if any detector is enabled
      for (const detectorId of listResponse.DetectorIds) {
        const getCommand = new GetDetectorCommand({ DetectorId: detectorId });
        const getResponse = await guardDutyClient.send(getCommand);

        if (getResponse.Status === 'ENABLED') {
          return {
            enabled: true,
            detectorId,
          };
        }
      }

      return {
        enabled: false,
      };
    } catch (error) {
      return {
        enabled: false,
      };
    }
  }

  /**
   * Validate security services configuration against best practices
   */
  validateSecurityServices(audit: SecurityServicesAudit, region: string): {
    valid: boolean;
    issues: string[];
  } {
    const issues: string[] = [];

    // CloudTrail validation
    if (!audit.cloudTrail.enabled) {
      issues.push(`CloudTrail is not enabled in region ${region}`);
    } else {
      const multiRegionTrails = audit.cloudTrail.trails.filter(t => t.isMultiRegionTrail);
      if (multiRegionTrails.length === 0) {
        issues.push(`No multi-region CloudTrail found in region ${region}`);
      }

      const validatedTrails = audit.cloudTrail.trails.filter(t => t.logFileValidationEnabled);
      if (validatedTrails.length === 0) {
        issues.push(`No CloudTrail with log file validation enabled in region ${region}`);
      }
    }

    // AWS Config validation
    if (!audit.config.enabled) {
      issues.push(`AWS Config is not enabled in region ${region}`);
    }

    // Security Hub validation
    if (!audit.securityHub.enabled) {
      issues.push(`Security Hub is not enabled in region ${region}`);
    } else if (audit.securityHub.standards.length === 0) {
      issues.push(`Security Hub is enabled but no standards are active in region ${region}`);
    }

    // GuardDuty validation
    if (!audit.guardDuty.enabled) {
      issues.push(`GuardDuty is not enabled in region ${region}`);
    }

    return {
      valid: issues.length === 0,
      issues,
    };
  }
}
