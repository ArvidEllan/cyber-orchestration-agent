/**
 * S3 Auditor for bucket configurations and policies
 */

import {
  S3Client,
  ListBucketsCommand,
  GetBucketLocationCommand,
  GetBucketEncryptionCommand,
  GetBucketPolicyCommand,
  GetBucketAclCommand,
  GetPublicAccessBlockCommand,
  GetBucketVersioningCommand,
  GetBucketLoggingCommand,
} from '@aws-sdk/client-s3';
import { Resource, ResourceSource } from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class S3Auditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit S3 buckets in an account
   */
  async auditBuckets(accountId: string): Promise<Resource[]> {
    try {
      // S3 is global, but we use us-east-1 for listing
      const s3Client = this.awsClient.getServiceClient(S3Client, 'us-east-1');

      const listCommand = new ListBucketsCommand({});
      const response = await s3Client.send(listCommand);

      if (!response.Buckets) {
        return [];
      }

      const resources: Resource[] = [];

      for (const bucket of response.Buckets) {
        if (bucket.Name) {
          const bucketResource = await this.auditBucket(bucket.Name, accountId);
          if (bucketResource) {
            resources.push(bucketResource);
          }
        }
      }

      return resources;
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit S3 buckets: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId }
      );
    }
  }

  /**
   * Audit a single S3 bucket
   */
  private async auditBucket(bucketName: string, accountId: string): Promise<Resource | null> {
    try {
      // Get bucket region
      const region = await this.getBucketRegion(bucketName);
      const s3Client = this.awsClient.getServiceClient(S3Client, region);

      // Gather bucket configuration
      const [encryption, policy, acl, publicAccessBlock, versioning, logging] = await Promise.allSettled([
        this.getBucketEncryption(s3Client, bucketName),
        this.getBucketPolicy(s3Client, bucketName),
        this.getBucketAcl(s3Client, bucketName),
        this.getPublicAccessBlock(s3Client, bucketName),
        this.getBucketVersioning(s3Client, bucketName),
        this.getBucketLogging(s3Client, bucketName),
      ]);

      return {
        id: `arn:aws:s3:::${bucketName}`,
        type: 'AWS::S3::Bucket',
        service: 's3',
        region,
        account: accountId,
        properties: {
          bucketName,
          encryption: encryption.status === 'fulfilled' ? encryption.value : null,
          policy: policy.status === 'fulfilled' ? policy.value : null,
          acl: acl.status === 'fulfilled' ? acl.value : null,
          publicAccessBlock: publicAccessBlock.status === 'fulfilled' ? publicAccessBlock.value : null,
          versioning: versioning.status === 'fulfilled' ? versioning.value : null,
          logging: logging.status === 'fulfilled' ? logging.value : null,
        },
        tags: {},
        relationships: [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };
    } catch (error) {
      // Skip buckets we can't access
      return null;
    }
  }

  /**
   * Get bucket region
   */
  private async getBucketRegion(bucketName: string): Promise<string> {
    try {
      const s3Client = this.awsClient.getServiceClient(S3Client, 'us-east-1');
      const command = new GetBucketLocationCommand({ Bucket: bucketName });
      const response = await s3Client.send(command);
      
      // LocationConstraint is null for us-east-1
      return response.LocationConstraint || 'us-east-1';
    } catch (error) {
      return 'us-east-1';
    }
  }

  /**
   * Get bucket encryption configuration
   */
  private async getBucketEncryption(s3Client: S3Client, bucketName: string): Promise<any> {
    try {
      const command = new GetBucketEncryptionCommand({ Bucket: bucketName });
      const response = await s3Client.send(command);
      return response.ServerSideEncryptionConfiguration;
    } catch (error: any) {
      if (error.name === 'ServerSideEncryptionConfigurationNotFoundError') {
        return { enabled: false };
      }
      throw error;
    }
  }

  /**
   * Get bucket policy
   */
  private async getBucketPolicy(s3Client: S3Client, bucketName: string): Promise<any> {
    try {
      const command = new GetBucketPolicyCommand({ Bucket: bucketName });
      const response = await s3Client.send(command);
      return response.Policy ? JSON.parse(response.Policy) : null;
    } catch (error: any) {
      if (error.name === 'NoSuchBucketPolicy') {
        return null;
      }
      throw error;
    }
  }

  /**
   * Get bucket ACL
   */
  private async getBucketAcl(s3Client: S3Client, bucketName: string): Promise<any> {
    try {
      const command = new GetBucketAclCommand({ Bucket: bucketName });
      const response = await s3Client.send(command);
      return {
        owner: response.Owner,
        grants: response.Grants,
      };
    } catch (error) {
      return null;
    }
  }

  /**
   * Get public access block configuration
   */
  private async getPublicAccessBlock(s3Client: S3Client, bucketName: string): Promise<any> {
    try {
      const command = new GetPublicAccessBlockCommand({ Bucket: bucketName });
      const response = await s3Client.send(command);
      return response.PublicAccessBlockConfiguration;
    } catch (error: any) {
      if (error.name === 'NoSuchPublicAccessBlockConfiguration') {
        return { enabled: false };
      }
      throw error;
    }
  }

  /**
   * Get bucket versioning configuration
   */
  private async getBucketVersioning(s3Client: S3Client, bucketName: string): Promise<any> {
    try {
      const command = new GetBucketVersioningCommand({ Bucket: bucketName });
      const response = await s3Client.send(command);
      return {
        status: response.Status || 'Disabled',
        mfaDelete: response.MFADelete,
      };
    } catch (error) {
      return { status: 'Disabled' };
    }
  }

  /**
   * Get bucket logging configuration
   */
  private async getBucketLogging(s3Client: S3Client, bucketName: string): Promise<any> {
    try {
      const command = new GetBucketLoggingCommand({ Bucket: bucketName });
      const response = await s3Client.send(command);
      return response.LoggingEnabled || { enabled: false };
    } catch (error) {
      return { enabled: false };
    }
  }
}
