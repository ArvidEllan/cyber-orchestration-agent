/**
 * EKS Auditor for cluster configurations
 */

import {
  EKSClient,
  ListClustersCommand,
  DescribeClusterCommand,
} from '@aws-sdk/client-eks';
import { Resource, ResourceSource } from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class EKSAuditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit EKS clusters in a region
   */
  async auditEKS(accountId: string, region: string): Promise<Resource[]> {
    try {
      const eksClient = this.awsClient.getServiceClient(EKSClient, region);
      return await this.listClusters(eksClient, accountId, region);
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit EKS: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId, region }
      );
    }
  }

  /**
   * List EKS clusters
   */
  private async listClusters(eksClient: EKSClient, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let nextToken: string | undefined;

    do {
      const listCommand = new ListClustersCommand({ nextToken });
      const listResponse = await eksClient.send(listCommand);

      if (listResponse.clusters) {
        for (const clusterName of listResponse.clusters) {
          const cluster = await this.describeCluster(eksClient, clusterName, accountId, region);
          if (cluster) {
            resources.push(cluster);
          }
        }
      }

      nextToken = listResponse.nextToken;
    } while (nextToken);

    return resources;
  }

  /**
   * Describe a specific EKS cluster
   */
  private async describeCluster(
    eksClient: EKSClient,
    clusterName: string,
    accountId: string,
    region: string
  ): Promise<Resource | null> {
    try {
      const command = new DescribeClusterCommand({ name: clusterName });
      const response = await eksClient.send(command);

      if (!response.cluster) {
        return null;
      }

      const cluster = response.cluster;

      return {
        id: cluster.arn || `arn:aws:eks:${region}:${accountId}:cluster/${clusterName}`,
        type: 'AWS::EKS::Cluster',
        service: 'eks',
        region,
        account: accountId,
        properties: {
          name: cluster.name,
          arn: cluster.arn,
          version: cluster.version,
          endpoint: cluster.endpoint,
          roleArn: cluster.roleArn,
          resourcesVpcConfig: cluster.resourcesVpcConfig,
          logging: cluster.logging,
          status: cluster.status,
          certificateAuthority: cluster.certificateAuthority,
          platformVersion: cluster.platformVersion,
          encryptionConfig: cluster.encryptionConfig,
        },
        tags: cluster.tags || {},
        relationships: cluster.roleArn ? [{
          type: 'USES_ROLE',
          targetId: cluster.roleArn,
        }] : [],
        source: ResourceSource.LIVE,
        timestamp: new Date(),
      };
    } catch (error) {
      return null;
    }
  }
}
