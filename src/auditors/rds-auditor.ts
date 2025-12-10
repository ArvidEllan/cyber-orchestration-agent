/**
 * RDS Auditor for database instances and configurations
 */

import {
  RDSClient,
  DescribeDBInstancesCommand,
  DescribeDBClustersCommand,
  DescribeDBSnapshotsCommand,
} from '@aws-sdk/client-rds';
import { Resource, ResourceSource } from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class RDSAuditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit RDS resources in a region
   */
  async auditRDS(accountId: string, region: string): Promise<Resource[]> {
    try {
      const rdsClient = this.awsClient.getServiceClient(RDSClient, region);

      const [instances, clusters, snapshots] = await Promise.all([
        this.listDBInstances(rdsClient, accountId, region),
        this.listDBClusters(rdsClient, accountId, region),
        this.listDBSnapshots(rdsClient, accountId, region),
      ]);

      return [...instances, ...clusters, ...snapshots];
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit RDS: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId, region }
      );
    }
  }

  /**
   * List RDS database instances
   */
  private async listDBInstances(rdsClient: RDSClient, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let marker: string | undefined;

    do {
      const command = new DescribeDBInstancesCommand({ Marker: marker });
      const response = await rdsClient.send(command);

      if (response.DBInstances) {
        for (const instance of response.DBInstances) {
          if (instance.DBInstanceIdentifier) {
            resources.push({
              id: instance.DBInstanceArn || `arn:aws:rds:${region}:${accountId}:db:${instance.DBInstanceIdentifier}`,
              type: 'AWS::RDS::DBInstance',
              service: 'rds',
              region,
              account: accountId,
              properties: {
                dbInstanceIdentifier: instance.DBInstanceIdentifier,
                dbInstanceClass: instance.DBInstanceClass,
                engine: instance.Engine,
                engineVersion: instance.EngineVersion,
                status: instance.DBInstanceStatus,
                endpoint: instance.Endpoint,
                port: instance.DbInstancePort,
                storageEncrypted: instance.StorageEncrypted,
                kmsKeyId: instance.KmsKeyId,
                publiclyAccessible: instance.PubliclyAccessible,
                vpcSecurityGroups: instance.VpcSecurityGroups,
                backupRetentionPeriod: instance.BackupRetentionPeriod,
                multiAZ: instance.MultiAZ,
                autoMinorVersionUpgrade: instance.AutoMinorVersionUpgrade,
                deletionProtection: instance.DeletionProtection,
              },
              tags: this.extractTags(instance.TagList),
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      marker = response.Marker;
    } while (marker);

    return resources;
  }

  /**
   * List RDS database clusters (Aurora)
   */
  private async listDBClusters(rdsClient: RDSClient, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let marker: string | undefined;

    do {
      const command = new DescribeDBClustersCommand({ Marker: marker });
      const response = await rdsClient.send(command);

      if (response.DBClusters) {
        for (const cluster of response.DBClusters) {
          if (cluster.DBClusterIdentifier) {
            resources.push({
              id: cluster.DBClusterArn || `arn:aws:rds:${region}:${accountId}:cluster:${cluster.DBClusterIdentifier}`,
              type: 'AWS::RDS::DBCluster',
              service: 'rds',
              region,
              account: accountId,
              properties: {
                dbClusterIdentifier: cluster.DBClusterIdentifier,
                engine: cluster.Engine,
                engineVersion: cluster.EngineVersion,
                status: cluster.Status,
                endpoint: cluster.Endpoint,
                readerEndpoint: cluster.ReaderEndpoint,
                port: cluster.Port,
                storageEncrypted: cluster.StorageEncrypted,
                kmsKeyId: cluster.KmsKeyId,
                vpcSecurityGroups: cluster.VpcSecurityGroups,
                backupRetentionPeriod: cluster.BackupRetentionPeriod,
                multiAZ: cluster.MultiAZ,
                deletionProtection: cluster.DeletionProtection,
                members: cluster.DBClusterMembers,
              },
              tags: this.extractTags(cluster.TagList),
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      marker = response.Marker;
    } while (marker);

    return resources;
  }

  /**
   * List RDS database snapshots
   */
  private async listDBSnapshots(rdsClient: RDSClient, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let marker: string | undefined;

    do {
      const command = new DescribeDBSnapshotsCommand({ 
        SnapshotType: 'manual',
        Marker: marker,
      });
      const response = await rdsClient.send(command);

      if (response.DBSnapshots) {
        for (const snapshot of response.DBSnapshots) {
          if (snapshot.DBSnapshotIdentifier) {
            resources.push({
              id: snapshot.DBSnapshotArn || `arn:aws:rds:${region}:${accountId}:snapshot:${snapshot.DBSnapshotIdentifier}`,
              type: 'AWS::RDS::DBSnapshot',
              service: 'rds',
              region,
              account: accountId,
              properties: {
                dbSnapshotIdentifier: snapshot.DBSnapshotIdentifier,
                dbInstanceIdentifier: snapshot.DBInstanceIdentifier,
                snapshotType: snapshot.SnapshotType,
                status: snapshot.Status,
                encrypted: snapshot.Encrypted,
                kmsKeyId: snapshot.KmsKeyId,
                snapshotCreateTime: snapshot.SnapshotCreateTime,
              },
              tags: this.extractTags(snapshot.TagList),
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      marker = response.Marker;
    } while (marker);

    return resources;
  }

  /**
   * Extract tags from AWS tag format
   */
  private extractTags(tags?: Array<{ Key?: string; Value?: string }>): Record<string, string> {
    if (!tags) return {};
    
    const result: Record<string, string> = {};
    tags.forEach(tag => {
      if (tag.Key) {
        result[tag.Key] = tag.Value || '';
      }
    });
    return result;
  }
}
