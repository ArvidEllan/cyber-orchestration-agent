/**
 * EC2 Auditor for instances, security groups, and network ACLs
 */

import {
  EC2Client,
  DescribeInstancesCommand,
  DescribeSecurityGroupsCommand,
  DescribeNetworkAclsCommand,
  DescribeVpcsCommand,
} from '@aws-sdk/client-ec2';
import { Resource, ResourceSource } from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class EC2Auditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit EC2 resources in a region
   */
  async auditEC2(accountId: string, region: string): Promise<Resource[]> {
    try {
      const ec2Client = this.awsClient.getServiceClient(EC2Client, region);

      const [instances, securityGroups, networkAcls, vpcs] = await Promise.all([
        this.listInstances(ec2Client, accountId, region),
        this.listSecurityGroups(ec2Client, accountId, region),
        this.listNetworkAcls(ec2Client, accountId, region),
        this.listVpcs(ec2Client, accountId, region),
      ]);

      return [...instances, ...securityGroups, ...networkAcls, ...vpcs];
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit EC2: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId, region }
      );
    }
  }

  /**
   * List EC2 instances
   */
  private async listInstances(ec2Client: EC2Client, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let nextToken: string | undefined;

    do {
      const command = new DescribeInstancesCommand({ NextToken: nextToken });
      const response = await ec2Client.send(command);

      if (response.Reservations) {
        for (const reservation of response.Reservations) {
          if (reservation.Instances) {
            for (const instance of reservation.Instances) {
              if (instance.InstanceId) {
                resources.push({
                  id: `arn:aws:ec2:${region}:${accountId}:instance/${instance.InstanceId}`,
                  type: 'AWS::EC2::Instance',
                  service: 'ec2',
                  region,
                  account: accountId,
                  properties: {
                    instanceId: instance.InstanceId,
                    instanceType: instance.InstanceType,
                    state: instance.State?.Name,
                    publicIpAddress: instance.PublicIpAddress,
                    privateIpAddress: instance.PrivateIpAddress,
                    vpcId: instance.VpcId,
                    subnetId: instance.SubnetId,
                    securityGroups: instance.SecurityGroups?.map(sg => sg.GroupId),
                    imageId: instance.ImageId,
                    launchTime: instance.LaunchTime,
                  },
                  tags: this.extractTags(instance.Tags),
                  relationships: instance.SecurityGroups?.map(sg => ({
                    type: 'USES_SECURITY_GROUP',
                    targetId: `arn:aws:ec2:${region}:${accountId}:security-group/${sg.GroupId}`,
                  })) || [],
                  source: ResourceSource.LIVE,
                  timestamp: new Date(),
                });
              }
            }
          }
        }
      }

      nextToken = response.NextToken;
    } while (nextToken);

    return resources;
  }

  /**
   * List security groups
   */
  private async listSecurityGroups(ec2Client: EC2Client, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let nextToken: string | undefined;

    do {
      const command = new DescribeSecurityGroupsCommand({ NextToken: nextToken });
      const response = await ec2Client.send(command);

      if (response.SecurityGroups) {
        for (const sg of response.SecurityGroups) {
          if (sg.GroupId) {
            resources.push({
              id: `arn:aws:ec2:${region}:${accountId}:security-group/${sg.GroupId}`,
              type: 'AWS::EC2::SecurityGroup',
              service: 'ec2',
              region,
              account: accountId,
              properties: {
                groupId: sg.GroupId,
                groupName: sg.GroupName,
                description: sg.Description,
                vpcId: sg.VpcId,
                ingressRules: sg.IpPermissions,
                egressRules: sg.IpPermissionsEgress,
              },
              tags: this.extractTags(sg.Tags),
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      nextToken = response.NextToken;
    } while (nextToken);

    return resources;
  }

  /**
   * List network ACLs
   */
  private async listNetworkAcls(ec2Client: EC2Client, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let nextToken: string | undefined;

    do {
      const command = new DescribeNetworkAclsCommand({ NextToken: nextToken });
      const response = await ec2Client.send(command);

      if (response.NetworkAcls) {
        for (const nacl of response.NetworkAcls) {
          if (nacl.NetworkAclId) {
            resources.push({
              id: `arn:aws:ec2:${region}:${accountId}:network-acl/${nacl.NetworkAclId}`,
              type: 'AWS::EC2::NetworkAcl',
              service: 'ec2',
              region,
              account: accountId,
              properties: {
                networkAclId: nacl.NetworkAclId,
                vpcId: nacl.VpcId,
                isDefault: nacl.IsDefault,
                entries: nacl.Entries,
                associations: nacl.Associations,
              },
              tags: this.extractTags(nacl.Tags),
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      nextToken = response.NextToken;
    } while (nextToken);

    return resources;
  }

  /**
   * List VPCs
   */
  private async listVpcs(ec2Client: EC2Client, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let nextToken: string | undefined;

    do {
      const command = new DescribeVpcsCommand({ NextToken: nextToken });
      const response = await ec2Client.send(command);

      if (response.Vpcs) {
        for (const vpc of response.Vpcs) {
          if (vpc.VpcId) {
            resources.push({
              id: `arn:aws:ec2:${region}:${accountId}:vpc/${vpc.VpcId}`,
              type: 'AWS::EC2::VPC',
              service: 'ec2',
              region,
              account: accountId,
              properties: {
                vpcId: vpc.VpcId,
                cidrBlock: vpc.CidrBlock,
                state: vpc.State,
                isDefault: vpc.IsDefault,
                dhcpOptionsId: vpc.DhcpOptionsId,
              },
              tags: this.extractTags(vpc.Tags),
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      nextToken = response.NextToken;
    } while (nextToken);

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
