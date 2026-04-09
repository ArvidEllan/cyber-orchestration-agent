import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as rds from 'aws-cdk-lib/aws-rds';
import * as eks from 'aws-cdk-lib/aws-eks';
import { Construct } from 'constructs';

/**
 * Insecure Infrastructure Demo - CDK Stack
 * This stack contains intentional security misconfigurations for demonstration purposes
 */
export class InsecureInfraStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // =========================================================================
    // VPC for resources
    // =========================================================================
    const vpc = new ec2.Vpc(this, 'DemoVpc', {
      maxAzs: 2,
    });

    // =========================================================================
    // S3 Bucket - Public Access (CRITICAL)
    // =========================================================================
    const publicBucket = new s3.Bucket(this, 'PublicDataBucket', {
      bucketName: 'company-public-data-cdk',
      // CRITICAL: Public read access
      publicReadAccess: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ACLS,
    });

    // S3 Bucket - Missing Encryption (HIGH)
    const logsBucket = new s3.Bucket(this, 'LogsBucket', {
      bucketName: 'company-logs-cdk',
      // HIGH: No encryption configured (encryption: undefined)
      // MEDIUM: No versioning (versioned: false by default)
    });

    // =========================================================================
    // IAM Policy - Wildcard Permissions (CRITICAL)
    // =========================================================================
    const adminPolicy = new iam.ManagedPolicy(this, 'AdminPolicy', {
      managedPolicyName: 'admin-full-access-cdk',
      description: 'Full admin access policy',
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          // CRITICAL: Wildcard action
          actions: ['*'],
          resources: ['*'],
        }),
      ],
    });

    const developerRole = new iam.Role(this, 'DeveloperRole', {
      roleName: 'developer-role-cdk',
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
    });

    // =========================================================================
    // Security Group - Open to Internet (CRITICAL)
    // =========================================================================
    const webServerSg = new ec2.SecurityGroup(this, 'WebServerSG', {
      vpc,
      securityGroupName: 'web-server-sg-cdk',
      description: 'Web server security group with open ports',
      allowAllOutbound: true,
    });

    // CRITICAL: SSH open to the world
    webServerSg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(22),
      'SSH access - INSECURE'
    );

    // CRITICAL: RDP open to the world
    webServerSg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(3389),
      'RDP access - INSECURE'
    );

    // HTTP is acceptable for web servers
    webServerSg.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(80),
      'HTTP access'
    );

    // =========================================================================
    // RDS Database - Insecure Configuration
    // =========================================================================
    const productionDb = new rds.DatabaseInstance(this, 'ProductionDatabase', {
      engine: rds.DatabaseInstanceEngine.mysql({
        version: rds.MysqlEngineVersion.VER_8_0,
      }),
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      vpc,
      // CRITICAL: Database publicly accessible
      publiclyAccessible: true,
      // HIGH: No encryption at rest
      storageEncrypted: false,
      credentials: rds.Credentials.fromPassword('admin', cdk.SecretValue.unsafePlainText('changeme123')),
    });

    // =========================================================================
    // EKS Cluster - Insecure Configuration
    // =========================================================================
    const eksCluster = new eks.Cluster(this, 'ProductionEKS', {
      clusterName: 'production-cluster-cdk',
      vpc,
      version: eks.KubernetesVersion.V1_28,
      defaultCapacity: 2,
      // HIGH: Public endpoint with no private access
      endpointAccess: eks.EndpointAccess.PUBLIC,
      // HIGH: No audit logging configured
    });

    // =========================================================================
    // EC2 Instance - With Security Issues
    // =========================================================================
    const webServer = new ec2.Instance(this, 'WebServer', {
      vpc,
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.MEDIUM),
      machineImage: ec2.MachineImage.latestAmazonLinux2(),
      securityGroup: webServerSg,
      // HIGH: Root volume not encrypted
      blockDevices: [
        {
          deviceName: '/dev/xvda',
          volume: ec2.BlockDeviceVolume.ebs(50, {
            encrypted: false,
          }),
        },
      ],
    });

    // =========================================================================
    // Outputs
    // =========================================================================
    new cdk.CfnOutput(this, 'PublicBucketName', {
      value: publicBucket.bucketName,
      description: 'Public data bucket name (INSECURE)',
    });

    new cdk.CfnOutput(this, 'DatabaseEndpoint', {
      value: productionDb.instanceEndpoint.hostname,
      description: 'RDS endpoint (INSECURE - publicly accessible)',
    });

    new cdk.CfnOutput(this, 'EKSClusterEndpoint', {
      value: eksCluster.clusterEndpoint,
      description: 'EKS cluster endpoint',
    });
  }
}

// App entry point
const app = new cdk.App();
new InsecureInfraStack(app, 'InsecureInfraStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1',
  },
});
