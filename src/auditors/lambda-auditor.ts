/**
 * Lambda Auditor for function configurations and permissions
 */

import {
  LambdaClient,
  ListFunctionsCommand,
  GetPolicyCommand,
} from '@aws-sdk/client-lambda';
import { Resource, ResourceSource } from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class LambdaAuditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit Lambda functions in a region
   */
  async auditLambda(accountId: string, region: string): Promise<Resource[]> {
    try {
      const lambdaClient = this.awsClient.getServiceClient(LambdaClient, region);
      return await this.listFunctions(lambdaClient, accountId, region);
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit Lambda: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId, region }
      );
    }
  }

  /**
   * List Lambda functions
   */
  private async listFunctions(lambdaClient: LambdaClient, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let marker: string | undefined;

    do {
      const command = new ListFunctionsCommand({ Marker: marker });
      const response = await lambdaClient.send(command);

      if (response.Functions) {
        for (const func of response.Functions) {
          if (func.FunctionName) {
            const functionDetails = await this.getFunctionDetails(lambdaClient, func.FunctionName);
            
            resources.push({
              id: func.FunctionArn || `arn:aws:lambda:${region}:${accountId}:function:${func.FunctionName}`,
              type: 'AWS::Lambda::Function',
              service: 'lambda',
              region,
              account: accountId,
              properties: {
                functionName: func.FunctionName,
                functionArn: func.FunctionArn,
                runtime: func.Runtime,
                role: func.Role,
                handler: func.Handler,
                codeSize: func.CodeSize,
                description: func.Description,
                timeout: func.Timeout,
                memorySize: func.MemorySize,
                lastModified: func.LastModified,
                environment: func.Environment,
                vpcConfig: func.VpcConfig,
                layers: func.Layers,
                kmsKeyArn: func.KMSKeyArn,
                tracingConfig: func.TracingConfig,
                policy: functionDetails.policy,
              },
              tags: {},
              relationships: func.Role ? [{
                type: 'USES_ROLE',
                targetId: func.Role,
              }] : [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      marker = response.NextMarker;
    } while (marker);

    return resources;
  }

  /**
   * Get detailed function information including policy
   */
  private async getFunctionDetails(lambdaClient: LambdaClient, functionName: string): Promise<{ policy: any }> {
    try {
      const policyCommand = new GetPolicyCommand({ FunctionName: functionName });
      const policyResponse = await lambdaClient.send(policyCommand);
      
      return {
        policy: policyResponse.Policy ? JSON.parse(policyResponse.Policy) : null,
      };
    } catch (error) {
      // Function may not have a resource policy
      return { policy: null };
    }
  }
}
