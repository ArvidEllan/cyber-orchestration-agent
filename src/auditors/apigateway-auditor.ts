/**
 * API Gateway Auditor for API configurations
 */

import {
  APIGatewayClient,
  GetRestApisCommand,
  GetAuthorizersCommand,
  GetStagesCommand,
} from '@aws-sdk/client-api-gateway';
import { Resource, ResourceSource } from '../types';
import { AWSClient } from './aws-client';
import { SecurityAgentError, ErrorCode, ErrorCategory } from '../types';

export class APIGatewayAuditor {
  private awsClient: AWSClient;

  constructor(awsClient: AWSClient) {
    this.awsClient = awsClient;
  }

  /**
   * Audit API Gateway APIs in a region
   */
  async auditAPIGateway(accountId: string, region: string): Promise<Resource[]> {
    try {
      const apiGatewayClient = this.awsClient.getServiceClient(APIGatewayClient, region);
      return await this.listRestApis(apiGatewayClient, accountId, region);
    } catch (error) {
      throw new SecurityAgentError(
        `Failed to audit API Gateway: ${error instanceof Error ? error.message : 'Unknown error'}`,
        ErrorCode.AWS_API_ERROR,
        ErrorCategory.API,
        true,
        { accountId, region }
      );
    }
  }

  /**
   * List REST APIs
   */
  private async listRestApis(apiGatewayClient: APIGatewayClient, accountId: string, region: string): Promise<Resource[]> {
    const resources: Resource[] = [];
    let position: string | undefined;

    do {
      const command = new GetRestApisCommand({ position });
      const response = await apiGatewayClient.send(command);

      if (response.items) {
        for (const api of response.items) {
          if (api.id) {
            const apiDetails = await this.getApiDetails(apiGatewayClient, api.id);
            
            resources.push({
              id: `arn:aws:apigateway:${region}::/restapis/${api.id}`,
              type: 'AWS::ApiGateway::RestApi',
              service: 'apigateway',
              region,
              account: accountId,
              properties: {
                id: api.id,
                name: api.name,
                description: api.description,
                createdDate: api.createdDate,
                version: api.version,
                binaryMediaTypes: api.binaryMediaTypes,
                minimumCompressionSize: api.minimumCompressionSize,
                apiKeySource: api.apiKeySource,
                endpointConfiguration: api.endpointConfiguration,
                policy: api.policy,
                authorizers: apiDetails.authorizers,
                stages: apiDetails.stages,
              },
              tags: api.tags || {},
              relationships: [],
              source: ResourceSource.LIVE,
              timestamp: new Date(),
            });
          }
        }
      }

      position = response.position;
    } while (position);

    return resources;
  }

  /**
   * Get detailed API information including authorizers and stages
   */
  private async getApiDetails(apiGatewayClient: APIGatewayClient, apiId: string): Promise<{
    authorizers: any[];
    stages: any[];
  }> {
    try {
      const [authorizersResponse, stagesResponse] = await Promise.allSettled([
        apiGatewayClient.send(new GetAuthorizersCommand({ restApiId: apiId })),
        apiGatewayClient.send(new GetStagesCommand({ restApiId: apiId })),
      ]);

      return {
        authorizers: authorizersResponse.status === 'fulfilled' ? authorizersResponse.value.items || [] : [],
        stages: stagesResponse.status === 'fulfilled' ? stagesResponse.value.item || [] : [],
      };
    } catch (error) {
      return {
        authorizers: [],
        stages: [],
      };
    }
  }
}
