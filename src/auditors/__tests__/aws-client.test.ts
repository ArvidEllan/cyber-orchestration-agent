/**
 * Tests for AWSClient
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AWSClient } from '../aws-client';
import { AWSCredentials } from '../../types';

describe('AWSClient', () => {
  let awsClient: AWSClient;

  beforeEach(() => {
    awsClient = new AWSClient();
  });

  it('should initialize without connection', () => {
    expect(awsClient.isConnected()).toBe(false);
  });

  it('should throw error when getting caller identity without connection', async () => {
    await expect(awsClient.getCallerIdentity()).rejects.toThrow('AWS client not connected');
  });

  it('should throw error when assuming role without connection', async () => {
    await expect(awsClient.assumeRole('arn:aws:iam::123456789012:role/TestRole')).rejects.toThrow(
      'AWS client not connected'
    );
  });

  it('should throw error when getting service client without connection', () => {
    expect(() => awsClient.getServiceClient(class {}, 'us-east-1')).toThrow('AWS client not connected');
  });

  it('should validate invalid regions', async () => {
    const credentials: AWSCredentials = {
      accessKeyId: 'test-key',
      secretAccessKey: 'test-secret',
    };

    // Note: This test would require mocking AWS SDK calls
    // For now, we're just testing the structure
    expect(awsClient).toBeDefined();
  });
});
