/**
 * Tests for DriftDetector
 */

import { describe, it, expect } from 'vitest';
import { DriftDetector } from '../drift-detector';
import { Resource, ResourceSource } from '../../types';

describe('DriftDetector', () => {
  const driftDetector = new DriftDetector();

  const createResource = (id: string, type: string, properties: Record<string, any>): Resource => ({
    id,
    type,
    service: 's3',
    region: 'us-east-1',
    account: '123456789012',
    properties,
    tags: {},
    relationships: [],
    source: ResourceSource.LIVE,
    timestamp: new Date(),
  });

  it('should detect added resources', () => {
    const iacResources: Resource[] = [];
    const liveResources: Resource[] = [
      createResource('bucket-1', 'AWS::S3::Bucket', { bucketName: 'test-bucket' }),
    ];

    const drift = driftDetector.detectDrift(iacResources, liveResources);

    expect(drift.added).toHaveLength(1);
    expect(drift.added[0].id).toBe('bucket-1');
    expect(drift.removed).toHaveLength(0);
    expect(drift.modified).toHaveLength(0);
    expect(drift.unchanged).toHaveLength(0);
  });

  it('should detect removed resources', () => {
    const iacResources: Resource[] = [
      createResource('bucket-1', 'AWS::S3::Bucket', { bucketName: 'test-bucket' }),
    ];
    const liveResources: Resource[] = [];

    const drift = driftDetector.detectDrift(iacResources, liveResources);

    expect(drift.removed).toHaveLength(1);
    expect(drift.removed[0].id).toBe('bucket-1');
    expect(drift.added).toHaveLength(0);
    expect(drift.modified).toHaveLength(0);
    expect(drift.unchanged).toHaveLength(0);
  });

  it('should detect modified resources', () => {
    const iacResources: Resource[] = [
      createResource('bucket-1', 'AWS::S3::Bucket', { bucketName: 'test-bucket', encryption: false }),
    ];
    const liveResources: Resource[] = [
      createResource('bucket-1', 'AWS::S3::Bucket', { bucketName: 'test-bucket', encryption: true }),
    ];

    const drift = driftDetector.detectDrift(iacResources, liveResources);

    expect(drift.modified).toHaveLength(1);
    expect(drift.modified[0].resource.id).toBe('bucket-1');
    expect(drift.modified[0].changes).toHaveLength(1);
    expect(drift.modified[0].changes[0].property).toBe('encryption');
    expect(drift.modified[0].changes[0].oldValue).toBe(false);
    expect(drift.modified[0].changes[0].newValue).toBe(true);
  });

  it('should detect unchanged resources', () => {
    const iacResources: Resource[] = [
      createResource('bucket-1', 'AWS::S3::Bucket', { bucketName: 'test-bucket', encryption: true }),
    ];
    const liveResources: Resource[] = [
      createResource('bucket-1', 'AWS::S3::Bucket', { bucketName: 'test-bucket', encryption: true }),
    ];

    const drift = driftDetector.detectDrift(iacResources, liveResources);

    expect(drift.unchanged).toHaveLength(1);
    expect(drift.unchanged[0].id).toBe('bucket-1');
    expect(drift.added).toHaveLength(0);
    expect(drift.removed).toHaveLength(0);
    expect(drift.modified).toHaveLength(0);
  });

  it('should generate drift summary', () => {
    const driftReport = {
      added: [createResource('bucket-1', 'AWS::S3::Bucket', {})],
      removed: [createResource('bucket-2', 'AWS::S3::Bucket', {})],
      modified: [
        {
          resource: createResource('bucket-3', 'AWS::S3::Bucket', {}),
          changes: [{ property: 'encryption', oldValue: false, newValue: true }],
        },
      ],
      unchanged: [createResource('bucket-4', 'AWS::S3::Bucket', {})],
    };

    const summary = driftDetector.generateDriftSummary(driftReport);

    expect(summary.totalResources).toBe(4);
    expect(summary.addedCount).toBe(1);
    expect(summary.removedCount).toBe(1);
    expect(summary.modifiedCount).toBe(1);
    expect(summary.unchangedCount).toBe(1);
    expect(summary.driftPercentage).toBe(75);
  });

  it('should filter drift by resource type', () => {
    const driftReport = {
      added: [
        createResource('bucket-1', 'AWS::S3::Bucket', {}),
        createResource('instance-1', 'AWS::EC2::Instance', {}),
      ],
      removed: [],
      modified: [],
      unchanged: [],
    };

    const filtered = driftDetector.filterByResourceType(driftReport, 'AWS::S3::Bucket');

    expect(filtered.added).toHaveLength(1);
    expect(filtered.added[0].type).toBe('AWS::S3::Bucket');
  });
});
