/**
 * Drift Detector for comparing IaC resources with live AWS resources
 */

import {
  Resource,
  DriftReport,
  ResourceDiff,
  PropertyChange,
} from '../types';

export class DriftDetector {
  /**
   * Detect drift between IaC resources and live AWS resources
   */
  detectDrift(iacResources: Resource[], liveResources: Resource[]): DriftReport {
    const added: Resource[] = [];
    const removed: Resource[] = [];
    const modified: ResourceDiff[] = [];
    const unchanged: Resource[] = [];

    // Create maps for efficient lookup
    const iacMap = new Map<string, Resource>();
    const liveMap = new Map<string, Resource>();

    iacResources.forEach(r => iacMap.set(this.getResourceKey(r), r));
    liveResources.forEach(r => liveMap.set(this.getResourceKey(r), r));

    // Find added resources (in live but not in IaC)
    liveResources.forEach(liveResource => {
      const key = this.getResourceKey(liveResource);
      if (!iacMap.has(key)) {
        added.push(liveResource);
      }
    });

    // Find removed resources (in IaC but not in live)
    iacResources.forEach(iacResource => {
      const key = this.getResourceKey(iacResource);
      if (!liveMap.has(key)) {
        removed.push(iacResource);
      }
    });

    // Find modified and unchanged resources
    iacResources.forEach(iacResource => {
      const key = this.getResourceKey(iacResource);
      const liveResource = liveMap.get(key);
      
      if (liveResource) {
        const changes = this.compareResources(iacResource, liveResource);
        if (changes.length > 0) {
          modified.push({
            resource: liveResource,
            changes,
          });
        } else {
          unchanged.push(liveResource);
        }
      }
    });

    return {
      added,
      removed,
      modified,
      unchanged,
    };
  }

  /**
   * Generate a unique key for a resource
   * Uses multiple identifiers to match resources across IaC and live
   */
  private getResourceKey(resource: Resource): string {
    // Try to use resource ID first
    if (resource.id) {
      return resource.id;
    }

    // Fallback to type + name/identifier from properties
    const identifier = this.extractResourceIdentifier(resource);
    return `${resource.type}:${identifier}`;
  }

  /**
   * Extract a unique identifier from resource properties
   */
  private extractResourceIdentifier(resource: Resource): string {
    const props = resource.properties;

    // Common identifier fields
    const identifierFields = [
      'name',
      'id',
      'arn',
      'instanceId',
      'bucketName',
      'functionName',
      'roleName',
      'userName',
      'groupId',
      'vpcId',
      'subnetId',
      'dbInstanceIdentifier',
      'clusterName',
    ];

    for (const field of identifierFields) {
      if (props[field]) {
        return String(props[field]);
      }
    }

    // Fallback to stringified properties
    return JSON.stringify(props);
  }

  /**
   * Compare two resources and return property changes
   */
  private compareResources(iacResource: Resource, liveResource: Resource): PropertyChange[] {
    const changes: PropertyChange[] = [];

    // Compare properties
    const allKeys = new Set([
      ...Object.keys(iacResource.properties),
      ...Object.keys(liveResource.properties),
    ]);

    allKeys.forEach(key => {
      // Skip certain properties that are expected to differ
      if (this.shouldSkipProperty(key)) {
        return;
      }

      const iacValue = iacResource.properties[key];
      const liveValue = liveResource.properties[key];

      if (!this.deepEqual(iacValue, liveValue)) {
        changes.push({
          property: key,
          oldValue: iacValue,
          newValue: liveValue,
        });
      }
    });

    // Compare tags
    const allTagKeys = new Set([
      ...Object.keys(iacResource.tags),
      ...Object.keys(liveResource.tags),
    ]);

    allTagKeys.forEach(key => {
      const iacValue = iacResource.tags[key];
      const liveValue = liveResource.tags[key];

      if (iacValue !== liveValue) {
        changes.push({
          property: `tags.${key}`,
          oldValue: iacValue,
          newValue: liveValue,
        });
      }
    });

    return changes;
  }

  /**
   * Check if a property should be skipped during comparison
   */
  private shouldSkipProperty(property: string): boolean {
    // Properties that are expected to differ or are metadata
    const skipProperties = [
      'timestamp',
      'lastModified',
      'createdAt',
      'updatedAt',
      'createDate',
      'lastUsedDate',
      'passwordLastUsed',
      'status',
      'state',
      'arn', // ARNs may differ in format
    ];

    return skipProperties.includes(property);
  }

  /**
   * Deep equality check for property values
   */
  private deepEqual(a: any, b: any): boolean {
    if (a === b) return true;
    if (a == null || b == null) return false;
    if (typeof a !== typeof b) return false;

    if (typeof a === 'object') {
      if (Array.isArray(a) !== Array.isArray(b)) return false;

      if (Array.isArray(a)) {
        if (a.length !== b.length) return false;
        return a.every((val, idx) => this.deepEqual(val, b[idx]));
      }

      const keysA = Object.keys(a);
      const keysB = Object.keys(b);
      if (keysA.length !== keysB.length) return false;

      return keysA.every(key => this.deepEqual(a[key], b[key]));
    }

    return false;
  }

  /**
   * Generate a summary of drift
   */
  generateDriftSummary(driftReport: DriftReport): {
    totalResources: number;
    addedCount: number;
    removedCount: number;
    modifiedCount: number;
    unchangedCount: number;
    driftPercentage: number;
  } {
    const totalResources = 
      driftReport.added.length +
      driftReport.removed.length +
      driftReport.modified.length +
      driftReport.unchanged.length;

    const driftedResources = 
      driftReport.added.length +
      driftReport.removed.length +
      driftReport.modified.length;

    const driftPercentage = totalResources > 0 
      ? (driftedResources / totalResources) * 100 
      : 0;

    return {
      totalResources,
      addedCount: driftReport.added.length,
      removedCount: driftReport.removed.length,
      modifiedCount: driftReport.modified.length,
      unchangedCount: driftReport.unchanged.length,
      driftPercentage: Math.round(driftPercentage * 100) / 100,
    };
  }

  /**
   * Filter drift report by resource type
   */
  filterByResourceType(driftReport: DriftReport, resourceType: string): DriftReport {
    return {
      added: driftReport.added.filter(r => r.type === resourceType),
      removed: driftReport.removed.filter(r => r.type === resourceType),
      modified: driftReport.modified.filter(rd => rd.resource.type === resourceType),
      unchanged: driftReport.unchanged.filter(r => r.type === resourceType),
    };
  }

  /**
   * Filter drift report by service
   */
  filterByService(driftReport: DriftReport, service: string): DriftReport {
    return {
      added: driftReport.added.filter(r => r.service === service),
      removed: driftReport.removed.filter(r => r.service === service),
      modified: driftReport.modified.filter(rd => rd.resource.service === service),
      unchanged: driftReport.unchanged.filter(r => r.service === service),
    };
  }
}
