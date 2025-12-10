import * as fs from 'fs/promises';
import * as path from 'path';
import { Resource, ParsedInfrastructure } from '../types';
import { ParserFactory } from './parser-factory';

/**
 * Utility functions for IaC parsing and resource extraction
 */

/**
 * Parse multiple IaC files from a directory
 */
export async function parseDirectory(
  dirPath: string,
  recursive: boolean = true
): Promise<ParsedInfrastructure[]> {
  const results: ParsedInfrastructure[] = [];
  const files = await findIaCFiles(dirPath, recursive);

  for (const file of files) {
    try {
      const parsed = await ParserFactory.parseFile(file);
      results.push(parsed);
    } catch (error) {
      console.error(`Failed to parse ${file}:`, error);
      // Continue with other files
    }
  }

  return results;
}

/**
 * Find all IaC files in a directory
 */
export async function findIaCFiles(dirPath: string, recursive: boolean = true): Promise<string[]> {
  const files: string[] = [];
  const entries = await fs.readdir(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);

    if (entry.isDirectory()) {
      if (recursive && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
        const subFiles = await findIaCFiles(fullPath, recursive);
        files.push(...subFiles);
      }
    } else if (entry.isFile()) {
      if (isIaCFile(entry.name)) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

/**
 * Check if a file is an IaC file based on extension
 */
export function isIaCFile(fileName: string): boolean {
  const ext = path.extname(fileName).toLowerCase();
  const basename = fileName.toLowerCase();

  // Terraform
  if (ext === '.tf' || ext === '.tfvars') {
    return true;
  }

  // CloudFormation
  if (
    (ext === '.json' || ext === '.yaml' || ext === '.yml') &&
    (basename.includes('cloudformation') ||
      basename.includes('cfn') ||
      basename.includes('template'))
  ) {
    return true;
  }

  // CDK
  if (ext === '.ts' && (basename.includes('stack') || basename.includes('cdk'))) {
    return true;
  }

  return false;
}

/**
 * Merge resources from multiple parsed infrastructures
 */
export function mergeResources(parsed: ParsedInfrastructure[]): Resource[] {
  const allResources: Resource[] = [];
  const resourceMap = new Map<string, Resource>();

  for (const infrastructure of parsed) {
    for (const resource of infrastructure.resources) {
      // Use resource ID as key to deduplicate
      if (!resourceMap.has(resource.id)) {
        resourceMap.set(resource.id, resource);
        allResources.push(resource);
      }
    }
  }

  return allResources;
}

/**
 * Filter resources by type
 */
export function filterResourcesByType(resources: Resource[], types: string[]): Resource[] {
  return resources.filter((resource) => types.includes(resource.type));
}

/**
 * Filter resources by service
 */
export function filterResourcesByService(resources: Resource[], services: string[]): Resource[] {
  return resources.filter((resource) => services.includes(resource.service));
}

/**
 * Group resources by service
 */
export function groupResourcesByService(resources: Resource[]): Map<string, Resource[]> {
  const grouped = new Map<string, Resource[]>();

  for (const resource of resources) {
    const existing = grouped.get(resource.service) || [];
    existing.push(resource);
    grouped.set(resource.service, existing);
  }

  return grouped;
}

/**
 * Group resources by type
 */
export function groupResourcesByType(resources: Resource[]): Map<string, Resource[]> {
  const grouped = new Map<string, Resource[]>();

  for (const resource of resources) {
    const existing = grouped.get(resource.type) || [];
    existing.push(resource);
    grouped.set(resource.type, existing);
  }

  return grouped;
}

/**
 * Extract resource by ID
 */
export function findResourceById(resources: Resource[], id: string): Resource | undefined {
  return resources.find((resource) => resource.id === id);
}

/**
 * Get all resource dependencies
 */
export function getResourceDependencies(resource: Resource, allResources: Resource[]): Resource[] {
  const dependencies: Resource[] = [];

  for (const relationship of resource.relationships) {
    const dep = findResourceById(allResources, relationship.targetId);
    if (dep) {
      dependencies.push(dep);
    }
  }

  return dependencies;
}

/**
 * Build resource dependency graph
 */
export function buildDependencyGraph(
  resources: Resource[]
): Map<string, Set<string>> {
  const graph = new Map<string, Set<string>>();

  for (const resource of resources) {
    const deps = new Set<string>();
    for (const relationship of resource.relationships) {
      deps.add(relationship.targetId);
    }
    graph.set(resource.id, deps);
  }

  return graph;
}

/**
 * Validate resource references
 */
export function validateResourceReferences(resources: Resource[]): string[] {
  const errors: string[] = [];
  const resourceIds = new Set(resources.map((r) => r.id));

  for (const resource of resources) {
    for (const relationship of resource.relationships) {
      if (!resourceIds.has(relationship.targetId)) {
        errors.push(
          `Resource ${resource.id} references non-existent resource: ${relationship.targetId}`
        );
      }
    }
  }

  return errors;
}
