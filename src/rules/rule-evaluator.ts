/**
 * Rule Condition Evaluator
 * Evaluates rule conditions against resources
 */

import { RuleCondition, Resource } from '../types';

export class RuleEvaluator {
  /**
   * Evaluate a rule condition against a resource
   */
  evaluateCondition(condition: RuleCondition, resource: Resource): boolean {
    // Check resource type first (if specified)
    if (condition.resourceType && resource.type !== condition.resourceType) {
      return false;
    }

    // Handle logical operators
    if (condition.all) {
      return condition.all.every((c) => this.evaluateCondition(c, resource));
    }

    if (condition.any) {
      return condition.any.some((c) => this.evaluateCondition(c, resource));
    }

    // Check property condition
    if (condition.property && condition.operator) {
      // Some operators don't require a value (exists, notExists, isEmpty, isNotEmpty)
      const operatorsWithoutValue = ['exists', 'notExists', 'isEmpty', 'isNotEmpty'];
      if (operatorsWithoutValue.includes(condition.operator) || condition.value !== undefined) {
        return this.evaluatePropertyCondition(
          resource,
          condition.property,
          condition.operator,
          condition.value
        );
      }
    }

    // If only resourceType is specified, return true if it matches
    if (condition.resourceType && !condition.property) {
      return true;
    }

    return false;
  }

  /**
   * Evaluate a property condition
   */
  private evaluatePropertyCondition(
    resource: Resource,
    property: string,
    operator: string,
    value: any
  ): boolean {
    const propertyValue = this.getPropertyValue(resource, property);

    switch (operator) {
      case 'equals':
        return propertyValue === value;
      case 'notEquals':
        return propertyValue !== value;
      case 'contains':
        return this.contains(propertyValue, value);
      case 'notContains':
        return !this.contains(propertyValue, value);
      case 'startsWith':
        return typeof propertyValue === 'string' && propertyValue.startsWith(value);
      case 'endsWith':
        return typeof propertyValue === 'string' && propertyValue.endsWith(value);
      case 'matches':
        return typeof propertyValue === 'string' && new RegExp(value).test(propertyValue);
      case 'exists':
        return propertyValue !== undefined && propertyValue !== null;
      case 'notExists':
        return propertyValue === undefined || propertyValue === null;
      case 'greaterThan':
        return typeof propertyValue === 'number' && propertyValue > value;
      case 'lessThan':
        return typeof propertyValue === 'number' && propertyValue < value;
      case 'isEmpty':
        return this.isEmpty(propertyValue);
      case 'isNotEmpty':
        return !this.isEmpty(propertyValue);
      default:
        return false;
    }
  }

  /**
   * Get property value from resource using dot notation
   */
  private getPropertyValue(resource: Resource, property: string): any {
    const parts = property.split('.');
    let value: any = resource.properties;

    for (const part of parts) {
      if (value === undefined || value === null) {
        return undefined;
      }
      value = value[part];
    }

    return value;
  }

  /**
   * Check if a value contains another value
   */
  private contains(haystack: any, needle: any): boolean {
    if (typeof haystack === 'string') {
      return haystack.includes(needle);
    }
    if (Array.isArray(haystack)) {
      // For arrays, check if any element matches the needle
      if (typeof needle === 'object' && needle !== null) {
        // Deep object matching for array elements
        return haystack.some((item) => this.deepMatch(item, needle));
      }
      return haystack.includes(needle);
    }
    if (typeof haystack === 'object' && haystack !== null) {
      if (typeof needle === 'string') {
        return needle in haystack;
      }
      // Check if haystack contains all properties of needle
      return this.deepMatch(haystack, needle);
    }
    return false;
  }

  /**
   * Deep match to check if target contains all properties of pattern
   */
  private deepMatch(target: any, pattern: any): boolean {
    if (pattern === target) {
      return true;
    }

    if (typeof pattern !== 'object' || pattern === null) {
      return pattern === target;
    }

    if (typeof target !== 'object' || target === null) {
      return false;
    }

    // Check if target has all properties of pattern with matching values
    for (const key in pattern) {
      if (!Object.prototype.hasOwnProperty.call(pattern, key)) {
        continue;
      }

      const patternValue = pattern[key];
      const targetValue = target[key];

      if (typeof patternValue === 'object' && patternValue !== null) {
        if (!this.deepMatch(targetValue, patternValue)) {
          return false;
        }
      } else if (targetValue !== patternValue) {
        return false;
      }
    }

    return true;
  }

  /**
   * Check if a value is empty
   */
  private isEmpty(value: any): boolean {
    if (value === undefined || value === null) {
      return true;
    }
    if (typeof value === 'string') {
      return value.length === 0;
    }
    if (Array.isArray(value)) {
      return value.length === 0;
    }
    if (typeof value === 'object') {
      return Object.keys(value).length === 0;
    }
    return false;
  }
}
