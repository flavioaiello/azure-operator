// Package dependency provides operator dependency ordering.
//
// Features:
//  1. Topological sort for deployment order
//  2. Cycle detection
//  3. Parallel group calculation
package dependency

import (
	"errors"
	"fmt"
)

// Errors.
var (
	ErrCyclicDependency  = errors.New("cyclic dependency detected")
	ErrUnknownDependency = errors.New("unknown dependency")
	ErrSelfDependency    = errors.New("operator depends on itself")
)

// Operator represents an operator with dependencies.
type Operator struct {
	Name      string
	Domain    string
	DependsOn []string
}

// Graph represents a dependency graph.
type Graph struct {
	operators map[string]*Operator
	edges     map[string][]string // adjacency list (depends on)
	reverse   map[string][]string // reverse edges (depended by)
}

// NewGraph creates a new dependency graph.
func NewGraph() *Graph {
	return &Graph{
		operators: make(map[string]*Operator),
		edges:     make(map[string][]string),
		reverse:   make(map[string][]string),
	}
}

// AddOperator adds an operator to the graph.
func (g *Graph) AddOperator(op Operator) error {
	// Check for self-dependency.
	for _, dep := range op.DependsOn {
		if dep == op.Name {
			return fmt.Errorf("%w: %s", ErrSelfDependency, op.Name)
		}
	}

	g.operators[op.Name] = &op
	g.edges[op.Name] = op.DependsOn

	// Build reverse edges.
	for _, dep := range op.DependsOn {
		g.reverse[dep] = append(g.reverse[dep], op.Name)
	}

	return nil
}

// Validate checks for unknown dependencies and cycles.
func (g *Graph) Validate() error {
	if err := g.validateDependenciesExist(); err != nil {
		return err
	}
	return g.detectCycles()
}

// validateDependenciesExist checks that all dependencies reference known operators.
func (g *Graph) validateDependenciesExist() error {
	for name, deps := range g.edges {
		for _, dep := range deps {
			if _, exists := g.operators[dep]; !exists {
				return fmt.Errorf("%w: %s depends on %s", ErrUnknownDependency, name, dep)
			}
		}
	}
	return nil
}

// detectCycles uses DFS to find circular dependencies.
func (g *Graph) detectCycles() error {
	visited := make(map[string]bool)
	inStack := make(map[string]bool)

	for name := range g.operators {
		if cyclePath := g.dfsDetectCycle(name, visited, inStack); cyclePath != nil {
			return fmt.Errorf("%w: %v", ErrCyclicDependency, cyclePath)
		}
	}
	return nil
}

// dfsDetectCycle performs DFS to detect a cycle starting from the given node.
// Returns the cycle path if found, nil otherwise.
func (g *Graph) dfsDetectCycle(name string, visited, inStack map[string]bool) []string {
	if visited[name] {
		return nil
	}

	visited[name] = true
	inStack[name] = true

	for _, dep := range g.edges[name] {
		if inStack[dep] {
			return []string{name, dep}
		}
		if cyclePath := g.dfsDetectCycle(dep, visited, inStack); cyclePath != nil {
			return append([]string{name}, cyclePath...)
		}
	}

	inStack[name] = false
	return nil
}

// TopologicalSort returns operators in dependency order.
// Dependencies are listed before dependents.
func (g *Graph) TopologicalSort() ([]string, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}

	var result []string
	visited := make(map[string]bool)

	var visit func(name string)
	visit = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true

		// Visit dependencies first.
		for _, dep := range g.edges[name] {
			visit(dep)
		}

		result = append(result, name)
	}

	for name := range g.operators {
		visit(name)
	}

	return result, nil
}

// ReverseTopologicalSort returns operators in reverse dependency order.
// Dependents are listed before dependencies.
func (g *Graph) ReverseTopologicalSort() ([]string, error) {
	sorted, err := g.TopologicalSort()
	if err != nil {
		return nil, err
	}

	// Reverse the slice.
	result := make([]string, len(sorted))
	for i, name := range sorted {
		result[len(sorted)-1-i] = name
	}

	return result, nil
}

// ParallelGroups returns groups of operators that can run in parallel.
// Each group contains operators with no dependencies on each other.
func (g *Graph) ParallelGroups() ([][]string, error) {
	if err := g.Validate(); err != nil {
		return nil, err
	}

	inDegree := g.calculateInDegrees()
	remaining := g.initRemainingSet()

	var groups [][]string
	for len(remaining) > 0 {
		group := g.findZeroInDegreeNodes(remaining, inDegree)
		if len(group) == 0 {
			// Should not happen if validation passed.
			break
		}

		groups = append(groups, group)
		g.processGroup(group, remaining, inDegree)
	}

	return groups, nil
}

// calculateInDegrees returns a map of operator names to their in-degree counts.
func (g *Graph) calculateInDegrees() map[string]int {
	inDegree := make(map[string]int)
	for name, deps := range g.edges {
		inDegree[name] = len(deps)
	}
	return inDegree
}

// initRemainingSet returns a set of all operator names.
func (g *Graph) initRemainingSet() map[string]bool {
	remaining := make(map[string]bool)
	for name := range g.operators {
		remaining[name] = true
	}
	return remaining
}

// findZeroInDegreeNodes returns all nodes with in-degree 0 from remaining set.
func (g *Graph) findZeroInDegreeNodes(remaining map[string]bool, inDegree map[string]int) []string {
	var group []string
	for name := range remaining {
		if inDegree[name] == 0 {
			group = append(group, name)
		}
	}
	return group
}

// processGroup removes processed nodes and updates in-degrees.
func (g *Graph) processGroup(group []string, remaining map[string]bool, inDegree map[string]int) {
	for _, name := range group {
		delete(remaining, name)
		for _, dependent := range g.reverse[name] {
			if remaining[dependent] {
				inDegree[dependent]--
			}
		}
	}
}

// GetDependencies returns direct dependencies of an operator.
func (g *Graph) GetDependencies(name string) ([]string, error) {
	op, exists := g.operators[name]
	if !exists {
		return nil, fmt.Errorf("operator not found: %s", name)
	}
	return op.DependsOn, nil
}

// GetDependents returns operators that depend on the given operator.
func (g *Graph) GetDependents(name string) []string {
	return g.reverse[name]
}

// GetAllDependencies returns all transitive dependencies.
func (g *Graph) GetAllDependencies(name string) ([]string, error) {
	if _, exists := g.operators[name]; !exists {
		return nil, fmt.Errorf("operator not found: %s", name)
	}

	var result []string
	visited := make(map[string]bool)

	var collect func(n string)
	collect = func(n string) {
		for _, dep := range g.edges[n] {
			if !visited[dep] {
				visited[dep] = true
				result = append(result, dep)
				collect(dep)
			}
		}
	}

	collect(name)
	return result, nil
}

// GetOperator returns an operator by name.
func (g *Graph) GetOperator(name string) (*Operator, bool) {
	op, exists := g.operators[name]
	return op, exists
}

// Operators returns all operators.
func (g *Graph) Operators() []*Operator {
	result := make([]*Operator, 0, len(g.operators))
	for _, op := range g.operators {
		result = append(result, op)
	}
	return result
}

// Size returns the number of operators in the graph.
func (g *Graph) Size() int {
	return len(g.operators)
}
