//nolint:errcheck // Test file - setup errors are acceptable
package dependency

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGraph(t *testing.T) {
	g := NewGraph()
	assert.NotNil(t, g)
	assert.Equal(t, 0, g.Size())
}

func TestAddOperator(t *testing.T) {
	g := NewGraph()

	err := g.AddOperator(Operator{
		Name:   "connectivity",
		Domain: "connectivity",
	})
	require.NoError(t, err)

	err = g.AddOperator(Operator{
		Name:      "firewall",
		Domain:    "firewall",
		DependsOn: []string{"connectivity"},
	})
	require.NoError(t, err)

	assert.Equal(t, 2, g.Size())
}

func TestAddOperatorSelfDependency(t *testing.T) {
	g := NewGraph()

	err := g.AddOperator(Operator{
		Name:      "connectivity",
		DependsOn: []string{"connectivity"},
	})

	assert.ErrorIs(t, err, ErrSelfDependency)
}

func TestValidateUnknownDependency(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{
		Name:      "firewall",
		DependsOn: []string{"unknown"},
	})

	err := g.Validate()
	assert.ErrorIs(t, err, ErrUnknownDependency)
}

func TestValidateCyclicDependency(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{
		Name:      "a",
		DependsOn: []string{"b"},
	})
	_ = g.AddOperator(Operator{
		Name:      "b",
		DependsOn: []string{"c"},
	})
	_ = g.AddOperator(Operator{
		Name:      "c",
		DependsOn: []string{"a"},
	})

	err := g.Validate()
	assert.ErrorIs(t, err, ErrCyclicDependency)
}

func TestTopologicalSortSimple(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "management"})
	_ = g.AddOperator(Operator{Name: "connectivity", DependsOn: []string{"management"}})
	_ = g.AddOperator(Operator{Name: "firewall", DependsOn: []string{"connectivity"}})

	sorted, err := g.TopologicalSort()
	require.NoError(t, err)

	// Management must come before connectivity, connectivity before firewall.
	managementIdx := indexOf(sorted, "management")
	connectivityIdx := indexOf(sorted, "connectivity")
	firewallIdx := indexOf(sorted, "firewall")

	assert.Less(t, managementIdx, connectivityIdx)
	assert.Less(t, connectivityIdx, firewallIdx)
}

func TestTopologicalSortDiamond(t *testing.T) {
	g := NewGraph()

	// Diamond pattern:
	//     A
	//    / \
	//   B   C
	//    \ /
	//     D
	_ = g.AddOperator(Operator{Name: "A"})
	_ = g.AddOperator(Operator{Name: "B", DependsOn: []string{"A"}})
	_ = g.AddOperator(Operator{Name: "C", DependsOn: []string{"A"}})
	_ = g.AddOperator(Operator{Name: "D", DependsOn: []string{"B", "C"}})

	sorted, err := g.TopologicalSort()
	require.NoError(t, err)

	aIdx := indexOf(sorted, "A")
	bIdx := indexOf(sorted, "B")
	cIdx := indexOf(sorted, "C")
	dIdx := indexOf(sorted, "D")

	assert.Less(t, aIdx, bIdx)
	assert.Less(t, aIdx, cIdx)
	assert.Less(t, bIdx, dIdx)
	assert.Less(t, cIdx, dIdx)
}

func TestReverseTopologicalSort(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "management"})
	_ = g.AddOperator(Operator{Name: "connectivity", DependsOn: []string{"management"}})

	sorted, err := g.ReverseTopologicalSort()
	require.NoError(t, err)

	// Connectivity should come before management in reverse order.
	managementIdx := indexOf(sorted, "management")
	connectivityIdx := indexOf(sorted, "connectivity")

	assert.Less(t, connectivityIdx, managementIdx)
}

func TestParallelGroupsSimple(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "a"})
	_ = g.AddOperator(Operator{Name: "b"})
	_ = g.AddOperator(Operator{Name: "c", DependsOn: []string{"a", "b"}})

	groups, err := g.ParallelGroups()
	require.NoError(t, err)

	// First group: a and b (no deps).
	// Second group: c (depends on a and b).
	assert.Len(t, groups, 2)
	assert.ElementsMatch(t, []string{"a", "b"}, groups[0])
	assert.ElementsMatch(t, []string{"c"}, groups[1])
}

func TestParallelGroupsLinear(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "a"})
	_ = g.AddOperator(Operator{Name: "b", DependsOn: []string{"a"}})
	_ = g.AddOperator(Operator{Name: "c", DependsOn: []string{"b"}})

	groups, err := g.ParallelGroups()
	require.NoError(t, err)

	// Each operator in its own group.
	assert.Len(t, groups, 3)
	assert.Equal(t, []string{"a"}, groups[0])
	assert.Equal(t, []string{"b"}, groups[1])
	assert.Equal(t, []string{"c"}, groups[2])
}

func TestGetDependencies(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "a"})
	_ = g.AddOperator(Operator{Name: "b", DependsOn: []string{"a"}})

	deps, err := g.GetDependencies("b")
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, deps)

	deps, err = g.GetDependencies("a")
	require.NoError(t, err)
	assert.Empty(t, deps)

	_, err = g.GetDependencies("unknown")
	assert.Error(t, err)
}

func TestGetDependents(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "a"})
	_ = g.AddOperator(Operator{Name: "b", DependsOn: []string{"a"}})
	_ = g.AddOperator(Operator{Name: "c", DependsOn: []string{"a"}})

	dependents := g.GetDependents("a")
	assert.ElementsMatch(t, []string{"b", "c"}, dependents)

	dependents = g.GetDependents("b")
	assert.Empty(t, dependents)
}

func TestGetAllDependencies(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "a"})
	_ = g.AddOperator(Operator{Name: "b", DependsOn: []string{"a"}})
	_ = g.AddOperator(Operator{Name: "c", DependsOn: []string{"b"}})

	deps, err := g.GetAllDependencies("c")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"a", "b"}, deps)

	deps, err = g.GetAllDependencies("a")
	require.NoError(t, err)
	assert.Empty(t, deps)

	_, err = g.GetAllDependencies("unknown")
	assert.Error(t, err)
}

func TestGetOperator(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "connectivity", Domain: "connectivity"})

	op, exists := g.GetOperator("connectivity")
	assert.True(t, exists)
	assert.Equal(t, "connectivity", op.Name)
	assert.Equal(t, "connectivity", op.Domain)

	_, exists = g.GetOperator("unknown")
	assert.False(t, exists)
}

func TestOperators(t *testing.T) {
	g := NewGraph()

	_ = g.AddOperator(Operator{Name: "a"})
	_ = g.AddOperator(Operator{Name: "b"})

	operators := g.Operators()
	assert.Len(t, operators, 2)
}

func indexOf(slice []string, item string) int {
	for i, s := range slice {
		if s == item {
			return i
		}
	}
	return -1
}
