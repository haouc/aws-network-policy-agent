package ebpf

import (
	"fmt"
	"testing"

	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// key and val mirror NPA's 8-byte LPM trie key and value.
func key(n byte) string { return string([]byte{n, 0, 0, 0, 0, 0, 0, 0}) }
func val(n byte) []byte { return []byte{n, 0, 0, 0, 0, 0, 0, 0} }

// fakeKernel records what landed and scripts per-key failures.
type fakeKernel struct {
	entries     map[string][]byte
	updateErrs  map[string]error
	deleteErrs  map[string]error
	deleteCalls map[string]int
}

// newTestMap builds an InMemoryBpfMap over a fake kernel, seeded with entries
// that are already programmed, bypassing loadFromKernel.
func newTestMap(seed map[string][]byte) (*InMemoryBpfMap, *fakeKernel) {
	f := &fakeKernel{
		entries:     map[string][]byte{},
		updateErrs:  map[string]error{},
		deleteErrs:  map[string]error{},
		deleteCalls: map[string]int{},
	}
	contents := map[string][]byte{}
	for k, v := range seed {
		contents[k] = v
		f.entries[k] = v
	}
	m := &InMemoryBpfMap{
		bpfMap:   &maps.BpfMap{MapID: 1},
		contents: contents,
		updateEntry: func(key, value []byte) error {
			if err := f.updateErrs[string(key)]; err != nil {
				return err
			}
			f.entries[string(key)] = append([]byte(nil), value...)
			return nil
		},
		deleteEntry: func(key []byte) error {
			f.deleteCalls[string(key)]++
			if err := f.deleteErrs[string(key)]; err != nil {
				return err
			}
			delete(f.entries, string(key))
			return nil
		},
	}
	return m, f
}

// The #686 regression guard: one failing key must not abandon the remaining
// adds or the stale-entry delete sweep. Presence of a key in the trie is the
// allow decision, so a skipped sweep keeps a revoked policy in force.
func TestBulkRefresh_OneFailingKeyDoesNotAbandonTheRefresh(t *testing.T) {
	m, f := newTestMap(map[string][]byte{key(8): val(8), key(9): val(9)})
	f.updateErrs[key(1)] = fmt.Errorf("unable to update map: %w", unix.ENOMEM)

	err := m.BulkRefresh(map[string][]byte{
		key(1): val(1), // fails
		key(2): val(2),
		key(3): val(3),
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "1 of 3 map updates failed")

	for _, n := range []byte{2, 3} {
		assert.Equal(t, val(n), f.entries[key(n)], "add %d must land despite the failing key", n)
		assert.Equal(t, val(n), m.contents[key(n)])
	}
	assert.NotContains(t, f.entries, key(1))
	assert.NotContains(t, m.contents, key(1), "a key the kernel rejected must not be recorded as programmed")

	for _, n := range []byte{8, 9} {
		assert.NotContains(t, f.entries, key(n), "stale entry %d must still be swept", n)
		assert.NotContains(t, m.contents, key(n))
		assert.Equal(t, 1, f.deleteCalls[key(n)])
	}
}

// Every update failing must still return one short error, not one line per key.
func TestBulkRefresh_ManyFailuresReturnASummary(t *testing.T) {
	m, f := newTestMap(nil)
	desired := map[string][]byte{}
	for i := range 100 {
		k := key(byte(i))
		desired[k] = val(byte(i))
		f.updateErrs[k] = fmt.Errorf("unable to update map: %w", unix.ENOSPC)
	}

	err := m.BulkRefresh(desired)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "and 97 more")
	assert.Less(t, len(err.Error()), 300, "the returned error is re-logged at every layer above")
	assert.Empty(t, m.contents)
}

// A failed delete keeps the key in the shadow map, so the next refresh retries
// it without any special casing.
func TestBulkRefresh_FailedDeleteIsRetriedNextRefresh(t *testing.T) {
	m, f := newTestMap(map[string][]byte{key(8): val(8)})
	f.deleteErrs[key(8)] = fmt.Errorf("unable to delete map entry: %w", unix.EPERM)

	assert.NoError(t, m.BulkRefresh(map[string][]byte{}), "a delete failure must not fail CNI pod add")
	assert.Contains(t, m.contents, key(8))

	delete(f.deleteErrs, key(8))
	assert.NoError(t, m.BulkRefresh(map[string][]byte{}))
	assert.NotContains(t, m.contents, key(8))
	assert.NotContains(t, f.entries, key(8))
	assert.Equal(t, 2, f.deleteCalls[key(8)])
}

func TestSummarizeKeys(t *testing.T) {
	assert.Equal(t, "", summarizeKeys(nil))
	assert.Equal(t, "a, b", summarizeKeys([]string{"a", "b"}))
	assert.Equal(t, "a, b, c", summarizeKeys([]string{"a", "b", "c"}))
	assert.Equal(t, "a, b, c and 2 more", summarizeKeys([]string{"a", "b", "c", "d", "e"}))
}

// An except CIDR is stored as its own deny entry, so widening the except adds a
// shorter deny and deletes the longer one. If the add fails and the sweep runs
// anyway, the traffic falls through to the enclosing allow, which neither the old
// nor the new policy permits. A transient rejection must not open that gap.
func TestBulkRefresh_TransientAddFailureDoesNotDropTheDenyItReplaces(t *testing.T) {
	allow16, deny24, deny23 := key(16), key(24), key(23)
	m, f := newTestMap(map[string][]byte{allow16: val(1), deny24: val(9)})

	// Reject the new deny once, as a per-CPU allocator refill does.
	failures := 1
	inner := m.updateEntry
	m.updateEntry = func(k, v []byte) error {
		if string(k) == deny23 && failures > 0 {
			failures--
			return fmt.Errorf("unable to update map: %w", unix.ENOMEM)
		}
		return inner(k, v)
	}

	err := m.BulkRefresh(map[string][]byte{allow16: val(1), deny23: val(9)})

	assert.NoError(t, err, "a transient rejection must be retried, not reported")
	assert.Equal(t, val(9), f.entries[deny23], "the replacement deny must land")
	assert.NotContains(t, f.entries, deny24, "the superseded deny is swept once its replacement is in")
	assert.Equal(t, val(1), f.entries[allow16])
}

// With the retries exhausted the add is reported, and the sweep still runs so a
// revoked allow cannot survive. The stale deny going with it is the residual case
// a persistent rejection leaves open.
func TestBulkRefresh_PersistentAddFailureStillSweeps(t *testing.T) {
	allow16, deny24, deny23 := key(16), key(24), key(23)
	m, f := newTestMap(map[string][]byte{allow16: val(1), deny24: val(9)})
	f.updateErrs[deny23] = fmt.Errorf("unable to update map: %w", unix.ENOSPC)

	err := m.BulkRefresh(map[string][]byte{allow16: val(1), deny23: val(9)})

	assert.Error(t, err, "an add the kernel keeps rejecting must be reported for requeue")
	assert.Contains(t, err.Error(), "1 of 1 map updates failed")
	assert.NotContains(t, f.entries, deny23)
	assert.NotContains(t, m.contents, deny23)
	assert.NotContains(t, f.entries, deny24)
}
