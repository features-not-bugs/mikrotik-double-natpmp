package utility

import (
	"fmt"
	"strings"
)

// Transaction manages a series of operations with rollback capability
type Transaction struct {
	rollbacks []func() error
	committed bool
}

// NewTransaction creates a new transaction
func NewTransaction() *Transaction {
	return &Transaction{
		rollbacks: make([]func() error, 0),
	}
}

// AddRollback adds a rollback function to the transaction
// Rollback functions are executed in reverse order (LIFO)
func (t *Transaction) AddRollback(fn func() error) {
	t.rollbacks = append(t.rollbacks, fn)
}

// Commit marks the transaction as successful and clears rollback functions
func (t *Transaction) Commit() error {
	t.committed = true
	t.rollbacks = nil
	return nil
}

func (t *Transaction) Committed() bool {
	return t.committed
}

// Rollback executes all rollback functions in reverse order
// Collects all errors and returns them as a single error
func (t *Transaction) Rollback() error {
	if t.committed {
		return nil
	}

	var errors []string

	// Execute rollbacks in reverse order (LIFO)
	for i := len(t.rollbacks) - 1; i >= 0; i-- {
		if err := t.rollbacks[i](); err != nil {
			errors = append(errors, err.Error())
		}
	}

	t.rollbacks = nil

	if len(errors) > 0 {
		return fmt.Errorf("rollback errors: %s", strings.Join(errors, "; "))
	}

	return nil
}
