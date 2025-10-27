package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"go.goms.io/aks/AKSFlexNode/pkg/utils"
)

const (
	StateDir  = "/var/lib/aks-flex-node"
	StateFile = "bootstrap-state.json"
)

// BootstrapState tracks the progress of bootstrap operations
type BootstrapState struct {
	Version        string            `json:"version"`
	StartedAt      time.Time         `json:"started_at"`
	LastUpdated    time.Time         `json:"last_updated"`
	CompletedSteps map[string]bool   `json:"completed_steps"`
	FailedSteps    map[string]string `json:"failed_steps"`
	Configuration  map[string]string `json:"configuration"`
	VPNConnected   bool              `json:"vpn_connected"`
	ArcRegistered  bool              `json:"arc_registered"`
	KubeletRunning bool              `json:"kubelet_running"`
	LastError      string            `json:"last_error,omitempty"`
}

// StateManager manages bootstrap state persistence
type StateManager struct {
	statePath string
	logger    *logrus.Logger
}

// NewStateManager creates a new state manager
func NewStateManager(logger *logrus.Logger) *StateManager {
	return &StateManager{
		statePath: filepath.Join(StateDir, StateFile),
		logger:    logger,
	}
}

// LoadState loads the current bootstrap state
func (sm *StateManager) LoadState() (*BootstrapState, error) {
	// Ensure state directory exists using sudo if needed
	if err := utils.RunSystemCommand("mkdir", "-p", StateDir); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	// If state file doesn't exist, return a new state
	if _, err := os.Stat(sm.statePath); os.IsNotExist(err) {
		return sm.newBootstrapState(), nil
	}

	data, err := os.ReadFile(sm.statePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	var state BootstrapState
	if err := json.Unmarshal(data, &state); err != nil {
		sm.logger.Warnf("Failed to parse state file, creating new state: %v", err)
		return sm.newBootstrapState(), nil
	}

	return &state, nil
}

// SaveState persists the current bootstrap state
func (sm *StateManager) SaveState(state *BootstrapState) error {
	// Ensure state directory exists using sudo if needed
	if err := utils.RunSystemCommand("mkdir", "-p", StateDir); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	state.LastUpdated = time.Now()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}

	// Use atomic write operation for better reliability
	if err := utils.WriteFileAtomicSystem(sm.statePath, data, 0644); err != nil {
		return fmt.Errorf("failed to save state file: %w", err)
	}

	return nil
}

// MarkStepCompleted marks a bootstrap step as completed
func (sm *StateManager) MarkStepCompleted(state *BootstrapState, step string) error {
	if state.CompletedSteps == nil {
		state.CompletedSteps = make(map[string]bool)
	}

	state.CompletedSteps[step] = true

	// Remove from failed steps if it was there
	if state.FailedSteps != nil {
		delete(state.FailedSteps, step)
	}

	sm.logger.Infof("Step completed: %s", step)
	return sm.SaveState(state)
}

// MarkStepFailed marks a bootstrap step as failed
func (sm *StateManager) MarkStepFailed(state *BootstrapState, step, error string) error {
	if state.FailedSteps == nil {
		state.FailedSteps = make(map[string]string)
	}

	state.FailedSteps[step] = error
	state.LastError = error

	// Remove from completed steps if it was there
	if state.CompletedSteps != nil {
		delete(state.CompletedSteps, step)
	}

	sm.logger.Errorf("Step failed: %s - %s", step, error)
	return sm.SaveState(state)
}

// IsStepCompleted checks if a step has been completed
func (sm *StateManager) IsStepCompleted(state *BootstrapState, step string) bool {
	if state.CompletedSteps == nil {
		return false
	}
	return state.CompletedSteps[step]
}

// ClearState removes the state file (used for reset)
func (sm *StateManager) ClearState() error {
	// Check if file exists first
	if _, err := os.Stat(sm.statePath); os.IsNotExist(err) {
		sm.logger.Info("Bootstrap state file doesn't exist, nothing to clear")
		return nil
	}

	// Use sudo-aware file removal for system paths
	if err := utils.RunSystemCommand("rm", "-f", sm.statePath); err != nil {
		return fmt.Errorf("failed to remove state file: %w", err)
	}
	sm.logger.Info("Bootstrap state cleared")
	return nil
}

// newBootstrapState creates a new bootstrap state
func (sm *StateManager) newBootstrapState() *BootstrapState {
	return &BootstrapState{
		Version:        "1.0.0",
		StartedAt:      time.Now(),
		LastUpdated:    time.Now(),
		CompletedSteps: make(map[string]bool),
		FailedSteps:    make(map[string]string),
		Configuration:  make(map[string]string),
	}
}

// GetStateFilePath returns the path to the state file
func (sm *StateManager) GetStateFilePath() string {
	return sm.statePath
}
