//go:build !goexperiment.synctest && !deadlock_synctest && !deadlock_disable && go1.25

package deadlock

// shouldDisableTimerPool determines if timer pooling should be disabled
// In Go 1.25, timer pooling is enabled by default for performance. The synctest
// compatibility fix (skipping channel drain) is handled separately in releaseTimer().
func shouldDisableTimerPool() bool {
	switch Opts.TimerPool {
	case TimerPoolDefault:
		return false // Default: enable timer pooling for performance
	case TimerPoolEnabled:
		return false
	case TimerPoolDisabled:
		return true
	default:
		return false
	}
}
