from collections import deque
import numpy as np

class DriftMonitor:
    """Monitor if model behavior is drifting"""
    def __init__(self, baseline_errors, window_size=1000):
        self.baseline_mean = np.mean(baseline_errors)
        self.errors = deque(maxlen=window_size)

    def add_error(self, error):
        self.errors.append(error)

    def check_drift(self):
        if len(self.errors) < 100:
            return {"status": "insufficient_data"}

        current_mean = np.mean(self.errors)
        shift = 100 * (current_mean - self.baseline_mean) / self.baseline_mean

        if abs(shift) < 5:
            status = "normal"
        elif abs(shift) < 15:
            status = "gradual_drift"
        else:
            status = "sudden_drift"

        return {"status": status, "shift_pct": shift}
