import random
import time


class ExponentialBackoff:
    def __init__(self, base_delay: float = 1.0, max_delay: float = 60.0, jitter: float = 0.2):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.jitter = jitter
        self.attempt = 0

    def reset(self) -> None:
        self.attempt = 0

    def next_delay(self) -> float:
        delay = min(self.max_delay, self.base_delay * (2 ** self.attempt))
        self.attempt += 1
        jitter_amount = delay * self.jitter
        return max(0.0, delay + random.uniform(-jitter_amount, jitter_amount))

    def sleep(self) -> float:
        delay = self.next_delay()
        time.sleep(delay)
        return delay
