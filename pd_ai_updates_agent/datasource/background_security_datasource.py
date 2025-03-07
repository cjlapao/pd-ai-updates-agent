from typing import Dict, Optional
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BackgroundSecurityDataSource:
    def __init__(self):
        self._vms: Dict[str, datetime] = {}
        self._last_update: Optional[datetime] = None
        self._cache_duration: timedelta = timedelta(minutes=10)

    def update_vm(self, vm_id: str, last_update: datetime) -> None:
        """Update the last update time for a VM"""
        self._vms[vm_id] = last_update

    def get_last_check(self, vm_id: str) -> Optional[datetime]:
        """Get the last update time for a VM"""
        return self._vms.get(vm_id)

    def is_cache_valid(self) -> bool:
        """Check if the cache is still valid"""
        if self._last_update is None:
            return False
        return datetime.now() - self._last_update < self._cache_duration

    def clear_cache(self) -> None:
        """Clear the cache"""
        self._vms.clear()
        self._last_update = None

    def was_it_checked_in_threshold(self, vm_id: str, threshold: timedelta) -> bool:
        """Check if the VM was checked in the last threshold"""
        last_check = self.get_last_check(vm_id)
        if last_check is None:
            return False
        return datetime.now() - last_check < threshold
