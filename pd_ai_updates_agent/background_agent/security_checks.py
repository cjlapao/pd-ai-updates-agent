import logging
from typing import List
from pd_ai_agent_core.messages.constants import (
    VM_STATE_STARTED,
    VM_RUN_UPDATE,
)
from pd_ai_agent_core.parallels_desktop.execute_on_vm import execute_on_vm
from pd_ai_agent_core.core_types.background_agent import BackgroundAgent
from pd_ai_agent_core.services.background_service import BackgroundAgentService
from pd_ai_agent_core.messages.background_message import BackgroundMessage
from pd_ai_agent_core.services.vm_datasource_service import VmDatasourceService
from pd_ai_agent_core.services.notification_service import NotificationService
from pd_ai_agent_core.common.constants import (
    NOTIFICATION_SERVICE_NAME,
    LOGGER_SERVICE_NAME,
    VM_DATASOURCE_SERVICE_NAME,
    BACKGROUND_SERVICE_NAME,
)
from pd_ai_agent_core.services.service_registry import ServiceRegistry
from pd_ai_updates_agent.datasource.background_security_datasource import (
    BackgroundSecurityDataSource,
)
from datetime import datetime, timedelta
import asyncio
from pd_ai_agent_core.messages.notification_message import (
    create_info_notification_message,
    create_warning_notification_message,
    NotificationAction,
    NotificationActionType,
)
from pd_ai_agent_core.services.log_service import LogService
from pd_ai_agent_core.messages.notification_message import (
    create_error_notification_message,
)

logger = logging.getLogger(__name__)


class SecurityUpdateChecksAgent(BackgroundAgent):
    def __init__(self, session_id: str):
        super().__init__(
            session_id=session_id,
            agent_type="security_checks_agent",
            interval=None,
        )
        self._security_datasource = BackgroundSecurityDataSource()
        self.subscribe_to(VM_STATE_STARTED)
        self.subscribe_to(VM_RUN_UPDATE)
        self.data = ServiceRegistry.get(
            session_id,
            VM_DATASOURCE_SERVICE_NAME,
            VmDatasourceService,
        )
        self._notifications_service = ServiceRegistry.get(
            session_id, NOTIFICATION_SERVICE_NAME, NotificationService
        )
        self._background_service = ServiceRegistry.get(
            session_id, BACKGROUND_SERVICE_NAME, BackgroundAgentService
        )
        self._logger = ServiceRegistry.get(session_id, LOGGER_SERVICE_NAME, LogService)
        self._time_delta_checks = timedelta(hours=1)
        if self._background_service is not None:
            vms = self.data.datasource.get_vms_by_state("running")
            for vm in vms:
                logger.info(
                    f"Posting VM_STATE_STARTED message for VM {vm.id} to check for updates"
                )
                self._background_service.post_message(
                    VM_STATE_STARTED,
                    {"vm_id": vm.id},
                )

    @property
    def session_id(self) -> str:
        """Get the session ID for this agent"""
        return self._session_id

    @session_id.setter
    def session_id(self, value: str) -> None:
        """Set the session ID for this agent"""
        self._session_id = value

    async def process(self) -> None:
        """Periodic check of VM states"""
        pass

    async def process_message(self, message: BackgroundMessage) -> None:
        """Handle VM state change events"""
        try:
            if message.message_type == VM_STATE_STARTED:
                await self._process_check_for_security(message)
            if message.message_type == VM_RUN_UPDATE:
                await self._process_run_update(message)
        except Exception as e:
            logger.error(f"Error processing security checks: {e}")

    def _get_os(self, vm_id: str) -> str | None:
        vm = self.data.datasource.get_vm(vm_id)
        if not vm:
            return None
        if vm.os:
            return vm.os
        else:
            return None

    def _get_list_updates_cmd(self, os: str) -> List[str]:
        if os.lower() == "ubuntu":
            return ["sudo", "apt", "list", "--upgradable"]
        elif os.lower() == "debian":
            return ["sudo", "apt", "list", "--upgradable"]
        elif os.lower() == "macos":
            return ["sudo", "brew", "list", "--upgradable"]
        else:
            return []

    def _run_update_cmd(self, os: str) -> List[str]:
        if os.lower() == "ubuntu":
            return [
                "sudo",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "upgrade",
                "-y",
            ]
        elif os.lower() == "debian":
            return [
                "sudo",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "upgrade",
                "-y",
            ]
        elif os.lower() == "macos":
            return ["sudo", "brew", "upgrade", "-y"]
        else:
            return []

    def _get_update_packages_cmd(self, os: str) -> List[str]:
        if os.lower() == "ubuntu":
            return ["sudo", "apt", "update"]
        elif os.lower() == "debian":
            return ["sudo", "apt", "update"]
        elif os.lower() == "macos":
            return ["sudo", "brew", "update"]
        else:
            return []

    async def _process_check_for_security(self, message: BackgroundMessage) -> None:
        vm_id = message.data.get("vm_id")
        if vm_id:
            if self._security_datasource.was_it_checked_in_threshold(
                vm_id, self._time_delta_checks
            ):
                logger.info(f"VM {vm_id} security checks are up to date")
                return
            waitFor = 30
            is_available = False
            while waitFor > 0:
                exec_result = execute_on_vm(vm_id, "echo 'hello'")
                if exec_result.exit_code == 0:
                    is_available = True
                    break
                await asyncio.sleep(1)
                waitFor -= 1
            if is_available:
                logger.info(f"VM {vm_id} is available, checking for updates")
                os = self._get_os(vm_id)
                if os:
                    have_updates, markdown_updates = (
                        await self._check_if_there_are_updates(os, vm_id)
                    )
                    if have_updates:
                        notification_message = create_info_notification_message(
                            session_id=self.session_id,
                            channel=vm_id,
                            message="Updates available",
                            details=markdown_updates,
                            data={
                                "vm_id": vm_id,
                            },
                            replace=True,
                            actions=[
                                NotificationAction(
                                    label="Update",
                                    value=VM_RUN_UPDATE,
                                    icon="cogs",
                                    kind=NotificationActionType.BACKGROUND_MESSAGE,
                                    data={
                                        "message_type": VM_RUN_UPDATE,
                                        "vm_id": vm_id,
                                    },
                                )
                            ],
                        )
                        await self._notifications_service.send(notification_message)
                        logger.info(f"VM {vm_id} has updates")
                    else:
                        logger.info(f"VM {vm_id} has no updates")

                self._security_datasource.update_vm(vm_id, datetime.now())

    async def _check_if_there_are_updates(
        self, os: str, vm_id: str
    ) -> tuple[bool, str]:
        if os.lower() == "ubuntu":
            return await self._check_if_there_are_updates_debian(os, vm_id)
        elif os.lower() == "debian":
            return await self._check_if_there_are_updates_debian(os, vm_id)
        elif os.lower() == "macos":
            return False, ""
        else:
            return False, ""

    async def _check_if_there_are_updates_debian(
        self,
        os: str,
        vm_id: str,
    ) -> tuple[bool, str]:
        update_result = execute_on_vm(
            vm_id, " ".join(self._get_update_packages_cmd(os))
        )
        if update_result.exit_code != 0:
            warn_notification = create_warning_notification_message(
                session_id=self.session_id,
                channel=vm_id,
                message=f"There was an error refreshing updates",
                details=f"Error: {update_result.error}, output: {update_result.output}",
                data={
                    "vm_id": vm_id,
                    "error": update_result.error,
                    "output": update_result.output,
                },
            )
            await self._notifications_service.send(warn_notification)
            self._logger.warning(
                vm_id,
                f"There was an error getting updates: {update_result.output}, error: {update_result.error}",
            )
        list_results = execute_on_vm(vm_id, " ".join(self._get_list_updates_cmd(os)))
        if list_results.exit_code == 0:
            updates = list_results.output.split("\n")[1:]
            updates = [update.split("/")[0] for update in updates]
            updates = [update for update in updates if update.strip()]
            if len(updates) > 0:
                markdown_updates = self._generate_update_markdown(list_results.output)
                return True, markdown_updates
            else:
                return False, ""
        else:
            return False, ""

    def _generate_update_markdown(self, output: str) -> str:
        updates = output.split("\n")[1:]
        updates = [update.split("/")[0] for update in updates]
        updates = [update for update in updates if update.strip()]
        updates = [f"- {update}" for update in updates]
        markdown_updates = "### Packages to be updated:\n\n"
        markdown_updates += "\n".join(updates)
        markdown_updates += "\n\n"
        return markdown_updates

    async def _process_run_update(self, message: BackgroundMessage) -> None:
        vm_id = message.data.get("vm_id")
        if vm_id:
            waitFor = 30
            is_available = False
            while waitFor > 0:
                exec_result = execute_on_vm(vm_id, "echo 'hello'")
                if exec_result.exit_code == 0:
                    is_available = True
                    break
                await asyncio.sleep(1)
                waitFor -= 1
            if is_available:
                logger.info(f"VM {vm_id} is available, running updates")
                os = self._get_os(vm_id)
                if os:
                    update_result = execute_on_vm(
                        vm_id, " ".join(self._get_update_packages_cmd(os))
                    )
                    run_updates = execute_on_vm(
                        vm_id, " ".join(self._run_update_cmd(os))
                    )
                    if run_updates.exit_code == 0:
                        # lets check if all updates were applied
                        have_updates, markdown_updates = (
                            await self._check_if_there_are_updates(os, vm_id)
                        )
                        if have_updates:
                            warning_header = f"Some updates were not applied to {vm_id}"
                            notification_message = create_warning_notification_message(
                                session_id=self.session_id,
                                channel=vm_id,
                                message=warning_header,
                                details=markdown_updates,
                                data={
                                    "vm_id": vm_id,
                                    "error": run_updates.error,
                                    "output": run_updates.output,
                                },
                            )
                            await self._notifications_service.send(notification_message)
                    else:
                        error_notification = create_error_notification_message(
                            session_id=self.session_id,
                            channel=vm_id,
                            message="Updates failed",
                            details=run_updates.error,
                            data={
                                "vm_id": vm_id,
                                "error": run_updates.error,
                                "output": run_updates.output,
                            },
                        )
                        await self._notifications_service.send(error_notification)
                        logger.error(f"VM {vm_id} updates failed")
