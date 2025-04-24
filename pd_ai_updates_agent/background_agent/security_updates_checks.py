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
from pd_ai_updates_agent.datasource.background_updates_datasource import (
    BackgroundSecurityDataSource,
)
from datetime import datetime, timedelta
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
from pd_ai_agent_core.parallels_desktop.os import (
    get_std_os,
    get_updates,
    update_vm_packages,
)
from pd_ai_agent_core.parallels_desktop.models.update_package import (
    UpdatePackageResponse,
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
            logger.info(f"Processing message1: {message.message_type}")
            if message.message_type == VM_STATE_STARTED:
                await self._process_check_for_security(message)
            if message.message_type == VM_RUN_UPDATE:
                logger.info(f"Processing message1: {message.message_type}")
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
        os = get_std_os(os)
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
            vm = self.data.datasource.get_vm(vm_id)
            if not vm:
                logger.error(f"VM {vm_id} was not found")
                return
            logger.info(f"VM {vm_id} is available, checking for updates")
            os = self._get_os(vm_id)
            if os:
                have_updates, markdown_updates = await self._check_if_there_are_updates(
                    os, vm_id
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
                                icon="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8cGF0aAogICAgZD0iTTExLjU0NzMgMjEuNjI3MUMxMS4yMzA2IDIxLjYyNzEgMTAuOTU0OCAyMS41Mzc3IDEwLjcxOTggMjEuMzU4OUMxMC40ODk5IDIxLjE4MDEgMTAuMzM5MiAyMC45Mzc0IDEwLjI2NzcgMjAuNjMxTDkuOTUzNTcgMTkuMjc0OEw5Ljc0NjcgMTkuMjA1OEw4LjU3NDM3IDE5LjkyNjFDOC4zMDg3NCAyMC4wOTQ2IDguMDI3NzggMjAuMTU4NSA3LjczMTUyIDIwLjExNzdDNy40NDAzNSAyMC4wODE4IDcuMTgyMzggMTkuOTUxNiA2Ljk1NzYyIDE5LjcyNjlMNS44ODQ5MSAxOC42NjE4QzUuNjU1MDQgMTguNDMyIDUuNTIyMjMgMTguMTcxNCA1LjQ4NjQ3IDE3Ljg4MDNDNS40NTA3MSAxNy41ODkxIDUuNTE3MTIgMTcuMzEwNyA1LjY4NTY5IDE3LjA0NTFMNi40MjEyNyAxNS44NzI3TDYuMzUyMzIgMTUuNjgxMkw0Ljk5NjA5IDE1LjM2N0M0LjY5NDcxIDE1LjI5NTUgNC40NTIwNyAxNS4xNDIzIDQuMjY4MTcgMTQuOTA3M0M0LjA4OTM4IDE0LjY3MjMgNCAxNC4zOTkgNCAxNC4wODc0VjEyLjU3OEM0IDEyLjI2NjQgNC4wODkzOCAxMS45OTU2IDQuMjY4MTcgMTEuNzY1OEM0LjQ0Njk1IDExLjUzMDggNC42ODk1OSAxMS4zNzUgNC45OTYwOSAxMS4yOTg0TDYuMzM2OTkgMTAuOTc2Nkw2LjQxMzYgMTAuNzY5N0w1LjY3ODA0IDkuNTk3MzZDNS41MDk0NyA5LjMzNjg0IDUuNDQzMDYgOS4wNjA5OSA1LjQ3ODggOC43Njk4M0M1LjUxNDU2IDguNDc4NjYgNS42NDczNyA4LjIxODE0IDUuODc3MjUgNy45ODgyOEw2Ljk0OTk2IDYuOTE1NTZDNy4xNzQ3MiA2LjY5MDgxIDcuNDMyNjkgNi41NjA1NSA3LjcyMzg2IDYuNTI0NzlDOC4wMTUwMiA2LjQ4MzkyIDguMjkzNDIgNi41NDUyMyA4LjU1OTA0IDYuNzA4NjhMOS43MzkwMyA3LjQzNjZMOS45NTM1NyA3LjM1MjMxTDEwLjI2NzcgNS45OTYwOUMxMC4zMzkyIDUuNjk0NzEgMTAuNDg5OSA1LjQ1NDY0IDEwLjcxOTggNS4yNzU4NUMxMC45NTQ4IDUuMDkxOTUgMTEuMjMwNiA1IDExLjU0NzMgNUgxMy4xMDI4QzEzLjQxOTUgNSAxMy42OTI4IDUuMDkxOTUgMTMuOTIyNiA1LjI3NTg1QzE0LjE1MjUgNS40NTQ2NCAxNC4zMDMyIDUuNjk0NzEgMTQuMzc0NyA1Ljk5NjA5TDE0LjY4ODggNy4zNTIzMUwxNC45MDM0IDcuNDM2NkwxNi4wODMzIDYuNzA4NjhDMTYuMzQ5IDYuNTQ1MjMgMTYuNjI3NCA2LjQ4MzkyIDE2LjkxODUgNi41MjQ3OUMxNy4yMTQ4IDYuNTYwNTUgMTcuNDcyOCA2LjY5MDgxIDE3LjY5MjQgNi45MTU1NkwxOC43NjUyIDcuOTg4MjhDMTguOTg5OSA4LjIxODE0IDE5LjEyMDIgOC40Nzg2NiAxOS4xNTU5IDguNzY5ODNDMTkuMTk2NyA5LjA2MDk5IDE5LjEzMyA5LjMzNjg0IDE4Ljk2NDQgOS41OTczNkwxOC4yMjg4IDEwLjc2OTdMMTguMzEzMSAxMC45NzY2TDE5LjY0NjMgMTEuMjk4NEMxOS45NDc2IDExLjM2OTkgMjAuMTg3OCAxMS41MjMxIDIwLjM2NjYgMTEuNzU4MUMyMC41NTA1IDExLjk5MzEgMjAuNjQyNCAxMi4yNjY0IDIwLjY0MjQgMTIuNTc4VjE0LjA4NzRDMjAuNjQyNCAxNC4zOTkgMjAuNTUwNSAxNC42NzIzIDIwLjM2NjYgMTQuOTA3M0MyMC4xODc4IDE1LjEzNzIgMTkuOTQ3NiAxNS4yOTA0IDE5LjY0NjMgMTUuMzY3TDE4LjI5NzggMTUuNjgxMkwxOC4yMjExIDE1Ljg3MjdMMTguOTU2NyAxNy4wNDUxQzE5LjEyNTMgMTcuMzEwNyAxOS4xODkxIDE3LjU4OTEgMTkuMTQ4MyAxNy44ODAzQzE5LjExMjYgMTguMTcxNCAxOC45ODIyIDE4LjQzMiAxOC43NTc1IDE4LjY2MThMMTcuNjg0NyAxOS43MjY5QzE3LjQ2IDE5Ljk1MTYgMTcuMTk5NSAyMC4wODE4IDE2LjkwMzIgMjAuMTE3N0MxNi42MTIxIDIwLjE1ODUgMTYuMzMzNyAyMC4wOTQ2IDE2LjA2OCAxOS45MjYxTDE0Ljg4ODEgMTkuMjA1OEwxNC42ODg4IDE5LjI3NDhMMTQuMzc0NyAyMC42MzFDMTQuMzAzMiAyMC45Mzc0IDE0LjE1MjUgMjEuMTgwMSAxMy45MjI2IDIxLjM1ODlDMTMuNjkyOCAyMS41Mzc3IDEzLjQxOTUgMjEuNjI3MSAxMy4xMDI4IDIxLjYyNzFIMTEuNTQ3M1pNMTEuNzM4OSAyMC4yNDAySDEyLjkxMTJDMTMuMDMzOCAyMC4yNDAyIDEzLjEwMjggMjAuMTgxNCAxMy4xMTgxIDIwLjA2NEwxMy41Nzc4IDE4LjE3OTFDMTMuODMzMiAxOC4xMjI4IDE0LjA3MDggMTguMDQ4OSAxNC4yOTA0IDE3Ljk1NjlDMTQuNTEwMSAxNy44NTk5IDE0LjcxNDQgMTcuNzUyNSAxNC45MDM0IDE3LjYzNUwxNi41NTA3IDE4LjY0NjVDMTYuNjQ3OCAxOC43MTI5IDE2Ljc0MjMgMTguNzAyNyAxNi44MzQyIDE4LjYxNTlMMTcuNjQ2NSAxNy43OTZDMTcuNzI4MiAxNy43MjQ0IDE3LjczNTkgMTcuNjMyNSAxNy42Njk0IDE3LjUyMDFMMTYuNjU4IDE1Ljg4MDRDMTYuNzY1NCAxNS42OTY1IDE2Ljg2NSAxNS40OTIyIDE2Ljk1NjkgMTUuMjY3NEMxNy4wNTQgMTUuMDQyNyAxNy4xMzA1IDE0LjgxMDMgMTcuMTg2NyAxNC41NzAyTDE5LjA3OTMgMTQuMTE4MUMxOS4xOTY3IDE0LjA5NzcgMTkuMjU1NSAxNC4wMjYxIDE5LjI1NTUgMTMuOTAzNVYxMi43NTQyQzE5LjI1NTUgMTIuNjM2NyAxOS4xOTY3IDEyLjU2NTIgMTkuMDc5MyAxMi41Mzk3TDE3LjE5NDQgMTIuMDg3NkMxNy4xMzMgMTEuODMyMiAxNy4wNTE0IDExLjU4OTUgMTYuOTQ5MSAxMS4zNTk3QzE2Ljg1MjEgMTEuMTI5OCAxNi43NTc2IDEwLjkzMzEgMTYuNjY1NiAxMC43Njk3TDE3LjY3NzEgOS4xMjIzQzE3Ljc0ODYgOS4wMTUwMiAxNy43NDEgOC45MTc5NyAxNy42NTQxIDguODMxMTRMMTYuODQxOSA4LjAzNDI2QzE2Ljc1NSA3Ljk1MjUzIDE2LjY1OCA3LjkzOTc2IDE2LjU1MDcgNy45OTU5NUwxNC45MDM0IDguOTk5NzFDMTQuNzE0NCA4Ljg5MjQzIDE0LjUwNzUgOC43OTI4MiAxNC4yODI3IDguNzAwODdDMTQuMDYzMSA4LjYwMzgyIDEzLjgyODEgOC41MjQ2NCAxMy41Nzc4IDguNDYzMzVMMTMuMTE4MSA2LjU2MzExQzEzLjEwMjggNi40NDU2MSAxMy4wMzM4IDYuMzg2ODcgMTIuOTExMiA2LjM4Njg3SDExLjczODlDMTEuNjExMiA2LjM4Njg3IDExLjUzNzEgNi40NDU2MSAxMS41MTY3IDYuNTYzMTFMMTEuMDcyMyA4LjQ0ODAyQzEwLjgyNzEgOC41MDkzMSAxMC41ODQ0IDguNTkxMDQgMTAuMzQ0MyA4LjY5MzIxQzEwLjEwOTQgOC43OTAyNiA5LjkwNTA1IDguODg5ODcgOS43MzEzNiA4Ljk5MjA0TDguMDgzOTggNy45OTU5NUM3Ljk4MTgxIDcuOTM5NzYgNy44ODczMSA3Ljk0OTk3IDcuODAwNDcgOC4wMjY1OUw2Ljk4MDYyIDguODMxMTRDNi44OTg4OSA4LjkxNzk3IDYuODkxMjIgOS4wMTUwMiA2Ljk1NzYyIDkuMTIyM0w3Ljk2OTA0IDEwLjc2OTdDNy44ODIyMSAxMC45MzMxIDcuNzg3NzEgMTEuMTI5OCA3LjY4NTU0IDExLjM1OTdDNy41ODMzOCAxMS41ODk1IDcuNTA0MTkgMTEuODMyMiA3LjQ0OCAxMi4wODc2TDUuNTYzMDkgMTIuNTM5N0M1LjQ0NTYxIDEyLjU2NTIgNS4zODY4NyAxMi42MzY3IDUuMzg2ODcgMTIuNzU0MlYxMy45MDM1QzUuMzg2ODcgMTQuMDI2MSA1LjQ0NTYxIDE0LjA5NzcgNS41NjMwOSAxNC4xMTgxTDcuNDQ4IDE0LjU2MjVDNy41MDkzMSAxNC44MDc3IDcuNTg4NDggMTUuMDQyNyA3LjY4NTU0IDE1LjI2NzRDNy43ODI1OSAxNS40ODcxIDcuODgyMjEgMTUuNjkxNCA3Ljk4NDM4IDE1Ljg4MDRMNi45NjUyOSAxNy41Mjc4QzYuOTAzOTkgMTcuNjM1IDYuOTExNjUgMTcuNzI3IDYuOTg4MjcgMTcuODAzNkw3LjgwODE0IDE4LjYxNTlDNy45MDAwOSAxOC43MDI3IDcuOTkyMDMgMTguNzE1NSA4LjA4Mzk4IDE4LjY1NDFMOS43MzkwMyAxNy42MzVDOS45MjgwMyAxNy43NTI1IDEwLjEzNDkgMTcuODU5OSAxMC4zNTk3IDE3Ljk1NjlDMTAuNTg5NSAxOC4wNDg5IDEwLjgyNDUgMTguMTIyOCAxMS4wNjQ2IDE4LjE3OTFMMTEuNTE2NyAyMC4wNjRDMTEuNTM3MSAyMC4xODE0IDExLjYxMTIgMjAuMjQwMiAxMS43Mzg5IDIwLjI0MDJaTTEyLjMyMTIgMTYuMjI1MkMxMS43OSAxNi4yMjUyIDExLjMwMjEgMTYuMDk1IDEwLjg1NzcgMTUuODM0NEMxMC40MTg0IDE1LjU2ODggMTAuMDY2IDE1LjIxNjMgOS44MDAzMiAxNC43NzdDOS41Mzk4MSAxNC4zMzc3IDkuNDA5NTUgMTMuODQ5OSA5LjQwOTU1IDEzLjMxMzZDOS40MDk1NSAxMi43ODIzIDkuNTM5ODEgMTIuMjk3IDkuODAwMzIgMTEuODU3N0MxMC4wNjYgMTEuNDE4NCAxMC40MTg0IDExLjA2ODUgMTAuODU3NyAxMC44MDhDMTEuMzAyMSAxMC41NDc1IDExLjc5IDEwLjQxNzIgMTIuMzIxMiAxMC40MTcyQzEyLjg1NzYgMTAuNDE3MiAxMy4zNDU0IDEwLjU0NzUgMTMuNzg0NyAxMC44MDhDMTQuMjI0IDExLjA2ODUgMTQuNTczOSAxMS40MTg0IDE0LjgzNDQgMTEuODU3N0MxNS4wOTQ5IDEyLjI5NyAxNS4yMjUyIDEyLjc4MjMgMTUuMjI1MiAxMy4zMTM2QzE1LjIyNTIgMTMuODQ0OCAxNS4wOTQ5IDE0LjMzMjYgMTQuODM0NCAxNC43NzdDMTQuNTczOSAxNS4yMjE0IDE0LjIyNCAxNS41NzM5IDEzLjc4NDcgMTUuODM0NEMxMy4zNDU0IDE2LjA5NSAxMi44NTc2IDE2LjIyNTIgMTIuMzIxMiAxNi4yMjUyWk0xMi4zMjEyIDE0LjkwNzNDMTIuNjA3MyAxNC45MDczIDEyLjg3MDMgMTQuODM1OCAxMy4xMTA0IDE0LjY5MjhDMTMuMzUwNSAxNC41NDQ2IDEzLjUzOTUgMTQuMzUwNSAxMy42Nzc0IDE0LjExMDRDMTMuODIwNSAxMy44NzAzIDEzLjg5MiAxMy42MDQ3IDEzLjg5MiAxMy4zMTM2QzEzLjg5MiAxMy4wMjI0IDEzLjgyMDUgMTIuNzU5MyAxMy42Nzc0IDEyLjUyNDNDMTMuNTM5NSAxMi4yODQzIDEzLjM1MDUgMTIuMDkyNyAxMy4xMTA0IDExLjk0OTdDMTIuODcwMyAxMS44MDY2IDEyLjYwNzMgMTEuNzM1MSAxMi4zMjEyIDExLjczNTFDMTIuMDMgMTEuNzM1MSAxMS43NjQ0IDExLjgwNjYgMTEuNTI0MyAxMS45NDk3QzExLjI4NDMgMTIuMDkyNyAxMS4wOTI3IDEyLjI4NDMgMTAuOTQ5NyAxMi41MjQzQzEwLjgwNjYgMTIuNzU5MyAxMC43MzUxIDEzLjAyMjQgMTAuNzM1MSAxMy4zMTM2QzEwLjczNTEgMTMuNjA5OCAxMC44MDY2IDEzLjg3OCAxMC45NDk3IDE0LjExODFDMTEuMDkyNyAxNC4zNTgyIDExLjI4NDMgMTQuNTQ5NyAxMS41MjQzIDE0LjY5MjhDMTEuNzY0NCAxNC44MzU4IDEyLjAzIDE0LjkwNzMgMTIuMzIxMiAxNC45MDczWiIKICAgIGZpbGw9ImJsYWNrIiAvPgo8L3N2Zz4=",
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
        self,
        os: str,
        vm_id: str,
    ) -> tuple[bool, str]:
        list_results = get_updates(vm_id, os)
        return list_results.has_updates(), self._generate_update_markdown(list_results)

    def _generate_update_markdown(self, packages: UpdatePackageResponse) -> str:
        updates = [f"- {update.name} ({update.version})" for update in packages.updates]
        markdown_updates = "### Packages to be updated:\n\n"
        markdown_updates += "\n".join(updates)
        markdown_updates += "\n\n"
        return markdown_updates

    async def _process_run_update(self, message: BackgroundMessage) -> None:
        vm_id = message.data.get("vm_id")
        if vm_id:
            logger.info(f"VM {vm_id} is available, running updates")
            os = self._get_os(vm_id)
            if os:
                run_updates = update_vm_packages(vm_id, os)
                if run_updates:
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
                            },
                        )
                        await self._notifications_service.send(notification_message)
                else:
                    error_notification = create_error_notification_message(
                        session_id=self.session_id,
                        channel=vm_id,
                        message="Updates failed",
                        details="Failed to update",
                        data={
                            "vm_id": vm_id,
                        },
                    )
                    await self._notifications_service.send(error_notification)
                    logger.error(f"VM {vm_id} updates failed")
