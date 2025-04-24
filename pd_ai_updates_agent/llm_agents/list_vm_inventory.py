from pd_ai_agent_core.core_types.llm_chat_ai_agent import (
    LlmChatAgent,
    LlmChatAgentResponse,
    AgentFunctionDescriptor,
    AttachmentContextVariable,
    AttachmentType,
)
from pd_ai_agent_core.services.service_registry import ServiceRegistry
from pd_ai_agent_core.services.notification_service import NotificationService
from pd_ai_agent_core.services.log_service import LogService
from pd_ai_agent_core.services.vm_datasource_service import VmDatasourceService

from pd_ai_agent_core.messages import (
    create_agent_function_call_chat_message,
    create_clean_agent_function_call_chat_message,
)
import json
import logging

from pd_ai_agent_core.helpers import (
    get_context_variable,
)
from pd_ai_agent_core.common import (
    NOTIFICATION_SERVICE_NAME,
    LOGGER_SERVICE_NAME,
    VM_DATASOURCE_SERVICE_NAME,
)
import openai
from typing import List
from pd_ai_agent_core.parallels_desktop.os import (
    get_vm_details,
    get_os_version,
    get_inventory,
)
from pd_ai_agent_core.parallels_desktop.models.update_package import (
    app_packages_to_csv,
)
from typing import Optional
from thefuzz import process

logger = logging.getLogger(__name__)


def ANALYZE_UPDATES_WITH_LLM_PROMPT(context_variables) -> str:
    result = """You are an AI specialized in security analysis of virtual machines (VMs).
Your task is to evaluate the security posture of a VM by analyzing its operating system (OS) version and the output of package updates.
Follow these steps to generate a comprehensive security report: 
1.**Input Data**: 
  This will be provided by the user, you need to analyze the OS version and the package update output.
  - OS Version
  - Installed Packages
  - Available Updates
2.**Analysis**:
  - Determine if the OS version is up-to-date with the latest security patches.
  - Identify any outdated packages listed in the package update output.
  - Highlight any known vulnerabilities associated with the current OS version and outdated packages.\
3.**Reporting**:
  - Generate a concise response summarizing the findings, including: 
  - The current OS version and its support status.
  - A list of outdated packages and their respective versions.
  - Summary of any identified vulnerabilities.
4.**Recommendations**:
- For each outdated package and OS version, provide potential fixes and recommended actions: 
- Suggested updates or upgrades for the OS.- Commands for updating packages.
- Additional security best practices that could enhance the VM's security.
5.**Output Format**:
  - Present the final report in a structured format: 
    - **Summary of Findings**:
      - OS Version: [insert OS version]
      - Package Status: [list of outdated packages]
      - Vulnerabilities Detected: [list of vulnerabilities]
    - **Recommendations**: 
      - OS Update: [insert recommended OS update actions]
      - Package Updates: [insert specific commands to update packages]
      - Additional Security Measures: [insert best practices]
      
Ensure that your analysis and recommendations are clear, direct, and actionable for a security administrator to implement.


"""

    if context_variables is not None:
        result += f"""Use the provided context in JSON format: {json.dumps(context_variables)}\
If the user has provided a vm id, use it to perform the operation on the VM.
If the user has provided a vm name, use it on your responses to the user to identify the VM instead of the vm id.

"""
    return result


def LIST_VM_INVENTORY_PROMPT(context_variables) -> str:
    result = """You are a seasoned software analyst with very deep knowledge of software.
Your job is to get a vm or vms inventory or list of current installed applications and list it in a nice way

You will need to resume the OS of the VM and any other details and return a nice markdown formatted table with:
name,version, description.

Something like this template

[Talk about the vm]
Name | Version | Description

if you are analyzing more than one VM adjust the output to be easy to read and still helpful.
You also can search for a specific application by name and return the details of the application. just pass the name of the application to the function list_vms_inventory_tool.
"""
    if context_variables is not None:
        result += f"""Use the provided context in JSON format: {json.dumps(context_variables)}\
If the user has provided a vm id, use it to perform the operation on the VM.
If the user has provided a vm name, use it on your responses to the user to identify the VM instead of the vm id.

"""
    return result


LIST_VM_INVENTORY_TRANSFER_INSTRUCTIONS = """
Call this function if the user is asking you to list the inventory or applications of a VM or VMs.
If you are listing just one VM, use the vm_id or vm_name to identify the VM.
Check the context or history of the conversation for this information.
"""


class ListVmInventoryAgent(LlmChatAgent):
    def __init__(self):
        super().__init__(
            name="List VM Inventory Agent",
            instructions=LIST_VM_INVENTORY_PROMPT,
            description="This agent is responsible for listing all applications of a VM.",
            icon="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjwhLS0gVXBsb2FkZWQgdG86IFNWRyBSZXBvLCB3d3cuc3ZncmVwby5jb20sIEdlbmVyYXRvcjogU1ZHIFJlcG8gTWl4ZXIgVG9vbHMgLS0+Cjxzdmcgd2lkdGg9IjgwMHB4IiBoZWlnaHQ9IjgwMHB4IiB2aWV3Qm94PSIwIDAgMTYgMTYiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+DQogICAgPHBhdGggZD0ibSA4IDAgYyAtMC43Njk1MzEgMCAtMS41MzkwNjIgMC4yOTI5NjkgLTIuMTIxMDk0IDAuODc1IGwgLTUuMDAzOTA2IDUuMDAzOTA2IGMgLTEuMTY0MDYyIDEuMTY0MDYzIC0xLjE2NDA2MiAzLjA3ODEyNSAwIDQuMjQyMTg4IGwgNS4wMDM5MDYgNS4wMDM5MDYgYyAxLjE2NDA2MyAxLjE2NDA2MiAzLjA3ODEyNSAxLjE2NDA2MiA0LjI0MjE4OCAwIGwgNS4wMDc4MTIgLTUuMDAzOTA2IGMgMS4xNjQwNjMgLTEuMTY0MDYzIDEuMTY0MDYzIC0zLjA3ODEyNSAwIC00LjI0MjE4OCBsIC01LjAwNzgxMiAtNS4wMDM5MDYgYyAtMC41ODIwMzIgLTAuNTgyMDMxIC0xLjM1MTU2MyAtMC44NzUgLTIuMTIxMDk0IC0wLjg3NSB6IG0gMC4xMDE1NjIgMS45ODgyODEgYyAwLjIxMDkzOCAwLjAyMzQzOCAwLjQxNDA2MyAwLjExNzE4OCAwLjU4NTkzOCAwLjI4MTI1IGwgLTAuMzM5ODQ0IDAuMTEzMjgxIGMgLTAuMDc0MjE4IC0wLjEzNjcxOCAtMC4xNTYyNSAtMC4yNjk1MzEgLTAuMjQ2MDk0IC0wLjM5NDUzMSB6IG0gLTEuNTcwMzEyIDEuMDU4NTk0IGMgMC4zMDA3ODEgMC40MjE4NzUgMC40NjQ4NDQgMC45Mjk2ODcgMC40Njg3NSAxLjQ1MzEyNSBjIDAgMS4zNzg5MDYgLTEuMTIxMDk0IDIuNSAtMi41IDIuNSBjIC0wLjUyMzQzOCAtMC4wMDM5MDYgLTEuMDMxMjUgLTAuMTcxODc1IC0xLjQ0OTIxOSAtMC40NzI2NTYgeiBtIDMuNDQxNDA2IDAuNTAzOTA2IGwgMy43NDIxODggMy43NDIxODggYyAwLjQwMjM0NCAwLjQwMjM0MyAwLjQwMjM0NCAxLjAxMTcxOSAwIDEuNDE0MDYyIGwgLTAuMjUzOTA2IDAuMjUgYyAtMC4wMzkwNjMgLTAuMDQ2ODc1IC0wLjA3NDIxOSAtMC4wOTM3NSAtMC4xMTcxODggLTAuMTQwNjI1IGwgMC42MjEwOTQgLTAuODU1NDY4IGwgLTAuODA4NTk0IC0wLjU4NTkzOCBsIC0wLjYyMTA5NCAwLjg1MTU2MiBjIC0wLjE2Nzk2OCAtMC4wNzgxMjQgLTAuMzQ3NjU2IC0wLjEzNjcxOCAtMC41MzUxNTYgLTAuMTc1NzgxIHYgLTEuMDUwNzgxIGggLTEgdiAxLjA1MDc4MSBjIC0wLjE4MzU5NCAwLjAzOTA2MyAtMC4zNjMyODEgMC4wOTc2NTcgLTAuNTMxMjUgMC4xNzU3ODEgbCAtMC42MjEwOTQgLTAuODUxNTYyIGwgLTAuODA0Njg3IDAuNTg1OTM4IGwgMC42MTcxODcgMC44NTU0NjggYyAtMC4xMjUgMC4xMzY3MTkgLTAuMjM4MjgxIDAuMjg5MDYzIC0wLjMzMjAzMSAwLjQ1MzEyNSBsIC0xIC0wLjMyNDIxOSBsIC0wLjMwODU5NCAwLjk0OTIxOSBsIDEgMC4zMjQyMTkgYyAtMC4wMTE3MTkgMC4wOTM3NSAtMC4wMTk1MzEgMC4xODc1IC0wLjAxOTUzMSAwLjI4MTI1IHMgMC4wMDc4MTIgMC4xODc1IDAuMDE5NTMxIDAuMjgxMjUgbCAtMSAwLjMyNDIxOSBsIDAuMzA4NTk0IDAuOTQ5MjE5IGwgMSAtMC4zMjQyMTkgYyAwLjA5Mzc1IDAuMTY0MDYyIDAuMjA3MDMxIDAuMzE2NDA2IDAuMzMyMDMxIDAuNDUzMTI1IGwgLTAuNjE3MTg3IDAuODU1NDY4IGwgMC4xOTUzMTIgMC4xNDA2MjYgbCAtMC41MzEyNSAwLjUzMTI1IGMgLTAuNDAyMzQzIDAuNDA2MjUgLTEuMDExNzE5IDAuNDA2MjUgLTEuNDE0MDYyIDAgbCAtNC45MDIzNDQgLTQuOTAyMzQ0IGwgMC4wMjczNDQgLTAuMDM5MDYzIGwgMC4yMDcwMzEgLTAuMjg5MDYyIGMgMC4zMzIwMzEgMC4xNTIzNDMgMC42ODM1OTQgMC4yNjk1MzEgMS4wNDY4NzUgMC4zMzk4NDMgdiAxLjE3OTY4OCBoIDEuNjUyMzQ0IHYgLTEuMTc5Njg4IGMgMC4zNjMyODEgLTAuMDcwMzEyIDAuNzE0ODQzIC0wLjE4NzUgMS4wNDY4NzUgLTAuMzM5ODQzIGwgMC4yMDcwMzEgMC4yODkwNjIgbCAwLjQ4NDM3NSAwLjY2Nzk2OSBsIDEuMzMyMDMxIC0wLjk3MjY1NiBsIC0wLjQ4MDQ2OSAtMC42Njc5NjkgbCAtMC4yMTA5MzcgLTAuMjg5MDYzIGMgMC4yNSAtMC4yNjk1MzEgMC40Njg3NSAtMC41NjY0MDYgMC42NDQ1MzEgLTAuODkwNjI0IGwgMC4zMzk4NDQgMC4xMTMyODEgbCAwLjc4NTE1NiAwLjI1MzkwNiBsIDAuNTExNzE5IC0xLjU2NjQwNiBsIC0wLjc4NTE1NiAtMC4yNTc4MTMgbCAtMC4zMzk4NDQgLTAuMTA5Mzc1IGMgMC4wMjM0MzcgLTAuMTc5Njg3IDAuMDM5MDYzIC0wLjM2MzI4MSAwLjAzOTA2MyAtMC41NTA3ODEgcyAtMC4wMTU2MjYgLTAuMzcxMDk0IC0wLjAzOTA2MyAtMC41NTA3ODEgbCAwLjMzOTg0NCAtMC4xMDkzNzUgbCAwLjc4NTE1NiAtMC4yNTc4MTMgeiBtIDEuNTI3MzQ0IDUuNDQ5MjE5IGMgMC41MjczNDQgMCAwLjk4NDM3NSAwLjI2NTYyNSAxLjI1IDAuNjY3OTY5IGwgLTIuMDc4MTI1IDIuMDgyMDMxIGMgLTAuNDA2MjUgLTAuMjY5NTMxIC0wLjY3MTg3NSAtMC43MjI2NTYgLTAuNjcxODc1IC0xLjI1IGMgMCAtMC44MzU5MzggMC42Njc5NjkgLTEuNSAxLjUgLTEuNSB6IG0gMCAwIiBmaWxsPSIjMmUzNDM2Ii8+DQo8L3N2Zz4=",
            functions=[self.list_vm_inventory_tool, self.list_vms_inventory_tool],  # type: ignore
            function_descriptions=[
                AgentFunctionDescriptor(
                    name=self.list_vm_inventory_tool.__name__,
                    description="Listing VM inventory",
                ),
                AgentFunctionDescriptor(
                    name=self.list_vms_inventory_tool.__name__,
                    description="Listing VMs inventory",
                ),
            ],
            transfer_instructions=LIST_VM_INVENTORY_TRANSFER_INSTRUCTIONS,
        )

    def fuzzy_lib_search(self, app_list, search_term, threshold=70):
        """Use thefuzz library for fuzzy matching"""
        app_names = {app.name: app for app in app_list}
        matches = process.extractBests(
            search_term, app_names.keys(), score_cutoff=threshold
        )
        return [app_names[name] for name, score in matches]

    def list_vm_inventory_tool(
        self,
        session_context: dict,
        context_variables: dict,
        vm_id: str,
        os: str,
        application_name: Optional[str] = None,
    ) -> LlmChatAgentResponse:
        """This function is used to list a vm applications"""
        try:
            ns = ServiceRegistry.get(
                session_context["session_id"],
                NOTIFICATION_SERVICE_NAME,
                NotificationService,
            )
            ls = ServiceRegistry.get(
                session_context["session_id"], LOGGER_SERVICE_NAME, LogService
            )
            ls.info(
                session_context["channel"],
                f"listing applications for {vm_id} with args {session_context}, {context_variables}",
            )

            if not vm_id:
                context_vm_id = get_context_variable(
                    "vm_id", session_context, context_variables
                )
                if not context_vm_id:
                    return LlmChatAgentResponse(
                        status="error",
                        message="No VM ID provided",
                        error="No VM ID provided",
                    )
                vm_id = context_vm_id

            ns.send_sync(
                create_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    name=f"Gathering information about vm",
                    arguments={},
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )

            vm_details, error = get_vm_details(
                session_context, context_variables, vm_id
            )
            if error:
                return error
            if not vm_details:
                return LlmChatAgentResponse(
                    status="error",
                    message="No vm details provided",
                )
            os = vm_details.os
            ns.send_sync(
                create_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    name=f"Getting OS version for {vm_details.name}",
                    arguments={},
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )
            # lets get the os version
            os_version = get_os_version(vm_id, os)
            ns.send_sync(
                create_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    name=f"The OS of {vm_details.name} is {os_version.name}, Getting list of applications",
                    arguments={},
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )
            # now lets list all the packages
            installed_apps_response = get_inventory(vm_id, os)
            response = LlmChatAgentResponse(
                error=None,
                status="success",
                message=f"Listed successfully the vm {vm_details.name} apps",
            )
            if application_name:
                installed_apps_response.installed_apps = self.fuzzy_lib_search(
                    installed_apps_response.installed_apps, application_name
                )
                response.message = f"Listed successfully the vm {vm_details.name} apps"
                response.data = {
                    "installed_apps": installed_apps_response.installed_apps_to_json(),
                }
                return response

            if len(installed_apps_response.installed_apps) > 50:
                installed_apps_csv = app_packages_to_csv(
                    installed_apps_response.installed_apps
                )
                # Limit to first 50 records
                installed_apps_response.installed_apps = (
                    installed_apps_response.installed_apps[:50]
                )
                response.data = {
                    "installed_apps": installed_apps_response.installed_apps_to_json(),
                    "notes": f"Showing only first 50 of {len(installed_apps_response.installed_apps)} installed applications",
                }
            else:
                response.data = {
                    "installed_apps": installed_apps_response.installed_apps_to_json(),
                }
            attachment = AttachmentContextVariable(
                name="Installed Apps.csv",
                id="installed_apps",
                type=AttachmentType.TEXT,
                value=installed_apps_csv,
            )

            response.attachments = [attachment]

            return response
        except Exception as e:
            ns.send_sync(
                create_clean_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )
            return LlmChatAgentResponse(
                status="error",
                message=f"Failed to analyze security of vm {vm_id}: {e}",
                error=str(e),
                context_variables=context_variables,
                actions=[],
            )

    def list_vms_inventory_tool(
        self,
        session_context: dict,
        context_variables: dict,
    ) -> LlmChatAgentResponse:
        """This function is used to list all of the running vms applications"""
        try:
            ns = ServiceRegistry.get(
                session_context["session_id"],
                NOTIFICATION_SERVICE_NAME,
                NotificationService,
            )
            ls = ServiceRegistry.get(
                session_context["session_id"], LOGGER_SERVICE_NAME, LogService
            )
            data = ServiceRegistry.get(
                session_context["session_id"],
                VM_DATASOURCE_SERVICE_NAME,
                VmDatasourceService,
            )
            ls.info(
                session_context["channel"],
                f"Listing VMs applications with args {session_context}, {context_variables}",
            )
            response = LlmChatAgentResponse(
                error=None,
                status="success",
                message="",
            )
            vm_inventory_list = dict[str, LlmChatAgentResponse]()
            vm_error = dict[str, str]()
            for vm in data.datasource.get_all_vms():
                if vm.state == "running":
                    response = self.list_vm_inventory_tool(
                        session_context, context_variables, vm.id, vm.os
                    )

                    if response.error:
                        vm_error[vm.id] = response.error
                    else:
                        vm_inventory_list[vm.id] = response
            data = dict[str, dict[any, any] | list[dict[any, any]] | None]()
            message = "Listed successfully the applications for the following VMs"
            for vm_id in vm_inventory_list:
                message += f"\n\n{vm_inventory_list[vm_id].message}"
            if len(vm_error) > 0:
                message += f"\n\nThe following VMs had errors: {vm_error}"
            response.message = message

            for vm_id in vm_inventory_list:
                data[vm_id] = vm_inventory_list[vm_id].data

            response.data = data
            attachments = []
            for vm_id in vm_inventory_list:
                if vm_inventory_list[vm_id].attachments:
                    for attachment in vm_inventory_list[vm_id].attachments:
                        attachment.id = f"{vm_id}-{attachment.id}"
                        attachment.name = f"{vm_id}-{attachment.name}"
                        attachments.append(attachment)
            response.attachments = attachments
            return response
        except Exception as e:
            ns.send_sync(
                create_clean_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )
            return LlmChatAgentResponse(
                status="error",
                message=f"Failed to analyze security of vm {vm_id}: {e}",
                error=str(e),
                context_variables=context_variables,
                actions=[],
            )
