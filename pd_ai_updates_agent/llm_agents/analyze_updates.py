from pd_ai_agent_core.core_types.llm_chat_ai_agent import (
    LlmChatAgent,
    LlmChatAgentResponse,
    AgentFunctionDescriptor,
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
from pd_ai_agent_core.parallels_desktop.execute_on_vm import execute_on_vm
from pd_ai_agent_core.helpers import (
    get_context_variable,
)
from pd_ai_agent_core.common import (
    NOTIFICATION_SERVICE_NAME,
    LOGGER_SERVICE_NAME,
)
import openai
from typing import List
from pd_ai_updates_agent.llm_agents.helpers import get_vm_details

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


def ANALYZE_UPDATES_PROMPT(context_variables) -> str:
    result = """You are an AI specialized in security analysis of virtual machines (VMs).
.
Please provide a comprehensive report that includes the following elements: 
1.**Current Security Status**: Assess the current security posture of the VM, including any known vulnerabilities or weaknesses that may be present.
2.**Installed Updates**: List all currently installed security updates and patches, along with their dates of installation.
3.**Available Updates**: Identify any available security updates or patches that have not yet been applied, specifying their criticality and impact.
4.**Vulnerability Assessment**: Conduct a vulnerability assessment based on the current configuration and running services of the VM.Utilize any relevant tools or databases to support your findings.
5.**Recommendations**: Provide actionable recommendations for mitigating identified vulnerabilities, including steps for applying available updates and enhancing overall security.
6.**Compliance Check**: If applicable, evaluate the VM against relevant security compliance standards (e.g., NIST, CIS Benchmarks) and summarize any areas of non-compliance.

Ensure that the analysis is thorough, precise, and uses the most up-to-date security information available as of October 2023.

You will need the following information to analyze the security of the virtual machine:
  - vm_id or vm_name  

If you don't have the information, please ask the user for it.


"""
    if context_variables is not None:
        result += f"""Use the provided context in JSON format: {json.dumps(context_variables)}\
If the user has provided a vm id, use it to perform the operation on the VM.
If the user has provided a vm name, use it on your responses to the user to identify the VM instead of the vm id.

"""
    return result


ANALYZE_UPDATES_TRANSFER_INSTRUCTIONS = """
Call this function if the user is asking you to analyze the security, vulnerabilities, or updates of a VM.
    You will need the VM ID or VM Name to do this. check the context or history of the conversation for this information.
"""


class AnalyzeUpdatesAgent(LlmChatAgent):
    def __init__(self):
        super().__init__(
            name="Analyze Updates Agent",
            instructions=ANALYZE_UPDATES_PROMPT,
            description="This agent is responsible for analyzing updates of a VM.",
            functions=[self.analyze_updates_tool],  # type: ignore
            function_descriptions=[
                AgentFunctionDescriptor(
                    name=self.analyze_updates_tool.__name__,
                    description="Analyze the security, vulnerabilities, or updates of a VM",
                ),
            ],
            transfer_instructions=ANALYZE_UPDATES_TRANSFER_INSTRUCTIONS,
        )

    def get_update_packages_cmd(self, os: str) -> List[str]:
        if os.lower() == "ubuntu":
            return ["sudo", "apt", "update"]
        elif os.lower() == "debian":
            return ["sudo", "apt", "update"]
        elif os.lower() == "macos":
            return ["sudo", "brew", "update"]
        else:
            return []

    def get_list_all_packages_cmd(self, os: str) -> List[str]:
        if os.lower() == "ubuntu":
            return ["sudo", "apt", "list"]
        elif os.lower() == "debian":
            return ["sudo", "apt", "list"]
        elif os.lower() == "macos":
            return ["sudo", "brew", "list"]
        else:
            return []

    def get_list_updates_cmd(self, os: str) -> List[str]:
        if os.lower() == "ubuntu":
            return ["sudo", "apt", "list", "--upgradable"]
        elif os.lower() == "debian":
            return ["sudo", "apt", "list", "--upgradable"]
        else:
            return []

    def get_os_version_cmd(self, os: str) -> List[str]:
        if os.lower() == "ubuntu":
            return ["lsb_release", "-a"]
        elif os.lower() == "debian":
            return ["lsb_release", "-a"]
        else:
            return []

    def analyze_updates_with_llm(
        self,
        context_variables: dict,
        os: str,
        list_all_packages: str,
        list_updates: str,
    ):
        try:
            client = openai.OpenAI()
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": ANALYZE_UPDATES_WITH_LLM_PROMPT(context_variables),
                    },
                    {
                        "role": "user",
                        "content": f"OS Version: {os}\nInstalled Packages: {list_all_packages}\nAvailable Updates: {list_updates}",
                    },
                ],
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"Error using OpenAI API: {e}")
            return None

    def analyze_updates_tool(
        self,
        session_context: dict,
        context_variables: dict,
        vm_id: str,
    ) -> LlmChatAgentResponse:
        """This function is used to analyze the security, vulnerabilities, or updates of a virtual machine.
        it will require the vm_id to be provided.
        """
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
                f"Analyzing security of vm {vm_id} with args {session_context}, {context_variables}",
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
                    session_context["session_id"],
                    session_context["channel"],
                    f"Gathering information about vm {vm_id}",
                    {},
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
            # lets get the os version
            os_version = execute_on_vm(
                vm_id, command=" ".join(self.get_os_version_cmd(os))
            )
            if os_version.exit_code != 0:
                raise RuntimeError(f"Failed to get OS version: {os_version.error}")
            # first lets update the package list
            update_packages = execute_on_vm(
                vm_id, command=" ".join(self.get_update_packages_cmd(os))
            )

            # now lets list all the packages
            list_all_packages = execute_on_vm(
                vm_id, command=" ".join(self.get_list_all_packages_cmd(os))
            )
            if list_all_packages.exit_code != 0:
                raise RuntimeError(
                    f"Failed to list all packages: {list_all_packages.error}"
                )

            # now lets list the updates
            list_updates = execute_on_vm(
                vm_id, command=" ".join(self.get_list_updates_cmd(os))
            )
            if list_updates.exit_code != 0:
                raise RuntimeError(f"Failed to list updates: {list_updates.error}")

            ns.send_sync(
                create_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    name=f"Analyzing security of vm {vm_id}",
                    arguments={},
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )

            # lets analyze this with the llm to check for issues
            analysis = self.analyze_updates_with_llm(
                context_variables, os, list_all_packages.output, list_updates.output
            )
            ns.send_sync(
                create_clean_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )
            return LlmChatAgentResponse(
                status="success",
                message=f"Analyzed successfully security of vm {vm_id}",
                data={"analysis": analysis},
            )
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
            )
