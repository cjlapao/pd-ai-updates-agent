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
from pd_ai_agent_core.helpers import (
    get_context_variable,
)
from pd_ai_agent_core.common import (
    NOTIFICATION_SERVICE_NAME,
    LOGGER_SERVICE_NAME,
)
import openai
from typing import List
from pd_ai_agent_core.parallels_desktop.os import (
    get_vm_details,
    get_os_version,
    get_updates,
)
from pd_ai_agent_core.parallels_desktop.models.os import os_to_string
from pd_ai_agent_core.messages.constants import VM_RUN_UPDATE
from pd_ai_agent_core.core_types.llm_chat_ai_agent import (
    LlmChatAgentResponseAction,
)

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
    result = """You are an AI specialized in security and update list and analysis of virtual machines (VMs).
You are able to list updates from a vm and analyze them for the user.

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
For example the user might say "analyze the security of vm 123" or "analyze the updates of vm 123" or "analyze the vulnerabilities of vm 123"
or even more simply "list updates for vm 123", or "check for updates for vm 123",
You will need the VM ID or VM Name to do this. check the context or history of the conversation for this information.
"""


class AnalyzeUpdatesAgent(LlmChatAgent):
    def __init__(self):
        super().__init__(
            name="Analyze Updates Agent",
            instructions=ANALYZE_UPDATES_PROMPT,
            description="This agent is responsible for listingand analyzing and d updates of a VM.",
            icon="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjwhLS0gVXBsb2FkZWQgdG86IFNWRyBSZXBvLCB3d3cuc3ZncmVwby5jb20sIEdlbmVyYXRvcjogU1ZHIFJlcG8gTWl4ZXIgVG9vbHMgLS0+Cgo8c3ZnCiAgIHdpZHRoPSI4MDBweCIKICAgaGVpZ2h0PSI4MDBweCIKICAgdmlld0JveD0iMCAwIDQ4IDQ4IgogICBpZD0iYiIKICAgdmVyc2lvbj0iMS4xIgogICBzb2RpcG9kaTpkb2NuYW1lPSJ1cGRhdGVyLXN2Z3JlcG8tY29tLnN2ZyIKICAgaW5rc2NhcGU6dmVyc2lvbj0iMS40IChlN2MzZmViMSwgMjAyNC0xMC0wOSkiCiAgIHhtbG5zOmlua3NjYXBlPSJodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy9uYW1lc3BhY2VzL2lua3NjYXBlIgogICB4bWxuczpzb2RpcG9kaT0iaHR0cDovL3NvZGlwb2RpLnNvdXJjZWZvcmdlLm5ldC9EVEQvc29kaXBvZGktMC5kdGQiCiAgIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CiAgPHNvZGlwb2RpOm5hbWVkdmlldwogICAgIGlkPSJuYW1lZHZpZXcxIgogICAgIHBhZ2Vjb2xvcj0iI2ZmZmZmZiIKICAgICBib3JkZXJjb2xvcj0iIzAwMDAwMCIKICAgICBib3JkZXJvcGFjaXR5PSIwLjI1IgogICAgIGlua3NjYXBlOnNob3dwYWdlc2hhZG93PSIyIgogICAgIGlua3NjYXBlOnBhZ2VvcGFjaXR5PSIwLjAiCiAgICAgaW5rc2NhcGU6cGFnZWNoZWNrZXJib2FyZD0iMCIKICAgICBpbmtzY2FwZTpkZXNrY29sb3I9IiNkMWQxZDEiCiAgICAgaW5rc2NhcGU6em9vbT0iMS4yNjEyNSIKICAgICBpbmtzY2FwZTpjeD0iNDAwIgogICAgIGlua3NjYXBlOmN5PSI0MDAiCiAgICAgaW5rc2NhcGU6d2luZG93LXdpZHRoPSIxMjAwIgogICAgIGlua3NjYXBlOndpbmRvdy1oZWlnaHQ9IjExODYiCiAgICAgaW5rc2NhcGU6d2luZG93LXg9IjAiCiAgICAgaW5rc2NhcGU6d2luZG93LXk9IjI1IgogICAgIGlua3NjYXBlOndpbmRvdy1tYXhpbWl6ZWQ9IjAiCiAgICAgaW5rc2NhcGU6Y3VycmVudC1sYXllcj0iYiIgLz4KICA8ZGVmcwogICAgIGlkPSJkZWZzMSI+CiAgICA8c3R5bGUKICAgICAgIGlkPSJzdHlsZTEiPi5le2ZpbGw6bm9uZTtzdHJva2U6IzAwMDAwMDtzdHJva2UtbGluZWNhcDpyb3VuZDtzdHJva2UtbGluZWpvaW46cm91bmQ7fTwvc3R5bGU+CiAgPC9kZWZzPgogIDxnCiAgICAgaWQ9ImcxIgogICAgIHN0eWxlPSJzdHJva2Utd2lkdGg6Mi40Ij4KICAgIDxwYXRoCiAgICAgICBzdHlsZT0ic3Ryb2tlLWxpbmVjYXA6cm91bmQ7c3Ryb2tlLWxpbmVqb2luOnJvdW5kIgogICAgICAgZD0ibSAyMy41NjI1LDE1LjY5NzI2NiBhIDEuMjAwMTIsMS4yMDAxMiAwIDAgMCAtMC43NjE3MTksMS4xMTcxODcgViAzMS4xODU1NDcgQSAxLjIsMS4yIDAgMCAwIDI0LDMyLjM4NjcxOSAxLjIsMS4yIDAgMCAwIDI1LjE5OTIxOSwzMS4xODU1NDcgdiAtMTEuMzEyNSBsIDMuMzc2OTUzLDMuNjQwNjI1IGEgMS4yLDEuMiAwIDAgMCAxLjY5NTMxMiwwLjA2NDQ1IDEuMiwxLjIgMCAwIDAgMC4wNjQ0NSwtMS42OTUzMTMgTCAyNC44ODA4NTksMTUuOTk4MDQ3IEEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIDIzLjU2MjUsMTUuNjk3MjY2IFoiCiAgICAgICBpZD0iYyIgLz4KICAgIDxwYXRoCiAgICAgICBzdHlsZT0ic3Ryb2tlLWxpbmVjYXA6cm91bmQ7c3Ryb2tlLWxpbmVqb2luOnJvdW5kIgogICAgICAgZD0ibSAyNC44MTY0MDYsMTUuOTMzNTk0IGEgMS4yLDEuMiAwIDAgMCAtMS42OTcyNjUsMC4wNjQ0NSBsIC01LjQ1NTA3OSw1Ljg4NDc2NSBhIDEuMiwxLjIgMCAwIDAgMC4wNjQ0NSwxLjY5NTMxMyAxLjIsMS4yIDAgMCAwIDEuNjk1MzEyLC0wLjA2NDQ1IGwgNS40NTcwMzEsLTUuODgyODEzIGEgMS4yLDEuMiAwIDAgMCAtMC4wNjQ0NSwtMS42OTcyNjUgeiIKICAgICAgIGlkPSJkIiAvPgogIDwvZz4KICA8cGF0aAogICAgIHN0eWxlPSJzdHJva2UtbGluZWNhcDpyb3VuZDtzdHJva2UtbGluZWpvaW46cm91bmQiCiAgICAgZD0iTSAxOS45MDgyMDMsMi4zMDA3ODEzIEMgMTguODEyOTMsMi4yOTAwOTg5IDE3Ljg2MDMzMiwzLjEwODQ4MDggMTcuNzA3MDMxLDQuMTkzMzU5NCBMIDE3LjAxNTYyNSw5LjA2MjUgYyAtMC44NTI2NTQsMC40MDAzNjk2IC0xLjY2NzA2NiwwLjg3MTA3MDQgLTIuNDM5NDUzLDEuNDEwMTU2IEwgOS45NzY1NjI1LDguNjI1IGMgLTEuMDIxMjkxNiwtMC40MTQ5MjcgLTIuMjEzNzM2MiwwLjAwMzkyIC0yLjc1LDAuOTY2Nzk2OSBsIC00LjA5NTcwMzEsNy4xMDE1NjIxIDAuMDExNzE5LC0wLjAxNzU4IGMgLTAuNTcyNDg0OSwwLjk1MTk2MyAtMC4zMzI5OTA2LDIuMjA1OTUzIDAuNTQ4ODI4MiwyLjg4MDg2IDQuNjhlLTQsMy41OGUtNCAtNC42ODVlLTQsMC4wMDE2IDAsMC4wMDIgbCAzLjgxNDQ1MzEsMi45OTIxODcgYyAtMC4wNDMzNTEsMC40Nzg1NjkgLTAuMDk2OTY3LDAuOTU2Nzg0IC0wLjEwMTU2MjUsMS40Mzc1IGEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIDAsMC4wMjM0NCBjIDAuMDA0MzgsMC40ODA5NTYgMC4wNTgxMTYsMC45NTg2ODcgMC4xMDE1NjI1LDEuNDM3NSBsIC0zLjgxNDQ1MzEsMi45OTIxODcgYyAtNC42ODZlLTQsMy41OGUtNCA0LjY4MmUtNCwwLjAwMTYgMCwwLjAwMiAtMC44ODIxMTQzLDAuNjc0OTE1IC0xLjEyMTM1NDcsMS45Mjg4MjcgLTAuNTQ4ODI4MiwyLjg4MDg2IGwgLTAuMDExNzE5LC0wLjAxNzU4IDQuMDk1NzAzMSw3LjEwMTU2MiBjIDAuNTM2MjYzOCwwLjk2Mjg3NyAxLjcyODcwODQsMS4zODE3MjQgMi43NSwwLjk2Njc5NyBsIDQuNTgwMDc4NSwtMS44NDU3MDMgYyAwLjc3MzEsMC41Mzc2NTQgMS41ODc2ODksMS4wMDY2NTggMi40Mzk0NTMsMS40MDgyMDMgbCAwLjY5MTQwNiw0Ljg2OTE0MSBjIDAuMTUzMjk3LDEuMDg0ODU2IDEuMTA1NjA4LDEuOTAzNDgxIDIuMjAxMTcyLDEuODkyNTc4IGggOC4xODM1OTQgYyAxLjA5NTI3MywwLjAxMDY4IDIuMDQ3ODcxLC0wLjgwNzcgMi4yMDExNzEsLTEuODkyNTc4IGwgMC42ODk0NTQsLTQuODY3MTg4IGMgMC44NTMwNDgsLTAuNDAwNDA1IDEuNjY2NzIzLC0wLjg3MDkxOSAyLjQzOTQ1MywtMS40MTAxNTYgTCAzNy45ODI0MjIsMzkuMzc1IGMgMS4wMjAzOSwwLjQxNDU2MSAyLjIxMzA1MSwtMC4wMDM4IDIuNzUsLTAuOTY0ODQ0IGwgNC4wODU5MzcsLTcuMDg1OTM3IGMgMC41NzI3ODksLTAuOTUyNDY5IDAuMzMyMTg4LC0yLjIwODE2NSAtMC41NTA3ODEsLTIuODgyODEzIGwgLTMuNzgzMjAzLC0yLjk4ODI4MSBjIDAuMDQzNjcsLTAuNDgwMDc3IDAuMDk1MjIsLTAuOTU5MTY0IDAuMDk5NjEsLTEuNDQxNDA2IGEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIDAsLTAuMDIzNDQgYyAtMC4wMDQ0LC0wLjQ4MDk0MSAtMC4wNTYxNywtMC45NTg3MDIgLTAuMDk5NjEsLTEuNDM3NSBsIDMuODIyMjY2LC0yLjk5MjE4NyBjIDQuNjhlLTQsLTMuNThlLTQgLTQuNjhlLTQsLTAuMDAxNiAwLC0wLjAwMiAwLjg4MjExNSwtMC42NzQ5MTUgMS4xMjMzMDgsLTEuOTI4ODI3IDAuNTUwNzgxLC0yLjg4MDg2IGwgMC4wMTE3MiwwLjAxNzU4IC00LjA5NTcwNCwtNy4xMDE1NjIxIEMgNDAuMjM3MTc0LDguNjI4OTIgMzkuMDQyNzc2LDguMjEwMDczIDM4LjAyMTQ4NCw4LjYyNSBsIC00LjU3ODEyNSwxLjg0NTcwMyBDIDMyLjY3MDI4NCw5LjkzMzA1NDMgMzEuODU1NzE3LDkuNDY0MDU0MSAzMS4wMDM5MDYsOS4wNjI1IEwgMzAuMzEyNSw0LjE5MzM1OTQgQyAzMC4xNTkyMDMsMy4xMDg1MDI5IDI5LjIwNjg5MiwyLjI4OTg3NzkgMjguMTExMzI4LDIuMzAwNzgxMyBaIG0gMC4xNTAzOTEsMi40MDAzOTA2IGggNy45MDIzNDMgbCAwLjc0NjA5NCw1LjI2MzY3MTkgYSAxLjIwMDEyLDEuMjAwMTIgMCAwIDAgMC43MjQ2MSwwLjkzNzUwMDIgYyAxLjE0MDcxLDAuNDc3MjY2IDIuMjE2MjkzLDEuMDk5NDE2IDMuMTk5MjE4LDEuODQ5NjA5IGEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIDEuMTc3NzM1LDAuMTYwMTU2IGwgNC45NTcwMzEsLTIgMy45NDcyNjYsNi44NDc2NTcgLTQuMjA3MDMyLDMuMjkyOTY4IGEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIC0wLjQ1MTE3MiwxLjEwMTU2MyBjIDAuMDgwMzYsMC42MTE3MzkgMC4xMjQ3NjgsMS4yMjg3NDggMC4xMzA4NiwxLjg0NTcwMyAtMC4wMDYxLDAuNjE2OTUzIC0wLjA1MDQ5LDEuMjMzODI3IC0wLjEzMDg2LDEuODQ1NzAzIEEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIDM4LjUsMjYuOTQzMzU5IGwgNC4xNzM4MjgsMy4yOTY4NzUgLTMuOTQ3MjY2LDYuODQ3NjU3IC00Ljk1ODk4NCwtMiBBIDEuMjAwMTIsMS4yMDAxMiAwIDAgMCAzMi41ODc4OTEsMzUuMjUgYyAtMC45Nzk1NjgsMC43NTE2NDEgLTIuMDUzMjUsMS4zNzIyMTcgLTMuMTkzMzYsMS44NDU3MDMgYSAxLjIwMDEyLDEuMjAwMTIgMCAwIDAgLTAuNzI2NTYyLDAuOTM5NDUzIGwgLTAuNzQ4MDQ3LDUuMjYzNjcyIGggLTcuODgwODYgbCAtMC43NDYwOTMsLTUuMjYzNjcyIGEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIC0wLjcyNjU2MywtMC45Mzc1IEMgMTcuNDI1NzU5LDM2LjYyMDM3OCAxNi4zNTIwMzcsMzUuOTk4MjE4IDE1LjM2OTE0MSwzNS4yNDgwNDcgQSAxLjIwMDEyLDEuMjAwMTIgMCAwIDAgMTQuMTkxNDA2LDM1LjA4Nzg5MSBMIDkuMjM0Mzc1LDM3LjA4NTkzNyA1LjI4NzEwOTQsMzAuMjQyMTg3IDkuNDg2MzI4MSwyNi45NDUzMTIgQSAxLjIwMDEyLDEuMjAwMTIgMCAwIDAgOS45MzU1NDY5LDI1Ljg0NTcwMyBDIDkuODU1MTg1OSwyNS4yMzM5NjQgOS44MTA3Nzk4LDI0LjYxNjk1NSA5LjgwNDY4NzUsMjQgYyAwLjAwNjM3LC0wLjYxNzMwOSAwLjA1MDcyNCwtMS4yMzM0ODMgMC4xMzA4NTk0LC0xLjg0NTcwMyBhIDEuMjAwMTIsMS4yMDAxMiAwIDAgMCAtMC40NDkyMTg4LC0xLjA5OTYxIGwgLTQuMTk5MjE4NywtMy4yOTY4NzUgMy45NDcyNjU2LC02Ljg0NTcwMyA0Ljk3ODUxNiwyIEEgMS4yMDAxMiwxLjIwMDEyIDAgMCAwIDE1LjM5MDYyNSwxMi43NSBjIDAuOTc5NTY3LC0wLjc1MTY0MSAyLjA1MzI1LC0xLjM3MjIxNyAzLjE5MzM1OSwtMS44NDU3MDMgQSAxLjIwMDEyLDEuMjAwMTIgMCAwIDAgMTkuMzEyNSw5Ljk2NDg0MzggWiIKICAgICBpZD0icGF0aDEiIC8+Cjwvc3ZnPgo=",
            functions=[self.analyze_updates_tool],  # type: ignore
            function_descriptions=[
                AgentFunctionDescriptor(
                    name=self.analyze_updates_tool.__name__,
                    description="Analyzing VM updates",
                ),
            ],
            transfer_instructions=ANALYZE_UPDATES_TRANSFER_INSTRUCTIONS,
        )

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
        os: str,
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
                    name=f"Getting OS version",
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
                    name=f"The os is {os_version.name}, Getting list of updates",
                    arguments={},
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )
            # now lets list all the packages
            packages_to_update = get_updates(vm_id, os)
            ns.send_sync(
                create_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    name=f"Analyzing security of vm {vm_details.name}",
                    arguments={},
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )

            # lets analyze this with the llm to check for issues
            analysis = self.analyze_updates_with_llm(
                context_variables,
                os_to_string(os_version),
                "",
                packages_to_update.to_string(),
            )

            response = LlmChatAgentResponse(
                status="success",
                message=f"Analyzed successfully security of vm {vm_id}",
                data={"analysis": analysis},
                actions=[],
                attachments=[],
            )

            if packages_to_update.has_updates():
                update_action = LlmChatAgentResponseAction(
                    id=f"update_action_{vm_id}",
                    name="Update",
                    description="Run Update",
                    type="background_message",
                    value=VM_RUN_UPDATE,
                    icon="data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjQiIGhlaWdodD0iMjQiIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KICA8cGF0aAogICAgZD0iTTExLjU0NzMgMjEuNjI3MUMxMS4yMzA2IDIxLjYyNzEgMTAuOTU0OCAyMS41Mzc3IDEwLjcxOTggMjEuMzU4OUMxMC40ODk5IDIxLjE4MDEgMTAuMzM5MiAyMC45Mzc0IDEwLjI2NzcgMjAuNjMxTDkuOTUzNTcgMTkuMjc0OEw5Ljc0NjcgMTkuMjA1OEw4LjU3NDM3IDE5LjkyNjFDOC4zMDg3NCAyMC4wOTQ2IDguMDI3NzggMjAuMTU4NSA3LjczMTUyIDIwLjExNzdDNy40NDAzNSAyMC4wODE4IDcuMTgyMzggMTkuOTUxNiA2Ljk1NzYyIDE5LjcyNjlMNS44ODQ5MSAxOC42NjE4QzUuNjU1MDQgMTguNDMyIDUuNTIyMjMgMTguMTcxNCA1LjQ4NjQ3IDE3Ljg4MDNDNS40NTA3MSAxNy41ODkxIDUuNTE3MTIgMTcuMzEwNyA1LjY4NTY5IDE3LjA0NTFMNi40MjEyNyAxNS44NzI3TDYuMzUyMzIgMTUuNjgxMkw0Ljk5NjA5IDE1LjM2N0M0LjY5NDcxIDE1LjI5NTUgNC40NTIwNyAxNS4xNDIzIDQuMjY4MTcgMTQuOTA3M0M0LjA4OTM4IDE0LjY3MjMgNCAxNC4zOTkgNCAxNC4wODc0VjEyLjU3OEM0IDEyLjI2NjQgNC4wODkzOCAxMS45OTU2IDQuMjY4MTcgMTEuNzY1OEM0LjQ0Njk1IDExLjUzMDggNC42ODk1OSAxMS4zNzUgNC45OTYwOSAxMS4yOTg0TDYuMzM2OTkgMTAuOTc2Nkw2LjQxMzYgMTAuNzY5N0w1LjY3ODA0IDkuNTk3MzZDNS41MDk0NyA5LjMzNjg0IDUuNDQzMDYgOS4wNjA5OSA1LjQ3ODggOC43Njk4M0M1LjUxNDU2IDguNDc4NjYgNS42NDczNyA4LjIxODE0IDUuODc3MjUgNy45ODgyOEw2Ljk0OTk2IDYuOTE1NTZDNy4xNzQ3MiA2LjY5MDgxIDcuNDMyNjkgNi41NjA1NSA3LjcyMzg2IDYuNTI0NzlDOC4wMTUwMiA2LjQ4MzkyIDguMjkzNDIgNi41NDUyMyA4LjU1OTA0IDYuNzA4NjhMOS43MzkwMyA3LjQzNjZMOS45NTM1NyA3LjM1MjMxTDEwLjI2NzcgNS45OTYwOUMxMC4zMzkyIDUuNjk0NzEgMTAuNDg5OSA1LjQ1NDY0IDEwLjcxOTggNS4yNzU4NUMxMC45NTQ4IDUuMDkxOTUgMTEuMjMwNiA1IDExLjU0NzMgNUgxMy4xMDI4QzEzLjQxOTUgNSAxMy42OTI4IDUuMDkxOTUgMTMuOTIyNiA1LjI3NTg1QzE0LjE1MjUgNS40NTQ2NCAxNC4zMDMyIDUuNjk0NzEgMTQuMzc0NyA1Ljk5NjA5TDE0LjY4ODggNy4zNTIzMUwxNC45MDM0IDcuNDM2NkwxNi4wODMzIDYuNzA4NjhDMTYuMzQ5IDYuNTQ1MjMgMTYuNjI3NCA2LjQ4MzkyIDE2LjkxODUgNi41MjQ3OUMxNy4yMTQ4IDYuNTYwNTUgMTcuNDcyOCA2LjY5MDgxIDE3LjY5MjQgNi45MTU1NkwxOC43NjUyIDcuOTg4MjhDMTguOTg5OSA4LjIxODE0IDE5LjEyMDIgOC40Nzg2NiAxOS4xNTU5IDguNzY5ODNDMTkuMTk2NyA5LjA2MDk5IDE5LjEzMyA5LjMzNjg0IDE4Ljk2NDQgOS41OTczNkwxOC4yMjg4IDEwLjc2OTdMMTguMzEzMSAxMC45NzY2TDE5LjY0NjMgMTEuMjk4NEMxOS45NDc2IDExLjM2OTkgMjAuMTg3OCAxMS41MjMxIDIwLjM2NjYgMTEuNzU4MUMyMC41NTA1IDExLjk5MzEgMjAuNjQyNCAxMi4yNjY0IDIwLjY0MjQgMTIuNTc4VjE0LjA4NzRDMjAuNjQyNCAxNC4zOTkgMjAuNTUwNSAxNC42NzIzIDIwLjM2NjYgMTQuOTA3M0MyMC4xODc4IDE1LjEzNzIgMTkuOTQ3NiAxNS4yOTA0IDE5LjY0NjMgMTUuMzY3TDE4LjI5NzggMTUuNjgxMkwxOC4yMjExIDE1Ljg3MjdMMTguOTU2NyAxNy4wNDUxQzE5LjEyNTMgMTcuMzEwNyAxOS4xODkxIDE3LjU4OTEgMTkuMTQ4MyAxNy44ODAzQzE5LjExMjYgMTguMTcxNCAxOC45ODIyIDE4LjQzMiAxOC43NTc1IDE4LjY2MThMMTcuNjg0NyAxOS43MjY5QzE3LjQ2IDE5Ljk1MTYgMTcuMTk5NSAyMC4wODE4IDE2LjkwMzIgMjAuMTE3N0MxNi42MTIxIDIwLjE1ODUgMTYuMzMzNyAyMC4wOTQ2IDE2LjA2OCAxOS45MjYxTDE0Ljg4ODEgMTkuMjA1OEwxNC42ODg4IDE5LjI3NDhMMTQuMzc0NyAyMC42MzFDMTQuMzAzMiAyMC45Mzc0IDE0LjE1MjUgMjEuMTgwMSAxMy45MjI2IDIxLjM1ODlDMTMuNjkyOCAyMS41Mzc3IDEzLjQxOTUgMjEuNjI3MSAxMy4xMDI4IDIxLjYyNzFIMTEuNTQ3M1pNMTEuNzM4OSAyMC4yNDAySDEyLjkxMTJDMTMuMDMzOCAyMC4yNDAyIDEzLjEwMjggMjAuMTgxNCAxMy4xMTgxIDIwLjA2NEwxMy41Nzc4IDE4LjE3OTFDMTMuODMzMiAxOC4xMjI4IDE0LjA3MDggMTguMDQ4OSAxNC4yOTA0IDE3Ljk1NjlDMTQuNTEwMSAxNy44NTk5IDE0LjcxNDQgMTcuNzUyNSAxNC45MDM0IDE3LjYzNUwxNi41NTA3IDE4LjY0NjVDMTYuNjQ3OCAxOC43MTI5IDE2Ljc0MjMgMTguNzAyNyAxNi44MzQyIDE4LjYxNTlMMTcuNjQ2NSAxNy43OTZDMTcuNzI4MiAxNy43MjQ0IDE3LjczNTkgMTcuNjMyNSAxNy42Njk0IDE3LjUyMDFMMTYuNjU4IDE1Ljg4MDRDMTYuNzY1NCAxNS42OTY1IDE2Ljg2NSAxNS40OTIyIDE2Ljk1NjkgMTUuMjY3NEMxNy4wNTQgMTUuMDQyNyAxNy4xMzA1IDE0LjgxMDMgMTcuMTg2NyAxNC41NzAyTDE5LjA3OTMgMTQuMTE4MUMxOS4xOTY3IDE0LjA5NzcgMTkuMjU1NSAxNC4wMjYxIDE5LjI1NTUgMTMuOTAzNVYxMi43NTQyQzE5LjI1NTUgMTIuNjM2NyAxOS4xOTY3IDEyLjU2NTIgMTkuMDc5MyAxMi41Mzk3TDE3LjE5NDQgMTIuMDg3NkMxNy4xMzMgMTEuODMyMiAxNy4wNTE0IDExLjU4OTUgMTYuOTQ5MSAxMS4zNTk3QzE2Ljg1MjEgMTEuMTI5OCAxNi43NTc2IDEwLjkzMzEgMTYuNjY1NiAxMC43Njk3TDE3LjY3NzEgOS4xMjIzQzE3Ljc0ODYgOS4wMTUwMiAxNy43NDEgOC45MTc5NyAxNy42NTQxIDguODMxMTRMMTYuODQxOSA4LjAzNDI2QzE2Ljc1NSA3Ljk1MjUzIDE2LjY1OCA3LjkzOTc2IDE2LjU1MDcgNy45OTU5NUwxNC45MDM0IDguOTk5NzFDMTQuNzE0NCA4Ljg5MjQzIDE0LjUwNzUgOC43OTI4MiAxNC4yODI3IDguNzAwODdDMTQuMDYzMSA4LjYwMzgyIDEzLjgyODEgOC41MjQ2NCAxMy41Nzc4IDguNDYzMzVMMTMuMTE4MSA2LjU2MzExQzEzLjEwMjggNi40NDU2MSAxMy4wMzM4IDYuMzg2ODcgMTIuOTExMiA2LjM4Njg3SDExLjczODlDMTEuNjExMiA2LjM4Njg3IDExLjUzNzEgNi40NDU2MSAxMS41MTY3IDYuNTYzMTFMMTEuMDcyMyA4LjQ0ODAyQzEwLjgyNzEgOC41MDkzMSAxMC41ODQ0IDguNTkxMDQgMTAuMzQ0MyA4LjY5MzIxQzEwLjEwOTQgOC43OTAyNiA5LjkwNTA1IDguODg5ODcgOS43MzEzNiA4Ljk5MjA0TDguMDgzOTggNy45OTU5NUM3Ljk4MTgxIDcuOTM5NzYgNy44ODczMSA3Ljk0OTk3IDcuODAwNDcgOC4wMjY1OUw2Ljk4MDYyIDguODMxMTRDNi44OTg4OSA4LjkxNzk3IDYuODkxMjIgOS4wMTUwMiA2Ljk1NzYyIDkuMTIyM0w3Ljk2OTA0IDEwLjc2OTdDNy44ODIyMSAxMC45MzMxIDcuNzg3NzEgMTEuMTI5OCA3LjY4NTU0IDExLjM1OTdDNy41ODMzOCAxMS41ODk1IDcuNTA0MTkgMTEuODMyMiA3LjQ0OCAxMi4wODc2TDUuNTYzMDkgMTIuNTM5N0M1LjQ0NTYxIDEyLjU2NTIgNS4zODY4NyAxMi42MzY3IDUuMzg2ODcgMTIuNzU0MlYxMy45MDM1QzUuMzg2ODcgMTQuMDI2MSA1LjQ0NTYxIDE0LjA5NzcgNS41NjMwOSAxNC4xMTgxTDcuNDQ4IDE0LjU2MjVDNy41MDkzMSAxNC44MDc3IDcuNTg4NDggMTUuMDQyNyA3LjY4NTU0IDE1LjI2NzRDNy43ODI1OSAxNS40ODcxIDcuODgyMjEgMTUuNjkxNCA3Ljk4NDM4IDE1Ljg4MDRMNi45NjUyOSAxNy41Mjc4QzYuOTAzOTkgMTcuNjM1IDYuOTExNjUgMTcuNzI3IDYuOTg4MjcgMTcuODAzNkw3LjgwODE0IDE4LjYxNTlDNy45MDAwOSAxOC43MDI3IDcuOTkyMDMgMTguNzE1NSA4LjA4Mzk4IDE4LjY1NDFMOS43MzkwMyAxNy42MzVDOS45MjgwMyAxNy43NTI1IDEwLjEzNDkgMTcuODU5OSAxMC4zNTk3IDE3Ljk1NjlDMTAuNTg5NSAxOC4wNDg5IDEwLjgyNDUgMTguMTIyOCAxMS4wNjQ2IDE4LjE3OTFMMTEuNTE2NyAyMC4wNjRDMTEuNTM3MSAyMC4xODE0IDExLjYxMTIgMjAuMjQwMiAxMS43Mzg5IDIwLjI0MDJaTTEyLjMyMTIgMTYuMjI1MkMxMS43OSAxNi4yMjUyIDExLjMwMjEgMTYuMDk1IDEwLjg1NzcgMTUuODM0NEMxMC40MTg0IDE1LjU2ODggMTAuMDY2IDE1LjIxNjMgOS44MDAzMiAxNC43NzdDOS41Mzk4MSAxNC4zMzc3IDkuNDA5NTUgMTMuODQ5OSA5LjQwOTU1IDEzLjMxMzZDOS40MDk1NSAxMi43ODIzIDkuNTM5ODEgMTIuMjk3IDkuODAwMzIgMTEuODU3N0MxMC4wNjYgMTEuNDE4NCAxMC40MTg0IDExLjA2ODUgMTAuODU3NyAxMC44MDhDMTEuMzAyMSAxMC41NDc1IDExLjc5IDEwLjQxNzIgMTIuMzIxMiAxMC40MTcyQzEyLjg1NzYgMTAuNDE3MiAxMy4zNDU0IDEwLjU0NzUgMTMuNzg0NyAxMC44MDhDMTQuMjI0IDExLjA2ODUgMTQuNTczOSAxMS40MTg0IDE0LjgzNDQgMTEuODU3N0MxNS4wOTQ5IDEyLjI5NyAxNS4yMjUyIDEyLjc4MjMgMTUuMjI1MiAxMy4zMTM2QzE1LjIyNTIgMTMuODQ0OCAxNS4wOTQ5IDE0LjMzMjYgMTQuODM0NCAxNC43NzdDMTQuNTczOSAxNS4yMjE0IDE0LjIyNCAxNS41NzM5IDEzLjc4NDcgMTUuODM0NEMxMy4zNDU0IDE2LjA5NSAxMi44NTc2IDE2LjIyNTIgMTIuMzIxMiAxNi4yMjUyWk0xMi4zMjEyIDE0LjkwNzNDMTIuNjA3MyAxNC45MDczIDEyLjg3MDMgMTQuODM1OCAxMy4xMTA0IDE0LjY5MjhDMTMuMzUwNSAxNC41NDQ2IDEzLjUzOTUgMTQuMzUwNSAxMy42Nzc0IDE0LjExMDRDMTMuODIwNSAxMy44NzAzIDEzLjg5MiAxMy42MDQ3IDEzLjg5MiAxMy4zMTM2QzEzLjg5MiAxMy4wMjI0IDEzLjgyMDUgMTIuNzU5MyAxMy42Nzc0IDEyLjUyNDNDMTMuNTM5NSAxMi4yODQzIDEzLjM1MDUgMTIuMDkyNyAxMy4xMTA0IDExLjk0OTdDMTIuODcwMyAxMS44MDY2IDEyLjYwNzMgMTEuNzM1MSAxMi4zMjEyIDExLjczNTFDMTIuMDMgMTEuNzM1MSAxMS43NjQ0IDExLjgwNjYgMTEuNTI0MyAxMS45NDk3QzExLjI4NDMgMTIuMDkyNyAxMS4wOTI3IDEyLjI4NDMgMTAuOTQ5NyAxMi41MjQzQzEwLjgwNjYgMTIuNzU5MyAxMC43MzUxIDEzLjAyMjQgMTAuNzM1MSAxMy4zMTM2QzEwLjczNTEgMTMuNjA5OCAxMC44MDY2IDEzLjg3OCAxMC45NDk3IDE0LjExODFDMTEuMDkyNyAxNC4zNTgyIDExLjI4NDMgMTQuNTQ5NyAxMS41MjQzIDE0LjY5MjhDMTEuNzY0NCAxNC44MzU4IDEyLjAzIDE0LjkwNzMgMTIuMzIxMiAxNC45MDczWiIKICAgIGZpbGw9ImJsYWNrIiAvPgo8L3N2Zz4=",
                    parameters={
                        "vm_id": vm_id,
                        "os": os,
                        "list_all_packages": packages_to_update.to_string(),
                        "list_updates": packages_to_update.to_string(),
                    },
                )
                response.actions.append(update_action)

            ns.send_sync(
                create_clean_agent_function_call_chat_message(
                    session_id=session_context["session_id"],
                    channel=session_context["channel"],
                    linked_message_id=session_context["linked_message_id"],
                    is_partial=session_context["is_partial"],
                )
            )
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
