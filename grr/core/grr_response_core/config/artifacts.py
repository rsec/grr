#!/usr/bin/env python
"""Configuration parameters for the artifact subsystem."""

from grr.core.grr_response_core.lib import config_lib

config_lib.DEFINE_list("Artifacts.artifact_dirs", [
    "%(grr/core/grr_response_core/artifacts|resource)",
    "%(grr/core/grr_response_core/artifacts/flow_templates|resource)",
    "%(grr/core/grr_response_core/artifacts/local|resource)"
], "A list directories to load artifacts from.")

config_lib.DEFINE_list(
    "Artifacts.knowledge_base", [
        "LinuxRelease",
        "LinuxUserProfiles",
        "MacOSUsers",
        "WindowsCodePage",
        "WindowsDomainName",
        "WindowsEnvironmentVariableAllUsersAppData",
        "WindowsEnvironmentVariableAllUsersProfile",
        "WindowsEnvironmentVariablePath",
        "WindowsEnvironmentVariableProfilesDirectory",
        "WindowsEnvironmentVariableProgramFiles",
        "WindowsEnvironmentVariableProgramFilesX86",
        "WindowsEnvironmentVariableSystemDrive",
        "WindowsEnvironmentVariableSystemRoot",
        "WindowsEnvironmentVariableTemp",
        "WindowsEnvironmentVariableWinDir",
        "WindowsRegistryCurrentControlSet",
        "WindowsRegistryProfiles",
        "WindowsUserShellFolders",
        "WindowsTimezone",
        "WMIAccountUsersDomain",
        "WMIProfileUsersHomeDir",
    ], "List of artifacts that are collected regularly by"
    " interrogate and used for interpolation of client-side"
    " variables. Includes artifacts for all supported OSes. "
    "Anything not in this list won't be downloaded by"
    " interrogate so be sure to include any necessary"
    " dependencies.")

config_lib.DEFINE_list(
    "Artifacts.non_kb_interrogate_artifacts", [
        "WMILogicalDisks", "RootDiskVolumeUsage", "WMIComputerSystemProduct",
        "LinuxHardwareInfo", "OSXSPHardwareDataType"
    ], "Non-knowledge-base artifacts collected during Interrogate flows.")

config_lib.DEFINE_list(
    "Artifacts.knowledge_base_additions", [],
    "Extra artifacts to add to the knowledge_base list. This"
    " allows per-site tweaks without having to redefine the"
    " whole list.")

config_lib.DEFINE_list(
    "Artifacts.knowledge_base_skip", [],
    "Artifacts to remove from the knowledge_base list. This"
    " allows per-site tweaks without having to redefine the"
    " whole list.")

config_lib.DEFINE_list(
    "Artifacts.knowledge_base_heavyweight", ["WMIAccountUsersDomain"],
    "Artifacts to skip when the 'lightweight' option is"
    " set on interrogate. These artifacts are too expensive"
    " or slow to collect regularly from all machines.")

config_lib.DEFINE_list(
    "Artifacts.netgroup_filter_regexes", [],
    help="Only parse groups that match one of these regexes"
    " from /etc/netgroup files.")

config_lib.DEFINE_list(
    "Artifacts.netgroup_user_blacklist", [],
    help="Exclude these users when parsing /etc/netgroup "
    "files.")
