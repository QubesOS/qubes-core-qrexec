# -*- encoding: utf8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2023 Marta Marczykowska-Górecka
#                               <marmarta@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.
# pylint: disable=too-many-return-statements,too-many-locals,too-many-branches,too-many-statements
import argparse
import pathlib
import shutil
import sys
from io import StringIO

from typing import Dict, List, Tuple

from qrexec.policy import parser
from qrexec.tools import qrexec_policy_graph

from .. import POLICYPATH
from .. import POLICYPATH_OLD

CONFIG_FILE = "30-user"

SERVICE_TO_FILE = {
    "qubes.ClipboardPaste": "50-config-clipboard",
    "qubes.Filecopy": "50-config-filecopy",
    "qubes.UpdatesProxy": "50-config-updates",
    "qubes.OpenInVM": "50-config-openinvm",
    "qubes.OpenURL": "50-config-openurl",
    "qubes.InputKeyboard": "50-config-input",
    "qubes.InputMouse": "50-config-input",
    "qubes.InputTablet": "50-config-input",
    "u2f.Authenticate": "50-config-u2f",
    "u2f.Register": "50-config-u2f",
    "policy.RegisterArgument": "50-config-u2f",
}

DISCLAIMER = """
# Policy rules in this file were automatically converted from old
# policy format. Old files can be found in /etc/qubes-rpc/policy; they have
# the suffix .rpmsave.

# All rules pertaining to qubes.Gpg were moved to this file. If you want to
# move them to the relevant GUI config file, see 50-config-splitgpg. Caution:
# the GUI tool for qubes.Gpg policy supports only policy rules that have a
# single vm as a target.
"""

TOOL_DISCLAIMER = """
# THIS IS AN AUTOMATICALLY GENERATED POLICY FILE.
# Any changes made manually may be overwritten by Qubes Configuration Tools.
"""

argparser = argparse.ArgumentParser(
    description="Convert legacy Qubes 4.0 policy files"
)


class NoCompatPolicy(parser.FilePolicy):
    """
    This class loads policy without loading 4.0 compatible policy format
    """

    def handle_compat40(self, *, filepath, lineno):
        return


class RuleWrapper:
    def __init__(self, rule: parser.Rule):
        self.rule: parser.Rule = rule
        self.service = rule.service

    def is_rule_simple(self) -> bool:
        return str(self.rule.action) in ["ask", "deny", "allow"]

    def is_rule_compatible(self) -> bool:
        # check if the rule is simple enough for config tool
        if self.service == "qubes.ClipboardPaste":
            return str(self.rule.action) in ["ask", "deny"]
        if self.service == "qubes.Filecopy":
            return self.is_rule_simple()

        if self.service == "qubes.UpdatesProxy":
            if self.rule.source.type == "keyword":
                if str(self.rule.source) not in [
                    "@type:TemplateVM",
                    "@tag:whonix-updatevm",
                ]:
                    return False
            if "allow" not in str(self.rule.action):
                return False
            return (
                self.rule.target.type != "keyword"
                or str(self.rule.target) == "@adminvm"
                or str(self.rule.target) == "@default"
            )

        if self.service in ("qubes.OpenInVM", "qubes.OpenURL"):
            if self.rule.target != "@dispvm":
                # tool does not support cases other than dispvm-related
                return False
            if str(self.rule.action) == "ask":
                target = str(self.rule.action.default_target)
            elif str(self.rule.action) == "allow":
                target = str(self.rule.action.target)
            else:
                target = "@dispvm"
            return "@dispvm" in target

        if self.service == "policy.RegisterArgument":
            return self.rule.argument == "+u2f.Authenticate"

        if self.service in ["u2f.Authenticate", "u2f.Register"]:
            if (
                self.rule.target.type == "keyword"
                and str(self.rule.target) != "@adminvm"
            ):
                return False
            if self.rule.argument:
                return False
            return True

        if self.service in [
            "qubes.InputKeyboard",
            "qubes.InputMouse",
            "qubes.InputTablet",
        ]:
            if self.rule.target not in ["dom0", "@adminvm"]:
                return False
            if self.rule.source.type == "keyword":
                return False
            if getattr(self.rule.action, "target", None):
                return str(self.rule.action.target) in ["dom0", "@adminvm"]
            if getattr(self.rule.action, "default_target", None):
                return str(self.rule.action.default_target) in [
                    "dom0",
                    "@adminvm",
                ]
            return True

        return False

    def __eq__(self, other):
        return (
            self.rule.filepath == other.rule.filepath
            and self.rule.lineno == other.rule.lineno
        )

    def __str__(self):
        return str(self.rule)


def split_input_rules(
    new_rules: List[RuleWrapper],
) -> Tuple[List[RuleWrapper], List[RuleWrapper]]:
    """
    Returns tuple of lists: rules that are supposed to go to the 50-config file
    and the remaining rules that should go to the 30-user file
    """
    services = {"qubes.InputKeyboard", "qubes.InputMouse", "qubes.InputTablet"}
    sys_usbs = {str(rule.rule.source) for rule in new_rules}
    combinations = {
        (service, sys_usb) for service in services for sys_usb in sys_usbs
    }
    # only one rule per service - sys_usb combo should go into the 50-config
    # file

    config_file_rules = []
    remaining_rules = []

    for rule in new_rules:
        combination = (rule.service, str(rule.rule.source))
        if combination in combinations:
            config_file_rules.append(rule)
            combinations.remove(combination)

    return config_file_rules, remaining_rules


def main(args=None):
    argparser.parse_args(args)

    print("Initiating policy conversion process...")

    # get initial state
    initial_state_string = StringIO()
    qrexec_policy_graph.main(
        ["--policy-dir", str(POLICYPATH), "--full-output"],
        output=initial_state_string,
    )
    initial_state = set(initial_state_string.getvalue().split("\n"))

    print("Converting old policy files into new format files....")
    current_policy = parser.FilePolicy(policy_path=POLICYPATH)
    current_policy_no_compat = NoCompatPolicy(policy_path=POLICYPATH)

    all_rules = [
        RuleWrapper(rule) for rule in current_policy.rules if rule.lineno
    ]
    new_rules = [RuleWrapper(rule) for rule in current_policy_no_compat.rules]

    # all rules that exist only in legacy files
    legacy_rules = [rule for rule in all_rules if rule not in new_rules]

    # all services for which a legacy rule exists
    all_services = {rule.service for rule in legacy_rules}

    # dict of file_name: rules list
    rules_to_save = {CONFIG_FILE: []}
    for filename in SERVICE_TO_FILE.values():
        rules_to_save[filename] = []

    for service in all_services:
        legacy = [rule for rule in legacy_rules if rule.service == service]
        non_legacy = [rule for rule in new_rules if rule.service == service]

        legacy_str = [str(rule) for rule in legacy]
        non_legacy_str = [str(rule) for rule in non_legacy]

        if legacy_str == non_legacy_str or not legacy:
            continue

        missing = [rule for rule in legacy if str(rule) not in non_legacy_str]
        if not missing:
            continue

        last_working_rule = len(missing)
        for i, rule in enumerate(missing):
            if (
                str(rule.rule.action) == "deny"
                and str(rule.rule.source) == "@anyvm"
                and str(rule.rule.target) == "@anyvm"
                and not rule.rule.argument
            ):
                last_working_rule = i
                break
        missing = missing[:last_working_rule]
        if not missing:
            continue
        filename = SERVICE_TO_FILE.get(service, CONFIG_FILE)

        for rule in missing:
            if rule.is_rule_compatible():
                rules_to_save[filename].append(rule)
            else:
                rules_to_save[CONFIG_FILE].append(rule)

    if "50-config-input" in rules_to_save:
        config_file, user_file = split_input_rules(
            rules_to_save["50-config-input"]
        )
        rules_to_save["50-config-input"] = config_file
        rules_to_save[CONFIG_FILE].extend(user_file)

    backups_made: Dict[pathlib.Path, pathlib.Path] = {}

    # do actual rule saving
    for filename, rules in rules_to_save.items():
        if not rules:
            continue

        file = POLICYPATH / (filename + ".policy")
        disclaimer = DISCLAIMER if filename == "30-user" else TOOL_DISCLAIMER
        text = disclaimer + "\n".join([str(rule.rule) for rule in rules]) + "\n"

        if file.exists():
            backup_name = str(file) + ".bak"
            while pathlib.Path(backup_name).exists():
                backup_name = backup_name + ".bak"
            backups_made[file] = pathlib.Path(backup_name)
            shutil.copy(file, backup_name)

            if filename != "50-config-input":
                # input files are special: they replace current rules
                current_text = file.read_text()
                if current_text.startswith(TOOL_DISCLAIMER):
                    current_text = current_text[len(TOOL_DISCLAIMER) :]
                text = text.rstrip("\n") + "\n" + current_text.lstrip("\n")

        print("Writing " + str(file) + "...")
        file.write_text(text)

    # remove old
    for file in POLICYPATH_OLD.iterdir():
        if file.is_file() and not file.name.endswith(".rpmsave"):
            backup_name = str(file) + ".rpmsave"
            while pathlib.Path(backup_name).exists():
                backup_name = backup_name + ".rpmsave"
            backups_made[file] = pathlib.Path(backup_name)
            file.rename(backup_name)

    # check if state changed
    try:
        current_state_string = StringIO()
        qrexec_policy_graph.main(
            ["--policy-dir", str(POLICYPATH), "--full-output"],
            output=current_state_string,
        )
        current_state = set(current_state_string.getvalue().split("\n"))
    except Exception:  # pylint: disable=broad-except
        current_state = "ERROR"

    if initial_state != current_state:
        print(
            "ERROR: Found the following differences between "
            "previous and converted policy states:"
        )
        print("OLD STATE")
        for line in initial_state.difference(current_state):
            print(line)
        print("NEW STATE")
        for line in current_state.difference(initial_state):
            print(line)
        if input("Do you want to restore initial state? [Y/n] ").upper() != "N":
            for new_file, backup in backups_made.items():
                new_file.unlink()
                backup.rename(new_file)
            print("Conversion reverted.")

            sys.exit(1)

    print("Successfully converted old policy to new format.")


if __name__ == "__main__":
    sys.exit(main())
