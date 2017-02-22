# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import logging
import socket
import uuid
from urlparse import urlparse
from minion.plugins.base import ExternalProcessPlugin


class TicketBleedPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "TicketBleedChecker"
    PLUGIN_VERSION = "0.2"
    PLUGIN_WEIGHT = "light"

    RUN_COMMAND = "timeout"
    RUN_ARGS = ["3"]
    ticket_bleep_path = "ticketbleed"

    report_dir = "/tmp/artifacts/"
    output_id = str(uuid.uuid4())

    logger_path = report_dir + "logging_" + output_id + ".txt"
    plugin_logger = ""
    plugin_stdout = ""
    plugin_stderr = ""

    target = "127.0.0.1"

    def do_configure(self):
        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
            self.logger_path = self.report_dir + "logging_" + self.output_id + ".txt"

        if "ticket_path" in self.configuration:
            self.ticket_bleep_path = self.configuration['ticket_path']

        # create logger
        self.plugin_logger = logging.getLogger()
        self.plugin_logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.FileHandler(self.logger_path)
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.plugin_logger.addHandler(ch)

    def do_start(self):
        self.plugin_logger.debug(self.configuration)
        # Get target for scan
        url = urlparse(self.configuration['target'])
        self.target = url.hostname

        # Check if the target is an ip to avoid empty hostname
        if not self.target:
            self.target = url.path

        # Build exec command
        self.RUN_ARGS.append(self.ticket_bleep_path)
        self.RUN_ARGS.append(self.target)

        self.plugin_logger.info("Running with command {cmd}".format(cmd=str(self.RUN_ARGS)))
        self.spawn(self.RUN_COMMAND, self.RUN_ARGS)

    def do_process_stdout(self, data):
        self.plugin_stdout += data

    def do_process_stderr(self, data):
        self.plugin_stderr += data

    def do_process_ended(self, status):
        if self.stopping and status == 9:
            self.report_finish("STOPPED")
        elif status == 0:

            issues = self.parse_result()

            self.report_issues(issues)

            self._save_artifacts()

            if self.plugin_stderr:
                failure = {
                    "hostname": socket.gethostname(),
                    "exception": self.plugin_stderr,
                    "message": "Plugin failed"
                }
                self.report_finish("FAILED", failure)
            else:
                self.report_finish()
        else:
            self._save_artifacts()
            failure = {
                "hostname": socket.gethostname(),
                "exception": self.plugin_stderr,
                "message": "Plugin failed"
            }
            self.report_finish("FAILED", failure)

    def _save_artifacts(self):
        stdout_log = self.report_dir + "STDOUT_" + self.output_id + ".txt"
        stderr_log = self.report_dir + "STDERR_" + self.output_id + ".txt"
        output_artifacts = []

        if self.plugin_stdout:
            with open(stdout_log, 'w+') as f:
                f.write(self.plugin_stdout)
            output_artifacts.append(stdout_log)
        if self.plugin_stderr:
            with open(stderr_log, 'w+') as f:
                f.write(self.plugin_stderr)
            output_artifacts.append(stderr_log)

        output_artifacts.append(self.logger_path)

        if output_artifacts:
            self.report_artifacts("Plugin Output", output_artifacts)

    def parse_result(self):
        issues = []
        # Check answer of plugin
        if "OK" in self.plugin_stdout:
            # success
            # TODO make it an option
            issues.append(self.create_ok())
        elif "KO" in self.plugin_stdout:
            issues.append(self.create_issue())
        else:
            # unknown state, error
            pass

        return issues

    def create_issue(self):
        issue = {
            "Summary": "Ticketbleed vulnerable",
            "Severity": "High",
            "Description": "Vulnerable with the F5 Ticketbleed vulnerability",
            "Classification": {
                "cwe_id": "126",
                "cwe_url": "http://cwe.mitre.org/data/definitions/126.html"
            },
            'URLs': [{'URL': self.target}],
        }

        return issue

    def create_ok(self):
        issue = {
            "Summary": "Ticketbleed not vulnerable",
            "Severity": "Info",
            "Description": "The target is not vulnerable with the F5 Ticketbleed vulnerability",
            "Classification": {
                "cwe_id": "126",
                "cwe_url": "http://cwe.mitre.org/data/definitions/126.html"
            },
            'URLs': [{'URL': self.target}],
        }
        return issue

