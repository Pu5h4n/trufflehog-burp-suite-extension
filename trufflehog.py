# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, IExtensionStateListener, IScanIssue
from java.lang import Runtime, Thread as JThread, Runnable
from java.lang import ProcessBuilder
from java.util.concurrent import TimeUnit, Executors
from javax.swing import SwingUtilities, JOptionPane, JTabbedPane

from threading import Thread, Lock
import os
import json
import re
import time
import tempfile
import shutil
import uuid
import subprocess
import sys

try:
    from urlparse import urlparse, urlunparse
except ImportError:
    from urllib.parse import urlparse, urlunparse

from tab_ui import TruffleTab

ISSUE_PREFIX = "Leaked "
ISSUE_SUFFIX = " secret detected (TruffleHog)"
HEADER_FILE_SUFFIX = "_headers.txt"
BODY_FILE_SUFFIX = "_body.txt"
HEADER_BODY_SEPARATOR = b'\r\n\r\n'

# Name of the scanner child process script
SCRIPT_NAME = "scanner.py"
VERIFIED_FLAG = "--only-verified"
OVERLAP_FLAG = "--allow-verification-overlap"


class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("TruffleHog Secret Scanner")

        self.secrets_by_raw = {}
        self.seen_secrets = set()

        self.process_holder = {}
        self.running = True
        self.response_lock = Lock()
        self.process_lock = Lock()
        self.responses = {}
        self.pending_callbacks = {}
        self.temp_files = set()
        self.temp_dir = tempfile.mkdtemp(prefix="trufflehog_burp_")
        self.process = None
        self.stdin = None
        self.stdout = None
        self.stderr = None

        self.truffle_tab = TruffleTab(callbacks)
        self.truffle_tab.setExtender(self)
        callbacks.addSuiteTab(self.truffle_tab)

        self.executor = Executors.newFixedThreadPool(10)

        self.start_external_process()

        callbacks.registerHttpListener(self)
        callbacks.registerExtensionStateListener(self)

        t = Thread(target=self.extension_set_up)
        t.daemon = True
        t.start()

        self.filename_sanitizer = re.compile(r'[^a-zA-Z0-9]')

    def extension_set_up(self):
        self.store_tab_reference()
        existing_issues = self._callbacks.getScanIssues("")
        self.loadIssues(existing_issues)

    def loadIssues(self, issues):
        countExistingIssues = 0
        for issue in issues:
            if issue.getIssueName().endswith(ISSUE_SUFFIX):
                advisory = issue.getIssueDetail()
                if not advisory:
                    continue

                secret_redacted = self.extract_secret_attr(advisory, "Secret Redacted")
                secret_type = self.extract_secret_attr(advisory, "Secret Type")
                secret_raw = self.extract_secret_attr(advisory, "Secret")
                url = issue.getUrl().toString()
                httpMessages = issue.getHttpMessages() or []

                for mi in httpMessages:
                    if self.truffle_tab.secrets_data.get(secret_raw):
                        self.truffle_tab.updateSecretUrls(secret_raw, url, mi, advisory)
                    else:
                        self.truffle_tab.addSecret(
                            secret_type, secret_raw, secret_redacted, url, mi, advisory,
                            existing_secret=True
                        )
                countExistingIssues += 1

        self.truffle_tab.refreshSecretTable()

    def extract_secret_attr(self, details, label):
        pattern = r'<b>{0}:</b> (.+?)<br>'.format(label)
        match = re.search(pattern, details)
        return match.group(1) if match else None

    def store_tab_reference(self):
        time.sleep(5)
        tabbedPane = SwingUtilities.getAncestorOfClass(JTabbedPane, self.truffle_tab.getUiComponent())
        if tabbedPane is not None:
            self.truffle_tab.tabbedPane = tabbedPane
            self.truffle_tab.tabIndex = tabbedPane.indexOfComponent(self.truffle_tab.getUiComponent())
        else:
            print("Warning: Could not find the JTabbedPane. Tab updates won't reflect.")

    def start_external_process(self):
        with self.process_lock:
            binary_path = os.path.join(os.getcwd(), SCRIPT_NAME)
            if not os.path.exists(binary_path):
                raise IOError(SCRIPT_NAME + " not found at path: " + binary_path)
            
            if not self.verify_trufflehog_path(self.truffle_tab.trufflehog_exec_path):
                self._callbacks.printError("TruffleHog binary not found at path: " + self.truffle_tab.trufflehog_exec_path)
                self.running = False
                return

            only_verified_flag = VERIFIED_FLAG if self.truffle_tab.getVerifySecretsFlag() else ""
            allow_overlap_flag = OVERLAP_FLAG if self.truffle_tab.getAllowOverlapFlag() else ""

            # Use sys.executable if it exists; otherwise, if on Windows, fallback to "jython", else "python"
            if sys.executable and os.path.exists(sys.executable):
                python_interpreter = sys.executable
            else:
                python_interpreter = "jython" if os.name == 'nt' else "python"
            
            command = [
                python_interpreter,
                binary_path,
                "--tempdir", self.temp_dir,
                "--trufflehog-path", self.truffle_tab.trufflehog_exec_path
            ]
            if only_verified_flag:
                command.append(VERIFIED_FLAG)
            if allow_overlap_flag:
                command.append(OVERLAP_FLAG)

            self._callbacks.printOutput("Starting TruffleHog child process with command: " + " ".join(command))
            process_builder = ProcessBuilder(command)
            self.process = process_builder.start()

            # On Windows, allow a longer startup delay (2s instead of 1s)
            wait_time = 2 if os.name == 'nt' else 1
            finished_early = self.process.waitFor(wait_time, TimeUnit.SECONDS)
            if finished_early:
                exit_code = self.process.exitValue()
                self._callbacks.printError("The external process exited almost immediately with code: " + str(exit_code))
                self.running = False
                return

            self.process_holder['process'] = self.process
            self.stdin = self.process.getOutputStream()
            self.stdout = self.process.getInputStream()
            self.stderr = self.process.getErrorStream()

            class ShutdownHook(Runnable):
                def run(self_inner):
                    try:
                        process = self.process_holder.get('process')
                        if process:
                            self._callbacks.printOutput("Burp is closing. Terminating child process...")
                            process.destroy()
                            if not process.waitFor(2, TimeUnit.SECONDS):
                                process.destroyForcibly()
                            self._callbacks.printOutput("External process terminated.")
                            self.cleanup_temp_files()
                    except Exception as e:
                        self._callbacks.printError("Error terminating process at shutdown: " + str(e))

            shutdown_thread = JThread(ShutdownHook(), "ShutdownHookThread")
            Runtime.getRuntime().addShutdownHook(shutdown_thread)

            self.running = True
            self.start_response_reader()
            self.start_error_reader()

    def start_stream_reader(self, stream, stream_name, line_callback):
        def read_loop():
            buf = []
            while self.running:
                try:
                    ch = stream.read()
                    if ch == -1:
                        break
                    if chr(ch) == '\n':
                        line = ''.join(buf)
                        buf = []
                        if line.strip():
                            line_callback(line)
                    else:
                        buf.append(chr(ch))
                except Exception as e:
                    self._callbacks.printError("Exception in " + stream_name + " reader: " + str(e))
                    break
            self._callbacks.printOutput(stream_name + " reader thread exiting.")

        t = Thread(target=read_loop, name="Truffle" + stream_name.capitalize() + "Reader")
        t.daemon = True
        t.start()
        return t

    def start_error_reader(self):
        self.stderr_reader_thread = self.start_stream_reader(
            self.stderr,
            "stderr",
            lambda line: self._callbacks.printError(line.rstrip('\r'))
        )

    def start_response_reader(self):
        self.response_reader_thread = self.start_stream_reader(
            self.stdout,
            "response",
            lambda line: self.handle_response_line(line.strip())
        )

    def shutdown_process(self):
        self.running = False
        try:
            if self.stdout:
                self.stdout.close()
            if hasattr(self, 'response_reader_thread') and self.response_reader_thread:
                self.response_reader_thread.join(5)
        except Exception as e:
            self._callbacks.printError("Error shutting down response stream: " + str(e))
        try:
            if self.stderr:
                self.stderr.close()
            if hasattr(self, 'stderr_reader_thread') and self.stderr_reader_thread:
                self.stderr_reader_thread.join(5)
        except Exception as e:
            self._callbacks.printError("Error shutting down error stream: " + str(e))
        old_process = self.process_holder.get('process')
        if old_process:
            try:
                old_process.destroy()
                old_process.waitFor(2, TimeUnit.SECONDS)
                self._callbacks.printOutput("Old external process terminated.")
            except Exception as e:
                self._callbacks.printError("Error terminating old process: " + str(e))
        self.process_holder.clear()
        self.responses.clear()
        self.pending_callbacks.clear()

    def restart_external_process_background(self):
        def do_restart():
            try:
                self._callbacks.printOutput("Restarting child process in background thread...")
                if self.restart_external_process():
                    SwingUtilities.invokeLater(
                        lambda: JOptionPane.showMessageDialog(
                            self.truffle_tab.getUiComponent(),
                            "TruffleHog reloaded successfully with new settings.",
                            "TruffleHog",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    )
                else:
                    SwingUtilities.invokeLater(
                        lambda: JOptionPane.showMessageDialog(
                            self.truffle_tab.getUiComponent(),
                            "Failed to restart TruffleHog child process. Please check the TruffleHog path and try again.",
                            "TruffleHog",
                            JOptionPane.ERROR_MESSAGE
                        )
                    )
            except Exception as e:
                self._callbacks.printError("Failed to restart child process in background thread: " + str(e))

        t = Thread(target=do_restart, name="TruffleRestartThread")
        t.setDaemon(True)
        t.start()

    def restart_external_process(self):
        with self.process_lock:
            self.shutdown_process()

        self.start_external_process()
        if self.running:
            self._callbacks.printOutput("Child process successfully restarted.")
            return True
        self._callbacks.printError("Failed to restart child process.")
        return False

    def handle_response_line(self, line):
        try:
            resp = json.loads(line)
            resp_id = resp.get("id")
            if resp_id:
                with self.response_lock:
                    callback = self.pending_callbacks.pop(resp_id, None)
                    if callback:
                        callback(resp)
        except ValueError as e:
            if "No JSON object could be decoded" in str(e):
                self._callbacks.printOutput(line)
                return
            raise e
        except Exception as e:
            self._callbacks.printError("Error parsing response line at line " + str(sys.exc_info()[2].tb_lineno) + ". Error: " + str(e) + " Line: " + line)

    def extensionUnloaded(self):
        self.shutdown_process()
        self.cleanup_temp_files()

    def processHttpMessage(self, toolFlag, isRequest, messageInfo):
        if not self.truffle_tab.isToolEnabled(toolFlag):
            return

        data = messageInfo.getRequest() if isRequest else messageInfo.getResponse()
        self.executor.submit(lambda: self.handleMessage(data, messageInfo))

    def handleMessage(self, message, messageInfo):
        headers, body = self.splitMessage(message)
        req_id = str(uuid.uuid4())
        headers_filename = os.path.join(self.temp_dir, req_id + HEADER_FILE_SUFFIX)
        body_filename = os.path.join(self.temp_dir, req_id + BODY_FILE_SUFFIX)

        if not self.write_temp_file(headers_filename, headers):
            return
        if not self.write_temp_file(body_filename, body):
            self.cleanup_specific_temp_file(headers_filename)
            return

        def response_callback(response):
            self.createIssue(messageInfo, response)

        with self.response_lock:
            self.pending_callbacks[req_id] = response_callback

    def splitMessage(self, message):
        full_message = message.tostring()
        parts = full_message.split(HEADER_BODY_SEPARATOR, 1)
        if len(parts) == 1:
            return parts[0], b""
        return parts[0], parts[1]

    def write_temp_file(self, path, content):
        try:
            with open(path, 'wb') as f:
                f.write(content)
            self.temp_files.add(path)
        except Exception as e:
            self._callbacks.printError("Failed to write temp file: " + str(e))
            return False
        return True

    def cleanup_specific_temp_file(self, file):
        try:
            os.remove(file)
            self.temp_files.discard(file)
        except Exception as e:
            self._callbacks.printError("Error deleting temp file " + file + ": " + str(e))

    def createIssue(self, messageInfo, issueDetail):
        if not issueDetail.get("results"):
            return

        secrets = self.processIssues(issueDetail)
        if not secrets:
            return

        url = self._helpers.analyzeRequest(messageInfo).getUrl().toString()
        parsed = urlparse(url)
        normalized_url = urlunparse((parsed.scheme, parsed.hostname, parsed.path, '', '', ''))

        for secret in secrets:
            advisory = self.formatIssueDetails(secret)
            duplicate = False
            existing_issues = self._callbacks.getScanIssues(normalized_url)
            if existing_issues:
                duplicate = any(advisory == (issue.getIssueDetail() or "") for issue in existing_issues)

            if not duplicate:
                scanIssue = CustomScanIssue(
                    messageInfo.getHttpService(),
                    self._helpers.analyzeRequest(messageInfo).getUrl(),
                    [messageInfo],
                    ISSUE_PREFIX + secret['secretType'] + ISSUE_SUFFIX,
                    "Medium",
                    "Certain" if secret['verified'] else "Tentative",
                    advisory
                )
                self._callbacks.addScanIssue(scanIssue)

                try:
                    if secret['raw'] in self.truffle_tab.secrets_data:
                        self.truffle_tab.updateSecretUrls(secret['raw'], url, messageInfo, advisory)
                    else:
                        self.truffle_tab.addSecret(
                            secret['secretType'],
                            secret['raw'],
                            secret['redacted'],
                            url,
                            messageInfo,
                            advisory
                        )
                except Exception as e:
                    self._callbacks.printError("Exception in createIssue: " + str(e))

    def processIssues(self, issues):
        seenRaw = set()
        final_issues = []
        for i in issues["results"]:
            if i["raw"] not in seenRaw:
                seenRaw.add(i["raw"])
                final_issues.append(i)
        return final_issues

    def formatIssueDetails(self, secret_details):
        issue = "<p>"
        issue += "<b>Verified:</b> " + ("Yes" if secret_details["verified"] else "No") + "<br>"
        issue += "<b>Secret Type:</b> " + secret_details["secretType"] + "<br>"
        issue += "<b>Decoder Type:</b> " + secret_details["decoderType"] + "<br>"
        issue += "<b>Secret:</b> " + secret_details["raw"] + "<br>"
        issue += "<b>Secret Redacted:</b> " + secret_details["redacted"] + "<br>"
        if secret_details.get("extraData"):
            for k, v in secret_details["extraData"].items():
                k_clean = k.replace("_", " ").title()
                issue += "<b>" + k_clean + ":</b> " + str(v) + "<br>"
        issue += "<b>Description:</b> " + secret_details["detectorDescription"] + "<br>"
        issue += "</p>"
        return issue

    def cleanup_temp_files(self):
        try:
            shutil.rmtree(self.temp_dir)
            self._callbacks.printOutput("Deleted temp directory: " + self.temp_dir)
        except Exception as e:
            self._callbacks.printError("Error deleting temp directory " + self.temp_dir + ": " + str(e))

    def verify_trufflehog_path(self, path):
        # On Windows, check that the file exists.
        if os.name == 'nt':
            if not path or not os.path.isabs(path) or not os.path.exists(path):
                return False
        else:
            if not path or not os.path.isabs(path) or not os.access(path, os.X_OK):
                return False
        try:
            proc = subprocess.Popen([path, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout_data, stderr_data = proc.communicate()
            return b"trufflehog" in (stderr_data.lower() + stdout_data.lower())
        except Exception as e:
            self._callbacks.printError("Cannot verify trufflehog path: " + str(e))
        return False


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, severity, confidence, formattedSecretDetails):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._severity = severity
        self._confidence = confidence
        self._detail = formattedSecretDetails

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
