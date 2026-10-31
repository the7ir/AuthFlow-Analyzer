from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory, IExtensionStateListener
from javax.swing import (JPanel, JTabbedPane, JSplitPane, JScrollPane, JTable, JButton, 
                         JLabel, JTextField, JTextArea, JCheckBox, Box, BoxLayout, 
                         ListSelectionModel, SwingUtilities, BorderFactory, JMenuItem,
                         SwingConstants, JSeparator, JFileChooser, JComboBox,
                         DefaultCellEditor, JOptionPane)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Dimension, Color, Font
from java.awt.event import ComponentAdapter
from java.lang import Integer, Object, String, Boolean
import threading
import traceback
import sys
import json
import re
import os
import copy
import time
import errno
import uuid
import tempfile
from collections import deque
from datetime import datetime

try:
    text_type = unicode
except NameError:
    text_type = str

def as_text(value):
    return "" if value is None else text_type(value)

VARIABLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
VARIABLE_REF = re.compile(r"\$\{([^{}]*)\}")
LISTENER_TOOLS = [("Proxy", 4), ("Repeater", 64), ("Intruder", 32)]

class AuthFlowError(ValueError):
    pass

class ProfileWorkerPool:
    """Bounded FIFO work per profile; independent profiles run concurrently."""
    def __init__(self, workers=4, capacity=256, on_error=None):
        self.condition = threading.Condition(threading.RLock())
        self.notify_workers = getattr(self.condition, "notify_all", self.condition.notifyAll)
        self.queues, self.ready, self.active = {}, deque(), set()
        self.pending, self.capacity, self.closed = 0, capacity, False
        self.threads, self.limit = [], 0
        self.on_error = on_error
        self.resize(workers)

    def resize(self, workers):
        with self.condition:
            self.limit = max(1, min(16, int(workers)))
            if self.closed:
                return
            while len(self.threads) < self.limit:
                thread = threading.Thread(target=self._worker, name="AuthFlow-worker-%d" % (len(self.threads) + 1))
                thread.daemon = True
                self.threads.append(thread)
                thread.start()
            self.notify_workers()

    def submit(self, key, function, args=(), tag=None):
        with self.condition:
            if self.closed or self.pending >= self.capacity:
                return False
            queue = self.queues.setdefault(key, deque())
            if not queue and key not in self.active:
                self.ready.append(key)
            queue.append((function, args, tag))
            self.pending += 1
            self.notify_workers()
            return True

    def cancel_pending(self, predicate):
        with self.condition:
            for key in list(self.queues):
                queue = self.queues[key]
                kept = deque(job for job in queue if not predicate(job[2]))
                self.pending -= len(queue) - len(kept)
                self.queues[key] = kept
                if not kept and key not in self.active:
                    del self.queues[key]
            self.ready = deque(key for key in self.ready if self.queues.get(key))
            self.notify_workers()

    def close(self):
        with self.condition:
            self.closed = True
            self.queues.clear()
            self.ready.clear()
            self.pending = 0
            self.notify_workers()

    def _worker(self):
        while True:
            with self.condition:
                while not self.closed and (not self.ready or len(self.active) >= self.limit):
                    self.condition.wait()
                if self.closed:
                    return
                key = self.ready.popleft()
                function, args, tag = self.queues[key].popleft()
                self.pending -= 1
                self.active.add(key)
            try:
                function(*args)
            except Exception as ex:
                if self.on_error:
                    try:
                        self.on_error(ex)
                    except Exception:
                        pass
            finally:
                with self.condition:
                    self.active.discard(key)
                    if self.queues.get(key):
                        self.ready.append(key)
                    else:
                        self.queues.pop(key, None)
                    self.notify_workers()

def template_variables(template):
    names = VARIABLE_REF.findall(as_text(template))
    for name in names:
        if not VARIABLE_NAME.match(name):
            raise AuthFlowError("Invalid variable reference; use ${variable_name}.")
    return names

def render_template(template, variables):
    template = as_text(template)
    for name in template_variables(template):
        if name not in variables:
            raise AuthFlowError("Variable '%s' has no value. Run the auth flow or set an initial value." % name)
    # One pass: token contents must never be interpreted as another template.
    return VARIABLE_REF.sub(lambda m: as_text(variables[m.group(1)]), template)

def new_auth_step(number=1):
    return {"name": "Step %d" % number, "request": "", "https": True,
            "expected_status": "200-299", "extractors": []}

def response_parts(response):
    parts = re.split(r"\r?\n\r?\n", response, maxsplit=1)
    return parts[0], parts[1] if len(parts) == 2 else ""

def extract_value(extractor, response):
    headers, body = response_parts(response)
    source = extractor.get("source", "Body")
    sources = {"Response": response, "Headers": headers, "Body": body}
    if source not in sources:
        raise AuthFlowError("Unknown extraction source.")
    content = sources[source]
    method = extractor.get("method", "Delimiters")
    selector = as_text(extractor.get("selector", ""))
    end = as_text(extractor.get("end", ""))
    if method == "Delimiters":
        if not selector or not end:
            raise AuthFlowError("Both Start and End delimiters are required.")
        start = content.find(selector)
        if start < 0:
            raise AuthFlowError("Start delimiter was not found.")
        start += len(selector)
        stop = content.find(end, start)
        if stop < 0:
            raise AuthFlowError("End delimiter was not found.")
        value = content[start:stop]
    elif method == "Regex":
        try:
            match = re.search(selector, content, re.DOTALL)
            if not match:
                raise AuthFlowError("Regex did not match the response.")
            group = end or "1"
            value = match.group(int(group) if group.isdigit() else group)
        except (re.error, IndexError):
            raise AuthFlowError("Invalid regex or capture group.")
    elif method == "JSON":
        try:
            value = json.loads(content)
            # JSON Pointer supports arbitrary object keys; dot paths cover simple cases.
            if selector.startswith("/"):
                path = [p.replace("~1", "/").replace("~0", "~") for p in selector[1:].split("/")]
            else:
                path_text = selector[2:] if selector.startswith("$.") else selector
                path_text = re.sub(r"\[(\d+)\]", r".\1", path_text)
                path = [] if path_text in ("", "$") else path_text.split(".")
            for key in path:
                value = value[int(key)] if isinstance(value, list) else value[key]
        except (ValueError, KeyError, IndexError, TypeError):
            raise AuthFlowError("Invalid JSON response or JSON path was not found.")
        if isinstance(value, (dict, list, bool)):
            value = json.dumps(value, separators=(",", ":"))
    elif method == "Header":
        value = None
        for line in headers.splitlines()[1:]:
            if ":" in line:
                key, candidate = line.split(":", 1)
                if key.strip().lower() == selector.strip().lower():
                    value = candidate.strip()
                    break
        if value is None:
            raise AuthFlowError("Response header was not found.")
    else:
        raise AuthFlowError("Unknown extraction method.")
    if value is None or as_text(value) == "":
        raise AuthFlowError("Extracted value is empty.")
    return as_text(value)

def status_matches(status, expected):
    if not expected.strip():
        return True
    matches = False
    for item in expected.split(","):
        item = item.strip().lower()
        if re.match(r"^[1-5]xx$", item):
            matches = matches or status // 100 == int(item[0])
        elif re.match(r"^\d{3}-\d{3}$", item):
            low, high = [int(n) for n in item.split("-")]
            if low > high:
                raise AuthFlowError("Invalid expected status range.")
            matches = matches or low <= status <= high
        elif re.match(r"^\d{3}$", item):
            matches = matches or status == int(item)
        else:
            raise AuthFlowError("Expected status must be blank, 2xx, 200-299, or comma-separated codes/ranges.")
    return matches

def validate_flow(steps, initial_variables, index_offset=0):
    available = set(initial_variables)
    for name in available:
        if not VARIABLE_NAME.match(name):
            raise AuthFlowError("Invalid initial variable name: %s" % name)
    if not steps:
        raise AuthFlowError("Add at least one auth step.")
    for index, step in enumerate(steps):
        prefix = "Step %d: " % (index + index_offset + 1)
        if not step.get("request", "").strip():
            raise AuthFlowError(prefix + "Auth Request is empty.")
        for name in template_variables(step["request"]):
            if name not in available:
                raise AuthFlowError(prefix + "variable '%s' must be set initially or extracted by an earlier step." % name)
        status_matches(200, step.get("expected_status", ""))
        seen = set()
        for extractor in step.get("extractors", []):
            name = extractor.get("variable", "")
            if not VARIABLE_NAME.match(name) or name in seen:
                raise AuthFlowError(prefix + "extractors need valid, unique variable names.")
            seen.add(name)
            if extractor.get("source", "Body") not in ("Response", "Body", "Headers"):
                raise AuthFlowError(prefix + "unknown extraction source.")
            method = extractor.get("method", "Delimiters")
            selector = extractor.get("selector", "")
            if method == "Delimiters":
                if not selector or not extractor.get("end", ""):
                    raise AuthFlowError(prefix + "both Start and End delimiters are required.")
            elif method == "Regex":
                try:
                    pattern = re.compile(selector)
                    group = extractor.get("end", "") or "1"
                    if (group.isdigit() and int(group) > pattern.groups) or (not group.isdigit() and group not in pattern.groupindex):
                        raise AuthFlowError(prefix + "regex capture group does not exist.")
                except re.error:
                    raise AuthFlowError(prefix + "invalid regex.")
            elif method == "Header":
                if not selector.strip():
                    raise AuthFlowError(prefix + "header name is required.")
            elif method != "JSON":
                raise AuthFlowError(prefix + "unknown extraction method.")
        available.update(seen)
    return available

# --- Data Models ---

class AuthStepResult:
    def __init__(self, index, step):
        self.index = index
        self.name = step.get("name", "Step %d" % (index + 1))
        self.status = "Not run"
        self.http_status = None
        self.elapsed_ms = None
        self.error = ""
        self.inputs = {}
        self.variables = {}
        self.captures = [{"variable": ex.get("variable", ""), "value": "",
                          "status": "Not run", "error": ""}
                         for ex in step.get("extractors", [])]
        self.request = None
        self.response = None
        self.service = None

    def getRequest(self):
        return self.request

    def getResponse(self):
        return self.response

    def getHttpService(self):
        return self.service

class AuthTestSession:
    def __init__(self, steps, initial_variables, previous=None):
        self.steps = copy.deepcopy(steps)
        self.initial_variables = dict(initial_variables)
        self.results = [AuthStepResult(i, step) for i, step in enumerate(steps)]
        self.busy = False
        self.status = "Ready"
        # Keep only the unchanged prefix. Editing a producer invalidates its consumers.
        if previous and previous.initial_variables == self.initial_variables:
            for i in range(min(len(steps), len(previous.steps))):
                if steps[i] != previous.steps[i]:
                    break
                self.results[i] = previous.results[i]

    def reset_from(self, index):
        for i in range(index, len(self.steps)):
            self.results[i] = AuthStepResult(i, self.steps[i])

    def inputs_for(self, index):
        variables = dict(self.initial_variables)
        for result in self.results[:index]:
            if result.status != "Success":
                raise AuthFlowError("Run step %d successfully first, or use Test Through Selected." % (result.index + 1))
            variables.update(result.variables)
        return variables

class Profile:
    def __init__(self, name):
        self.id = uuid.uuid4().hex
        self.state_lock = threading.RLock()
        self.auth_lock = threading.RLock()
        self.name = name
        self.detail = ""
        self.note = ""
        self.headers_list = [] # List of [key, value] pairs
        self.match_replace_list = [] # List of [match, replace] pairs
        self.headers_to_remove = [] # List of header keys to remove
        self.ator_enabled = False
        self.listener_enabled = True
        self.auth_request = ""
        self.token_pre = ""
        self.token_post = ""
        self.auth_steps = []
        self.initial_variables = {}
        self.variables = {}
        self.legacy_authorization = False
        self.trigger_condition = "401"
        self.init_token = "None"
        self.last_token = "None"
        self.is_regenerating = False
        self.config_revision = 0
        self.auth_generation = 0
        self.auth_test = None # Runtime diagnostics, never saved or cloned.

    def to_dict(self):
        with self.state_lock:
            return copy.deepcopy(self._to_dict())

    def _to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "detail": self.detail,
            "note": self.note,
            "headers_list": self.headers_list,
            "match_replace_list": self.match_replace_list,
            "headers_to_remove": self.headers_to_remove,
            "ator_enabled": self.ator_enabled,
            "listener_enabled": self.listener_enabled,
            "auth_request": self.auth_request,
            "token_pre": self.token_pre,
            "token_post": self.token_post,
            "auth_steps": self.get_auth_steps(),
            "initial_variables": self.initial_variables,
            "variables": self.variables,
            "legacy_authorization": self.legacy_authorization,
            "trigger_condition": self.trigger_condition,
            "init_token": self.init_token,
            "last_token": self.last_token
        }

    @staticmethod
    def from_dict(d):
        p = Profile(d["name"])
        if re.match(r"^[0-9a-f]{32}$", as_text(d.get("id", ""))):
            p.id = as_text(d["id"])
        p.detail = d.get("detail", "")
        p.note = d.get("note", "")
        p.headers_list = d.get("headers_list", [])
        p.match_replace_list = d.get("match_replace_list", [])
        p.headers_to_remove = d.get("headers_to_remove", [])
        p.ator_enabled = d.get("ator_enabled", False)
        p.listener_enabled = d.get("listener_enabled", True)
        p.auth_request = d.get("auth_request", "")
        p.token_pre = d.get("token_pre", "")
        p.token_post = d.get("token_post", "")
        p.initial_variables = dict(d.get("initial_variables", {}))
        p.variables = dict(d.get("variables", {}))
        p.legacy_authorization = d.get("legacy_authorization", "auth_steps" not in d)
        if "auth_steps" in d:
            p.auth_steps = copy.deepcopy(d["auth_steps"])
        else:
            p.auth_steps = p.get_auth_steps()
        p.trigger_condition = d.get("trigger_condition", "401")
        p.init_token = d.get("init_token", "None")
        p.last_token = d.get("last_token", "None")
        return p

    def get_auth_steps(self):
        if self.auth_steps:
            return copy.deepcopy(self.auth_steps)
        if self.auth_request.strip():
            return [{"name": "Login / Refresh", "request": self.auth_request,
                     "https": True, "expected_status": "", "extractors": [
                         {"variable": "AuthorToken", "source": "Response", "method": "Delimiters",
                          "selector": self.token_pre, "end": self.token_post}]}]
        return []

    def clone(self, name):
        duplicate = Profile.from_dict(copy.deepcopy(self.to_dict()))
        duplicate.id = uuid.uuid4().hex
        duplicate.name = name
        return duplicate

    def snapshot(self):
        with self.state_lock:
            snapshot = Profile.from_dict(self.to_dict())
            snapshot.config_revision = self.config_revision
            snapshot.auth_generation = self.auth_generation
            snapshot.source_profile = self
            snapshot.auth_lock = self.auth_lock
            return snapshot

class RequestGroup:
    def __init__(self, id, method, url):
        self.id = id
        self.method = method
        self.url = url
        self.responses = {} # profile_name -> IHttpRequestResponse
        self.statuses = {}
        self.profile_names = {}
        self.cancelled = False
        self.lock = threading.RLock()

class StoredMessage:
    """Read-only HTTP buffers restored from a Results export."""
    def __init__(self, service, request, response):
        self.service, self.request, self.response = service, request, response

    def getHttpService(self): return self.service
    def getRequest(self): return self.request
    def getResponse(self): return self.response

# --- UI Renderers ---

class StatusColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        cell = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        if value is not None and value != "-":
            status = str(value)
            if status == "ATOR...":
                cell.setForeground(Color.RED)
                cell.setFont(cell.getFont().deriveFont(Font.BOLD))
            elif status.startswith("1"):
                cell.setForeground(Color(0, 100, 200)) # Blue (Informational)
            elif status.startswith("2"):
                cell.setForeground(Color(0, 150, 0)) # Green (Success)
            elif status.startswith("3"):
                cell.setForeground(Color(255, 140, 0)) # Orange (Redirection)
            elif status.startswith("4"):
                cell.setForeground(Color.RED) # Red (Client Error)
            elif status.startswith("5"):
                cell.setForeground(Color(139, 0, 0)) # Dark Red (Server Error)
            else:
                if not isSelected: cell.setForeground(Color.BLACK)
            
            # Make status codes bold for better visibility
            if not status == "-":
                cell.setFont(cell.getFont().deriveFont(Font.BOLD))
        elif not isSelected:
            cell.setForeground(Color.BLACK)
            cell.setFont(cell.getFont().deriveFont(Font.PLAIN))
        return cell

class NumericalTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

    def getColumnClass(self, column):
        if column == 0: return Integer
        if column >= 3: return Object # Keep as Object to handle "-" safely but use renderer
        return Object

class ReadOnlyTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False

class ListenerProfileModel(DefaultTableModel):
    def getColumnClass(self, column):
        return Boolean if column == 1 else String

    def isCellEditable(self, row, column):
        return column == 1

class ResultMessageController(IMessageEditorController):
    def __init__(self, message):
        self.message = message

    def getHttpService(self):
        return self.message.getHttpService()

    def getRequest(self):
        return self.message.getRequest()

    def getResponse(self):
        return self.message.getResponse()

class InitialSplitDivider(ComponentAdapter):
    def componentResized(self, event):
        split = event.getComponent()
        if split.getWidth() > 0:
            split.setDividerLocation(0.5)
            split.removeComponentListener(self)

class AuthStepEditor(JPanel):
    def __init__(self, step):
        JPanel.__init__(self, BorderLayout())
        settings = JPanel()
        settings.setLayout(BoxLayout(settings, BoxLayout.Y_AXIS))
        fields = JPanel(FlowLayout(FlowLayout.LEFT))
        self.name_field = JTextField(step.get("name", "Auth Step"), 16)
        self.https_cb = JCheckBox("HTTPS", step.get("https", True))
        self.status_field = JTextField(step.get("expected_status", "200-299"), 14)
        for comp in [JLabel("Step name:"), self.name_field, self.https_cb,
                     JLabel("Expected status:"), self.status_field]:
            fields.add(comp)
        settings.add(fields)
        settings.add(JLabel("Status: 200-299, 2xx, 200,302; blank accepts any status. Port comes from Host."))
        settings.add(JLabel("Auth Request (Raw) - use ${name} for initial values or values from earlier steps:"))
        self.request_area = JTextArea(step.get("request", ""), 10, 60)
        settings.add(JScrollPane(self.request_area))
        self.add(settings, BorderLayout.CENTER)

        extracts = JPanel(BorderLayout())
        extracts.add(JLabel("Extract response values (zero or more per step):"), BorderLayout.NORTH)
        self.extractor_model = DefaultTableModel(
            ["Variable", "Source", "Method", "Selector / Start", "End / Regex group"], 0)
        self.extractor_table = JTable(self.extractor_model)
        self.extractor_table.getColumnModel().getColumn(1).setCellEditor(
            DefaultCellEditor(JComboBox(["Body", "Headers", "Response"])))
        self.extractor_table.getColumnModel().getColumn(2).setCellEditor(
            DefaultCellEditor(JComboBox(["Delimiters", "JSON", "Regex", "Header"])))
        for ex in step.get("extractors", []):
            self.extractor_model.addRow([ex.get("variable", ""), ex.get("source", "Body"),
                ex.get("method", "Delimiters"), ex.get("selector", ""), ex.get("end", "")])
        scroll = JScrollPane(self.extractor_table)
        scroll.setPreferredSize(Dimension(650, 110))
        extracts.add(scroll, BorderLayout.CENTER)
        footer = JPanel()
        footer.setLayout(BoxLayout(footer, BoxLayout.Y_AXIS))
        buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        buttons.add(JButton("Add Variable", actionPerformed=self.add_extractor))
        buttons.add(JButton("Remove Variable", actionPerformed=self.remove_extractor))
        footer.add(buttons)
        footer.add(JLabel("JSON: data.token, items[0].id or /data/token. Regex: capture group defaults to 1."))
        footer.add(JLabel("Delimiters: Start + End. Header: header name (first match); reads response headers."))
        extracts.add(footer, BorderLayout.SOUTH)
        self.add(extracts, BorderLayout.SOUTH)

    def add_extractor(self, e):
        self.extractor_model.addRow(["token", "Body", "JSON", "access_token", ""])

    def remove_extractor(self, e):
        row = self.extractor_table.getSelectedRow()
        if row != -1:
            if self.extractor_table.isEditing():
                self.extractor_table.getCellEditor().stopCellEditing()
            self.extractor_model.removeRow(row)

    def to_step(self):
        if self.extractor_table.isEditing():
            self.extractor_table.getCellEditor().stopCellEditing()
        keys = ["variable", "source", "method", "selector", "end"]
        extractors = []
        for row in range(self.extractor_model.getRowCount()):
            values = [as_text(self.extractor_model.getValueAt(row, col)) for col in range(5)]
            values[0] = values[0].strip()
            extractors.append(dict(zip(keys, values)))
        return {"name": as_text(self.name_field.getText()).strip(),
                "https": self.https_cb.isSelected(),
                "expected_status": as_text(self.status_field.getText()).strip(),
                "request": as_text(self.request_area.getText()), "extractors": extractors}

# --- Main Extension Class ---

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("AuthFlow-Analyzer PRO")
        
        self.profiles = []
        self.results_data = []
        self.results_lock = threading.RLock()
        self.extension_enabled = True
        self.config_lock = threading.RLock()
        self.config_file = "authflow_config.json"
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(callbacks.getExtensionFilename())), "data")
        self.load_listener_settings()
        
        self.status_renderer = StatusColorRenderer()
        self.init_ui()
        
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerExtensionStateListener(self)
        
        print("AuthFlow-Analyzer PRO loaded successfully.")

    def init_ui(self):
        self.listener_tools = getattr(self, "listener_tools", dict((name, True) for name, flag in LISTENER_TOOLS))
        self.listener_all_profiles = getattr(self, "listener_all_profiles", True)
        self.request_templates = getattr(self, "request_templates", [])
        self.results_lock = getattr(self, "results_lock", threading.RLock())
        self.config_lock = getattr(self, "config_lock", threading.RLock())
        self.worker_threads = getattr(self, "worker_threads", 4)
        self.extension_enabled = getattr(self, "extension_enabled", True)
        self.unloaded = False
        self.listener_slots = threading.BoundedSemaphore(256)
        self.listener_dropped = 0
        self.data_dir = getattr(self, "data_dir", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
        self.main_panel = JPanel(BorderLayout())
        
        # --- Top Global Toolbar ---
        top_toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        top_toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY))
        
        self.global_enabled_cb = JCheckBox("Enable Extension", True)
        self.global_enabled_cb.addActionListener(lambda e: self.toggle_global_status(e))
        
        save_btn = JButton("Save Profiles", actionPerformed=self.save_config_action)
        load_btn = JButton("Load Config File", actionPerformed=self.load_config_action)
        save_p_btn = JButton("Save Profile Changes", actionPerformed=self.save_profile_config)
        save_p_btn.setBackground(Color(220, 255, 220))
        
        top_toolbar.add(self.global_enabled_cb)
        top_toolbar.add(Box.createRigidArea(Dimension(20, 0)))
        top_toolbar.add(save_btn)
        top_toolbar.add(load_btn)
        top_toolbar.add(save_p_btn)
        top_toolbar.add(JButton("Clear All Results", actionPerformed=self.clear_results))
        top_toolbar.add(JButton("Clear Logs", actionPerformed=lambda e: self.log_table_model.setRowCount(0)))
        toolbars = JPanel()
        toolbars.setLayout(BoxLayout(toolbars, BoxLayout.Y_AXIS))
        toolbars.add(top_toolbar)
        listener_toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        listener_toolbar.add(JLabel("Listen on:"))
        self.listener_tool_cbs = {}
        for name, flag in LISTENER_TOOLS:
            checkbox = JCheckBox(name, self.listener_tools[name])
            checkbox.addActionListener(self.listener_settings_changed)
            self.listener_tool_cbs[name] = checkbox
            listener_toolbar.add(checkbox)
        listener_toolbar.add(JLabel("Profiles:"))
        self.listener_mode_combo = JComboBox(["All profiles", "Selected profiles"])
        self.listener_mode_combo.setSelectedIndex(0 if self.listener_all_profiles else 1)
        self.listener_mode_combo.addActionListener(self.listener_settings_changed)
        listener_toolbar.add(self.listener_mode_combo)
        listener_toolbar.add(JLabel("Workers:"))
        self.worker_count_combo = JComboBox(["1", "2", "4", "8", "16"])
        self.worker_count_combo.setSelectedItem(str(self.worker_threads))
        self.worker_count_combo.addActionListener(self.worker_count_changed)
        listener_toolbar.add(self.worker_count_combo)
        listener_toolbar.add(JLabel("Choose profiles using Listen in Config."))
        toolbars.add(listener_toolbar)
        self.main_panel.add(toolbars, BorderLayout.NORTH)

        self.tabs = JTabbedPane()
        
        # --- TAB 1: CONFIGURATION ---
        self.config_tab = JPanel(BorderLayout())
        
        # Profile List (Left)
        self.p_list_model = ListenerProfileModel(["Profiles", "Listen"], 0)
        self.p_list_model.addTableModelListener(self.listener_profile_changed)
        self.p_list_table = JTable(self.p_list_model)
        self.p_list_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.p_list_table.getSelectionModel().addListSelectionListener(self.profile_selection_changed)

        left_pnl = JPanel(BorderLayout())
        left_pnl.add(JScrollPane(self.p_list_table), BorderLayout.CENTER)
        p_btns = JPanel(FlowLayout(FlowLayout.LEFT))
        p_btns.add(JButton("Add", actionPerformed=self.add_profile))
        p_btns.add(JButton("Clone", actionPerformed=self.clone_profile))
        p_btns.add(JButton("Remove", actionPerformed=self.remove_profile))
        left_pnl.add(p_btns, BorderLayout.SOUTH)
        left_pnl.setPreferredSize(Dimension(250, 600))

        # Profile Editor (Center)
        self.editor_pnl = JPanel()
        self.editor_pnl.setLayout(BoxLayout(self.editor_pnl, BoxLayout.Y_AXIS))
        self.editor_pnl.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 10))

        self.p_name_field = JTextField(50)
        self.p_detail_field = JTextField(50)

        # Headers Table
        self.h_table_model = DefaultTableModel(["Header Key", "Header Value"], 0)
        self.h_table = JTable(self.h_table_model)
        h_scroll = JScrollPane(self.h_table)
        h_scroll.setPreferredSize(Dimension(450, 150))

        h_btns = JPanel(FlowLayout(FlowLayout.LEFT))
        h_btns.add(JButton("Add Header Row", actionPerformed=self.add_header_row))
        h_btns.add(JButton("Remove Selected", actionPerformed=self.remove_header_row))

        # Match and Replace Table
        self.mr_table_model = DefaultTableModel(["Match String", "Replace With"], 0)
        self.mr_table = JTable(self.mr_table_model)
        mr_scroll = JScrollPane(self.mr_table)
        mr_scroll.setPreferredSize(Dimension(450, 150))

        mr_btns = JPanel(FlowLayout(FlowLayout.LEFT))
        mr_btns.add(JButton("Add M&R Row", actionPerformed=self.add_mr_row))
        mr_btns.add(JButton("Remove M&R Selected", actionPerformed=self.remove_mr_row))

        # Headers to Remove Table
        self.rm_table_model = DefaultTableModel(["Header Key to Remove"], 0)
        self.rm_table = JTable(self.rm_table_model)
        rm_scroll = JScrollPane(self.rm_table)
        rm_scroll.setPreferredSize(Dimension(450, 100))

        rm_btns = JPanel(FlowLayout(FlowLayout.LEFT))
        rm_btns.add(JButton("Add Removal Row", actionPerformed=self.add_rm_row))
        rm_btns.add(JButton("Remove Selected Row", actionPerformed=self.remove_rm_row))

        # ATOR Inputs
        self.ator_enabled_cb = JCheckBox("Enable ATOR Regeneration")
        self.trigger_field = JTextField(50)
        self.auth_step_tabs = JTabbedPane()
        self.auth_step_tabs.setPreferredSize(Dimension(700, 440))
        self.initial_vars_model = DefaultTableModel(["Variable", "Initial Value"], 0)
        self.initial_vars_table = JTable(self.initial_vars_model)
        self.variables_model = ReadOnlyTableModel(["Variable", "Current Value"], 0)
        self.variables_table = JTable(self.variables_model)

        self.add_labeled_comp(self.editor_pnl, "Profile Name:", self.p_name_field)
        self.add_labeled_comp(self.editor_pnl, "Detail (Config):", self.p_detail_field)
        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        
        self.editor_pnl.add(JLabel("Headers to Replace (Key-Value):"))
        self.editor_pnl.add(JLabel("Use variables in values, e.g. Authorization: Bearer ${AuthorToken}"))
        self.editor_pnl.add(h_scroll)
        self.editor_pnl.add(h_btns)

        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        self.editor_pnl.add(JLabel("Match and Replace (Request Body/Headers):"))
        self.editor_pnl.add(JLabel("Literal replacements; both columns support ${variable_name}."))
        self.editor_pnl.add(mr_scroll)
        self.editor_pnl.add(mr_btns)

        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        self.editor_pnl.add(JLabel("Headers to Remove:"))
        self.editor_pnl.add(rm_scroll)
        self.editor_pnl.add(rm_btns)

        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        self.editor_pnl.add(JSeparator())
        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        self.editor_pnl.add(self.ator_enabled_cb)
        self.add_labeled_comp(self.editor_pnl, "Trigger Condition:", self.trigger_field)
        self.editor_pnl.add(JLabel("Initial variables (available at the start of every run):"))
        initial_scroll = JScrollPane(self.initial_vars_table)
        initial_scroll.setPreferredSize(Dimension(650, 90))
        self.editor_pnl.add(initial_scroll)
        initial_buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        initial_buttons.add(JButton("Add Initial Variable", actionPerformed=lambda e: self.initial_vars_model.addRow(["name", ""])))
        initial_buttons.add(JButton("Remove Initial Variable", actionPerformed=self.remove_initial_variable))
        self.editor_pnl.add(initial_buttons)
        self.editor_pnl.add(JLabel("Auth flow - steps run from left to right; variables belong to this profile:"))
        template_buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        template_buttons.add(JLabel("Template Request:"))
        self.request_template_combo = JComboBox()
        self.request_template_combo.setPreferredSize(Dimension(220, 26))
        self.refresh_request_templates()
        template_buttons.add(self.request_template_combo)
        template_buttons.add(JButton("Use as New Step", actionPerformed=self.use_request_template))
        template_buttons.add(JButton("Save Selected as Template", actionPerformed=self.save_step_template))
        template_buttons.add(JButton("Delete Template", actionPerformed=self.delete_request_template))
        self.editor_pnl.add(template_buttons)
        self.editor_pnl.add(self.auth_step_tabs)
        step_buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        step_buttons.add(JButton("Add Step", actionPerformed=self.add_auth_step))
        step_buttons.add(JButton("Remove Step", actionPerformed=self.remove_auth_step))
        step_buttons.add(JButton("Move Earlier", actionPerformed=lambda e: self.move_auth_step(-1)))
        step_buttons.add(JButton("Move Later", actionPerformed=lambda e: self.move_auth_step(1)))
        step_buttons.add(JButton("Save & Run Auth Flow", actionPerformed=self.run_config_auth_flow))
        self.editor_pnl.add(step_buttons)
        test_buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        self.auth_test_buttons = []
        for title, mode in [("Test Selected Step", "step"),
                            ("Test Through Selected", "through"), ("Test Full Flow", "full")]:
            button = JButton(title, actionPerformed=lambda e, mode=mode: self.run_config_auth_test(e, mode))
            self.auth_test_buttons.append(button)
            test_buttons.add(button)
        test_buttons.add(JButton("Reset Test", actionPerformed=self.reset_auth_test))
        self.editor_pnl.add(test_buttons)
        self.editor_pnl.add(JLabel("Tests send requests using current editor values. Test captures feed later test steps."))
        self.editor_pnl.add(JLabel("Save & Run Auth Flow applies a successful flow to this profile's headers/replacements."))
        self.auth_test_status = JLabel("No test run yet.")
        self.editor_pnl.add(self.auth_test_status)
        self.auth_test_model = ReadOnlyTableModel(["Step", "Status", "HTTP", "Time (ms)", "Captured variables"], 0)
        self.auth_test_table = JTable(self.auth_test_model)
        self.auth_test_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.auth_test_table.getSelectionModel().addListSelectionListener(self.auth_test_selection_changed)
        test_scroll = JScrollPane(self.auth_test_table)
        test_scroll.setPreferredSize(Dimension(700, 100))
        self.editor_pnl.add(test_scroll)
        self.auth_test_detail = JTabbedPane()
        self.auth_test_detail.setPreferredSize(Dimension(700, 330))
        values_panel = JPanel(BorderLayout())
        self.auth_capture_model = ReadOnlyTableModel(["Variable", "Value", "Status", "Detail"], 0)
        self.auth_capture_table = JTable(self.auth_capture_model)
        self.auth_capture_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self.auth_capture_table.getSelectionModel().addListSelectionListener(self.auth_capture_selection_changed)
        values_panel.add(JScrollPane(self.auth_capture_table), BorderLayout.CENTER)
        value_panel = JPanel(BorderLayout())
        value_panel.add(JLabel("Select a variable to view/copy its full value (names are case-sensitive):"), BorderLayout.NORTH)
        self.auth_capture_value = JTextArea(3, 60)
        self.auth_capture_value.setEditable(False)
        self.auth_capture_value.setLineWrap(True)
        value_panel.add(JScrollPane(self.auth_capture_value), BorderLayout.CENTER)
        values_panel.add(value_panel, BorderLayout.SOUTH)
        self.auth_test_detail.addTab("Variables", values_panel)
        self.auth_test_http_panel = JPanel(BorderLayout())
        self.auth_test_detail.addTab("Request / Response", self.auth_test_http_panel)
        self.auth_test_error = JTextArea(2, 60)
        self.auth_test_error.setEditable(False)
        self.auth_test_error.setLineWrap(True)
        self.auth_test_error.setWrapStyleWord(True)
        self.editor_pnl.add(JScrollPane(self.auth_test_error))
        self.editor_pnl.add(self.auth_test_detail)
        self._updating_auth_test_ui = False
        self.auth_test_editors = []
        self.editor_pnl.add(JLabel("Current variables (updated only after the entire flow succeeds):"))
        variables_scroll = JScrollPane(self.variables_table)
        variables_scroll.setPreferredSize(Dimension(650, 100))
        self.editor_pnl.add(variables_scroll)

        # Notes Panel (Right)
        self.notes_pnl = JPanel(BorderLayout())
        self.notes_pnl.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        self.notes_pnl.add(JLabel("Profile Notes:"), BorderLayout.NORTH)
        self.p_note_area = JTextArea()
        self.p_note_area.setLineWrap(True)
        self.p_note_area.setWrapStyleWord(True)
        self.notes_pnl.add(JScrollPane(self.p_note_area), BorderLayout.CENTER)
        self.notes_pnl.setPreferredSize(Dimension(300, 600))

        # Assemble Config Tab using nested splits
        right_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, JScrollPane(self.editor_pnl), self.notes_pnl)
        right_split.setResizeWeight(0.7)

        main_config_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_pnl, right_split)

        self.config_tab.add(main_config_split, BorderLayout.CENTER)
        # --- TAB 2: ATOR MANAGEMENT ---
        self.ator_mgmt_tab = JPanel(BorderLayout())
        self.ator_mgmt_model = DefaultTableModel(["Profile", "Status", "Init Token", "Last Token"], 0)
        self.ator_mgmt_table = JTable(self.ator_mgmt_model)
        
        ator_ctrl_pnl = JPanel(FlowLayout(FlowLayout.LEFT))
        ator_ctrl_pnl.add(JButton("Run ATOR Selected", actionPerformed=self.run_manual_ator))
        ator_ctrl_pnl.add(JButton("Run ATOR All Enabled", actionPerformed=self.run_all_ator_sequential))
        ator_ctrl_pnl.add(JButton("Enable ATOR for All", actionPerformed=lambda e: self.set_all_ator_enabled(True)))
        ator_ctrl_pnl.add(JButton("Disable ATOR for All", actionPerformed=lambda e: self.set_all_ator_enabled(False)))
        
        self.ator_mgmt_tab.add(JScrollPane(self.ator_mgmt_table), BorderLayout.CENTER)
        self.ator_mgmt_tab.add(ator_ctrl_pnl, BorderLayout.SOUTH)

        # --- TAB 3: RESULTS ---
        self.results_tab = JPanel(BorderLayout())
        
        # Search Bar
        search_bar = JPanel(FlowLayout(FlowLayout.LEFT))
        search_bar.add(JLabel("Filter Results:"))
        self.search_field = JTextField(30)
        self.search_field.getDocument().addDocumentListener(self.create_search_listener())
        search_bar.add(self.search_field)
        search_bar.add(JButton("Export Results", actionPerformed=self.export_results_action))
        search_bar.add(JButton("Import Results", actionPerformed=self.import_results_action))
        self.results_file_label = JLabel("")
        self.results_tab.add(self.results_file_label, BorderLayout.SOUTH)
        self.results_tab.add(search_bar, BorderLayout.NORTH)

        self.res_table_model = NumericalTableModel(["ID", "Method", "URL", "Base Status"], 0)
        self.result_column_keys = []
        self.result_column_names = {}
        self.res_table = JTable(self.res_table_model)
        self.res_table.setAutoCreateRowSorter(True)
        from javax.swing.table import TableRowSorter
        self.row_sorter = TableRowSorter(self.res_table_model)
        self.res_table.setRowSorter(self.row_sorter)
        self.res_table.getSelectionModel().addListSelectionListener(self.result_selection_changed)
        self.reapply_all_renderers()
        
        self.detail_tabs = JTabbedPane()
        res_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.res_table), self.detail_tabs)
        res_split.setDividerLocation(300)
        
        self.results_tab.add(res_split, BorderLayout.CENTER)

        # --- TAB 4: LOGS ---
        self.logs_tab = JPanel(BorderLayout())
        self.log_table_model = DefaultTableModel(["Timestamp", "Profile", "Message"], 0)
        self.log_table = JTable(self.log_table_model)
        self.logs_tab.add(JScrollPane(self.log_table), BorderLayout.CENTER)

        # Add All Tabs
        self.tabs.addTab("Config", self.config_tab)
        self.tabs.addTab("ATOR Management", self.ator_mgmt_tab)
        self.tabs.addTab("Results", self.results_tab)
        self.tabs.addTab("Logs", self.logs_tab)
        self.main_panel.add(self.tabs, BorderLayout.CENTER)

    def toggle_global_status(self, e):
        self.extension_enabled = self.global_enabled_cb.isSelected()
        self.add_log("System", "Global status: " + ("Enabled" if self.extension_enabled else "Disabled"))

    def load_listener_settings(self):
        self.listener_tools = dict((name, True) for name, flag in LISTENER_TOOLS)
        self.listener_all_profiles = True
        self.request_templates = []
        self.worker_threads = 4
        try:
            raw = self._callbacks.loadExtensionSetting("authflow_listener_settings")
            settings = json.loads(raw) if raw else {}
            self.listener_tools.update((name, bool(settings.get("tools", {}).get(name, True)))
                                       for name, flag in LISTENER_TOOLS)
            self.listener_all_profiles = bool(settings.get("all_profiles", True))
            self.request_templates = settings.get("request_templates", [])
            if not isinstance(self.request_templates, list):
                self.request_templates = []
            self.request_templates = [t for t in self.request_templates
                if isinstance(t, dict) and isinstance(t.get("name"), (str, text_type))
                and isinstance(t.get("step"), dict) and isinstance(t["step"].get("request"), (str, text_type))]
            workers = settings.get("worker_threads", 4)
            self.worker_threads = workers if workers in (1, 2, 4, 8, 16) else 4
        except (ValueError, TypeError, AttributeError):
            pass

    def save_listener_settings(self):
        if hasattr(self, "_callbacks") and hasattr(self._callbacks, "saveExtensionSetting"):
            self._callbacks.saveExtensionSetting("authflow_listener_settings", json.dumps({
                "tools": self.listener_tools, "all_profiles": self.listener_all_profiles,
                "request_templates": self.request_templates, "worker_threads": self.worker_threads}))

    def get_worker_pool(self):
        with self.config_lock:
            if not hasattr(self, "worker_pool"):
                self.worker_pool = ProfileWorkerPool(getattr(self, "worker_threads", 4),
                    on_error=lambda ex: self.add_log("System", "Worker failed: " + as_text(ex)))
                if getattr(self, "unloaded", False):
                    self.worker_pool.close()
            return self.worker_pool

    def worker_count_changed(self, e):
        self.worker_threads = int(as_text(self.worker_count_combo.getSelectedItem()))
        self.get_worker_pool().resize(self.worker_threads)
        self.save_listener_settings()

    def enqueue_profile_work(self, profile, function, args):
        if not self.get_worker_pool().submit(profile.id, function, args):
            self.add_log(profile.name, "Queue full: work was not started. Try again after pending requests finish.")
            return False
        return True

    def extensionUnloaded(self):
        self.unloaded = True
        self.extension_enabled = False
        if hasattr(self, "worker_pool"):
            self.worker_pool.close()
        if hasattr(self, "file_pool"):
            self.file_pool.close()
        with self.results_lock:
            for group in self.results_data:
                group.cancelled = True

    def listener_settings_changed(self, e):
        self.listener_tools = dict((name, cb.isSelected()) for name, cb in self.listener_tool_cbs.items())
        self.listener_all_profiles = self.listener_mode_combo.getSelectedIndex() == 0
        self.save_listener_settings()

    def listener_profile_changed(self, e):
        row = e.getFirstRow()
        if e.getColumn() == 1 and 0 <= row < len(self.profiles):
            profile = self.profiles[row]
            with profile.state_lock:
                profile.listener_enabled = bool(self.p_list_model.getValueAt(row, 1))
            self.save_config_action(None)

    def selected_listener_profiles(self, tool_flag):
        if not self.extension_enabled:
            return []
        if not any(flag == tool_flag and self.listener_tools.get(name, False) for name, flag in LISTENER_TOOLS):
            return []
        with self.config_lock:
            return [p for p in self.profiles if self.listener_all_profiles or p.listener_enabled]

    def set_all_ator_enabled(self, enabled):
        for profile in self.profiles:
            with profile.state_lock:
                profile.ator_enabled = enabled
            self.update_ator_status_ui(profile, "Enabled" if enabled else "Disabled")
        if self.p_list_table.getSelectedRow() != -1:
            self.ator_enabled_cb.setSelected(enabled)
        self.save_config_action(None)
        self.add_log("System", "ATOR regeneration %s for all profiles." % ("enabled" if enabled else "disabled"))

    def add_labeled_comp(self, pnl, label_text, comp):
        container = JPanel(FlowLayout(FlowLayout.LEFT))
        label = JLabel(label_text)
        label.setPreferredSize(Dimension(150, 25))
        container.add(label)
        container.add(comp)
        pnl.add(container)

    def getTabCaption(self): return "AuthFlow"
    def getUiComponent(self): return self.main_panel

    def reapply_all_renderers(self):
        # Column 3 is Base Status, 4+ are Profiles
        for i in range(3, self.res_table.getColumnCount()):
            self.res_table.getColumnModel().getColumn(i).setCellRenderer(self.status_renderer)

    # --- Profile Management Logic ---

    def unique_profile_name(self, base):
        names = set(p.name for p in self.profiles)
        candidate = base
        suffix = 2
        while candidate in names:
            candidate = "%s %d" % (base, suffix)
            suffix += 1
        return candidate

    def add_profile(self, e):
        name = self.unique_profile_name("Profile " + str(len(self.profiles) + 1))
        p = Profile(name)
        with self.config_lock:
            self.profiles.append(p)
        self.p_list_model.addRow([name, p.listener_enabled])
        self.ator_mgmt_model.addRow([name, "Idle", "None", "None"])
        self.ensure_result_columns([(p.id, name)])
        self.p_list_table.setRowSelectionInterval(len(self.profiles) - 1, len(self.profiles) - 1)

    def clone_profile(self, e):
        row = self.p_list_table.getSelectedRow()
        if row == -1 or not self.save_profile_config(e):
            return
        source = self.profiles[row]
        duplicate = source.clone(self.unique_profile_name(source.name + " (Copy)"))
        with self.config_lock:
            self.profiles.append(duplicate)
        self.p_list_model.addRow([duplicate.name, duplicate.listener_enabled])
        self.ator_mgmt_model.addRow([duplicate.name, "Idle", duplicate.init_token, duplicate.last_token])
        self.ensure_result_columns([(duplicate.id, duplicate.name)])
        index = len(self.profiles) - 1
        self.p_list_table.setRowSelectionInterval(index, index)
        self.save_config_action(None)
        self.add_log("System", "Cloned profile: " + source.name + " -> " + duplicate.name)

    def remove_profile(self, e):
        row = self.p_list_table.getSelectedRow()
        if row != -1:
            with self.config_lock:
                self.profiles.pop(row)
            self.p_list_model.removeRow(row)
            self.ator_mgmt_model.removeRow(row)

    def add_header_row(self, e):
        self.h_table_model.addRow(["Authorization", "Bearer null"])

    def remove_header_row(self, e):
        row = self.h_table.getSelectedRow()
        if row != -1: self.h_table_model.removeRow(row)

    def add_mr_row(self, e):
        self.mr_table_model.addRow(["match_me", "replace_me"])

    def remove_mr_row(self, e):
        row = self.mr_table.getSelectedRow()
        if row != -1: self.mr_table_model.removeRow(row)

    def add_rm_row(self, e):
        self.rm_table_model.addRow(["Header-Name"])

    def remove_rm_row(self, e):
        row = self.rm_table.getSelectedRow()
        if row != -1: self.rm_table_model.removeRow(row)

    def remove_initial_variable(self, e):
        row = self.initial_vars_table.getSelectedRow()
        if row != -1:
            if self.initial_vars_table.isEditing():
                self.initial_vars_table.getCellEditor().stopCellEditing()
            self.initial_vars_model.removeRow(row)

    def add_auth_step(self, e):
        step = new_auth_step(self.auth_step_tabs.getTabCount() + 1)
        editor = AuthStepEditor(step)
        self.auth_step_tabs.addTab(step["name"], editor)
        self.auth_step_tabs.setSelectedComponent(editor)

    def refresh_request_templates(self):
        self.request_template_combo.removeAllItems()
        for template in self.request_templates:
            self.request_template_combo.addItem(template["name"])

    def store_request_template(self, name, step):
        name = as_text(name).strip()
        if not name or any(t["name"] == name for t in self.request_templates):
            raise AuthFlowError("Choose a unique, non-empty template name.")
        if not step.get("request", "").strip():
            raise AuthFlowError("Template Request is empty.")
        self.request_templates.append({"name": name, "step": copy.deepcopy(step)})
        self.save_listener_settings()
        self.refresh_request_templates()
        self.request_template_combo.setSelectedIndex(len(self.request_templates) - 1)

    def save_step_template(self, e):
        editor = self.auth_step_tabs.getSelectedComponent()
        if editor is not None:
            self.prompt_save_template(editor.to_step())

    def prompt_save_template(self, step):
        name = JOptionPane.showInputDialog(self.main_panel, "Template name:", step.get("name", "Auth Request"))
        if name is not None:
            try:
                self.store_request_template(name, step)
            except AuthFlowError as ex:
                JOptionPane.showMessageDialog(self.main_panel, as_text(ex), "Template Request", JOptionPane.ERROR_MESSAGE)

    def use_request_template(self, e):
        index = self.request_template_combo.getSelectedIndex()
        if self.p_list_table.getSelectedRow() == -1 or index == -1:
            return
        step = copy.deepcopy(self.request_templates[index]["step"])
        self.auth_step_tabs.addTab(step.get("name", "Auth Step"), AuthStepEditor(step))
        self.auth_step_tabs.setSelectedIndex(self.auth_step_tabs.getTabCount() - 1)

    def delete_request_template(self, e):
        index = self.request_template_combo.getSelectedIndex()
        if index != -1:
            self.request_templates.pop(index)
            self.save_listener_settings()
            self.refresh_request_templates()

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages or messages[0].getRequest() is None:
            return []
        message = messages[0]
        step = new_auth_step()
        step["name"] = "Auth Request"
        step["request"] = self._helpers.bytesToString(message.getRequest())
        step["https"] = message.getHttpService().getProtocol() == "https"
        return [JMenuItem("AuthFlow: Save as Template Request",
                          actionPerformed=lambda e: self.prompt_save_template(step))]

    def remove_auth_step(self, e):
        index = self.auth_step_tabs.getSelectedIndex()
        if index != -1:
            self.auth_step_tabs.removeTabAt(index)

    def move_auth_step(self, direction):
        index = self.auth_step_tabs.getSelectedIndex()
        target = index + direction
        if index >= 0 and 0 <= target < self.auth_step_tabs.getTabCount():
            editor = self.auth_step_tabs.getComponentAt(index)
            title = self.auth_step_tabs.getTitleAt(index)
            self.auth_step_tabs.removeTabAt(index)
            self.auth_step_tabs.insertTab(title, None, editor, None, target)
            self.auth_step_tabs.setSelectedIndex(target)

    def refresh_variables_ui(self, profile):
        row = self.p_list_table.getSelectedRow()
        if 0 <= row < len(self.profiles) and self.profiles[row] is profile:
            self.variables_model.setRowCount(0)
            with profile.state_lock:
                values = dict(profile.initial_variables)
                values.update(profile.variables)
            for name in sorted(values):
                self.variables_model.addRow([name, values[name]])

    def run_config_auth_flow(self, e):
        if self.save_profile_config(e):
            row = self.p_list_table.getSelectedRow()
            profile = self.profiles[row]
            self.enqueue_profile_work(profile, self.regenerate_token, (profile,))

    def read_auth_flow_editor(self):
        if self.initial_vars_table.isEditing():
            self.initial_vars_table.getCellEditor().stopCellEditing()
        steps = [self.auth_step_tabs.getComponentAt(i).to_step()
                 for i in range(self.auth_step_tabs.getTabCount())]
        initial = {}
        for i in range(self.initial_vars_model.getRowCount()):
            name = as_text(self.initial_vars_model.getValueAt(i, 0)).strip()
            if not VARIABLE_NAME.match(name) or name in initial:
                raise AuthFlowError("Initial variables need valid, unique names (letters, digits, underscore; no leading digit).")
            initial[name] = as_text(self.initial_vars_model.getValueAt(i, 1))
        return steps, initial

    def run_config_auth_test(self, e, mode):
        row = self.p_list_table.getSelectedRow()
        if not 0 <= row < len(self.profiles):
            return
        profile = self.profiles[row]
        try:
            steps, initial = self.read_auth_flow_editor()
            index = self.auth_step_tabs.getSelectedIndex()
            session = self.prepare_auth_test(profile, steps, initial, mode, index)
        except AuthFlowError as ex:
            self.auth_test_status.setText("Cannot test: " + as_text(ex))
            return
        self.refresh_auth_test_ui(profile)
        self.auth_test_table.setRowSelectionInterval(0 if mode != "step" else index,
                                                    0 if mode != "step" else index)
        if not self.enqueue_profile_work(profile, self.execute_auth_test, (profile, session, mode, index)):
            session.busy = False
            session.status = "Queue full; try again."
            self.refresh_auth_test_ui(profile)

    def reset_auth_test(self, e):
        row = self.p_list_table.getSelectedRow()
        if 0 <= row < len(self.profiles):
            profile = self.profiles[row]
            profile.auth_test = None
            self.refresh_auth_test_ui(profile)

    def refresh_auth_test_ui(self, profile):
        row = self.p_list_table.getSelectedRow()
        if not 0 <= row < len(self.profiles) or self.profiles[row] is not profile:
            return
        session = profile.auth_test
        selected = self.auth_test_table.getSelectedRow()
        self._updating_auth_test_ui = True
        try:
            self.auth_test_model.setRowCount(0)
            if session:
                for result in session.results:
                    names = ", ".join(c["variable"] for c in result.captures if c["status"] == "Captured")
                    self.auth_test_model.addRow(["%d. %s" % (result.index + 1, result.name),
                        result.status, result.http_status if result.http_status is not None else "-",
                        result.elapsed_ms if result.elapsed_ms is not None else "-", names])
                self.auth_test_status.setText(session.status + " (results use the last tested editor values)")
                if session.results:
                    selected = max(0, min(selected, len(session.results) - 1))
                    self.auth_test_table.setRowSelectionInterval(selected, selected)
            else:
                self.auth_test_status.setText("No test run yet.")
            for button in self.auth_test_buttons:
                button.setEnabled(not session or not session.busy)
        finally:
            self._updating_auth_test_ui = False
        self.show_auth_test_result()

    def auth_test_selection_changed(self, e):
        if not e.getValueIsAdjusting() and not self._updating_auth_test_ui:
            self.show_auth_test_result()

    def clear_auth_test_ui(self):
        self._updating_auth_test_ui = True
        try:
            self.auth_test_model.setRowCount(0)
        finally:
            self._updating_auth_test_ui = False
        self.auth_test_status.setText("Select a profile to test its auth flow.")
        for button in self.auth_test_buttons:
            button.setEnabled(False)
        self.show_auth_test_result()

    def show_auth_test_result(self):
        self.auth_capture_model.setRowCount(0)
        self.auth_capture_value.setText("")
        self.auth_test_error.setText("")
        self.auth_test_http_panel.removeAll()
        self.auth_test_editors = []
        profile_row = self.p_list_table.getSelectedRow()
        index = self.auth_test_table.getSelectedRow()
        session = self.profiles[profile_row].auth_test if 0 <= profile_row < len(self.profiles) else None
        if session and 0 <= index < len(session.results):
            result = session.results[index]
            self.auth_test_error.setText("Step %d: %s%s" % (index + 1, result.status,
                " - " + result.error if result.error else ""))
            for capture in result.captures:
                self.auth_capture_model.addRow([capture["variable"], capture["value"], capture["status"], capture["error"]])
            for name in sorted(result.inputs):
                self.auth_capture_model.addRow([name, result.inputs[name], "Input", "Used in this request"])
            if self.auth_capture_model.getRowCount():
                self.auth_capture_table.setRowSelectionInterval(0, 0)
            if result.request is not None:
                panel, editors = self.create_message_view(result)
                self.auth_test_http_panel.add(panel, BorderLayout.CENTER)
                self.auth_test_editors = editors
            else:
                self.auth_test_http_panel.add(JLabel("No request sent for this step."), BorderLayout.NORTH)
        self.auth_test_http_panel.revalidate()
        self.auth_test_http_panel.repaint()

    def auth_capture_selection_changed(self, e):
        if not e.getValueIsAdjusting():
            row = self.auth_capture_table.getSelectedRow()
            self.auth_capture_value.setText(as_text(self.auth_capture_model.getValueAt(row, 1)) if row != -1 else "")
            self.auth_capture_value.setCaretPosition(0)

    def profile_selection_changed(self, e):
        if not e.getValueIsAdjusting():
            row = self.p_list_table.getSelectedRow()
            if 0 <= row < len(self.profiles):
                p = self.profiles[row]
                self.p_name_field.setText(p.name)
                self.p_detail_field.setText(p.detail)
                self.p_note_area.setText(p.note)
                self.ator_enabled_cb.setSelected(p.ator_enabled)
                self.auth_step_tabs.removeAll()
                for step in p.get_auth_steps():
                    self.auth_step_tabs.addTab(step.get("name", "Auth Step"), AuthStepEditor(step))
                self.initial_vars_model.setRowCount(0)
                for name in sorted(p.initial_variables):
                    self.initial_vars_model.addRow([name, p.initial_variables[name]])
                self.refresh_variables_ui(p)
                self.refresh_auth_test_ui(p)
                self.trigger_field.setText(p.trigger_condition)
                
                # Load Tables
                self.h_table_model.setRowCount(0)
                for h in p.headers_list:
                    self.h_table_model.addRow([h[0], h[1]])
                
                self.mr_table_model.setRowCount(0)
                for mr in p.match_replace_list:
                    self.mr_table_model.addRow([mr[0], mr[1]])
                
                self.rm_table_model.setRowCount(0)
                for rm in p.headers_to_remove:
                    self.rm_table_model.addRow([rm])
            else:
                self.clear_auth_test_ui()

    def save_profile_config(self, e):
        # Stop cell editing to ensure the last value is captured
        for t in [self.h_table, self.mr_table, self.rm_table, self.p_list_table, self.initial_vars_table]:
            if t and t.isEditing(): t.getCellEditor().stopCellEditing()
            
        row = self.p_list_table.getSelectedRow()
        if row != -1:
            p = self.profiles[row]
            try:
                steps, initial = self.read_auth_flow_editor()
                new_name = as_text(self.p_name_field.getText()).strip()
                if not new_name or new_name == "Base" or any(other is not p and other.name == new_name for other in self.profiles):
                    raise AuthFlowError("Choose a unique, non-empty profile name other than 'Base'.")
                available = validate_flow(steps, initial) if steps or self.ator_enabled_cb.isSelected() else set(initial)
                for table in [self.h_table_model, self.mr_table_model]:
                    for i in range(table.getRowCount()):
                        for col in range(2):
                            for name in template_variables(table.getValueAt(i, col)):
                                if name not in available:
                                    raise AuthFlowError("Variable '%s' is not defined by this profile's auth flow or initial values." % name)
            except AuthFlowError as ex:
                self.add_log(p.name, "[CONFIG] " + as_text(ex))
                JOptionPane.showMessageDialog(self.main_panel, as_text(ex), "Auth flow configuration", JOptionPane.ERROR_MESSAGE)
                return False
            with p.state_lock:
                if steps != p.get_auth_steps() or initial != p.initial_variables:
                    p.variables = {}
                    p.init_token = "None"
                    p.last_token = "None"
                if p.auth_test and (p.auth_test.steps != steps or p.auth_test.initial_variables != initial):
                    p.auth_test = None
                p.config_revision += 1
                old_name = p.name
                p.name = new_name
                p.detail = self.p_detail_field.getText()
                p.note = self.p_note_area.getText()
                p.ator_enabled = self.ator_enabled_cb.isSelected()
                p.auth_steps = steps
                p.initial_variables = initial
                p.auth_request = ""
                p.token_pre = ""
                p.token_post = ""
                p.trigger_condition = self.trigger_field.getText()
            
                # Save Headers
                p.headers_list = []
                for i in range(self.h_table_model.getRowCount()):
                    k = as_text(self.h_table_model.getValueAt(i, 0))
                    v = as_text(self.h_table_model.getValueAt(i, 1))
                    p.headers_list.append([k, v])
            
                # Save Match and Replace
                p.match_replace_list = []
                for i in range(self.mr_table_model.getRowCount()):
                    m = as_text(self.mr_table_model.getValueAt(i, 0))
                    r = as_text(self.mr_table_model.getValueAt(i, 1))
                    p.match_replace_list.append([m, r])
            
                # Save Headers to Remove
                p.headers_to_remove = []
                for i in range(self.rm_table_model.getRowCount()):
                    key = as_text(self.rm_table_model.getValueAt(i, 0))
                    if key: p.headers_to_remove.append(key)
            
            self.p_list_model.setValueAt(p.name, row, 0)
            self.ator_mgmt_model.setValueAt(p.name, row, 0)
            if old_name != p.name:
                self.result_column_names[p.id] = p.name
                self.refresh_result_column_labels()
            for index, step in enumerate(steps):
                self.auth_step_tabs.setTitleAt(index, step["name"] or "Step %d" % (index + 1))
            self.refresh_variables_ui(p)
            self.refresh_auth_test_ui(p)
            self.update_ator_status_ui(p, "Saved")
            self.save_config_action(None) # Auto-persist
            self.add_log("System", "Configuration saved and persisted for " + p.name)
            return True
        return False

    # --- Persistence ---

    def save_config_action(self, e):
        temporary = None
        try:
            with self.config_lock:
                data = [p.to_dict() for p in self.profiles]
                path = os.path.abspath(self.config_file)
                descriptor, temporary = tempfile.mkstemp(prefix=".authflow-", suffix=".json", dir=os.path.dirname(path))
                with os.fdopen(descriptor, "w") as f:
                    json.dump(data, f, indent=4)
                    f.flush()
                    os.fsync(f.fileno())
                os.rename(temporary, path)
                temporary = None
        except Exception as ex:
            self.add_log("System", "Save failed: " + str(ex))
        finally:
            if temporary is not None and os.path.exists(temporary):
                os.remove(temporary)

    def load_config_action(self, e):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            fpath = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(fpath, "r") as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    raise AuthFlowError("Profile configuration must be a JSON list.")
                profiles = [Profile.from_dict(d) for d in data]
                names = [p.name for p in profiles]
                ids = [p.id for p in profiles]
                if any(not isinstance(name, (str, text_type)) or not name or name == "Base" for name in names) or len(set(names)) != len(names) or len(set(ids)) != len(ids):
                    raise AuthFlowError("Profile names and IDs must be unique; 'Base' is reserved.")
                with self.config_lock:
                    self.profiles = profiles
                    self.config_file = fpath
                self.refresh_ui_full()
                self.add_log("System", "Config loaded from " + fpath)
            except Exception as ex: self.add_log("System", "Load failed: " + str(ex))

    def refresh_ui_full(self):
        self.p_list_model.setRowCount(0)
        self.ator_mgmt_model.setRowCount(0)
        for p in self.profiles:
            self.p_list_model.addRow([p.name, p.listener_enabled])
            self.ator_mgmt_model.addRow([p.name, "Idle", p.init_token, p.last_token])
        self.ensure_result_columns([(p.id, p.name) for p in self.profiles])
        self.auth_step_tabs.removeAll()
        self.initial_vars_model.setRowCount(0)
        self.variables_model.setRowCount(0)
        if self.profiles:
            self.p_list_table.setRowSelectionInterval(0, 0)

    # --- ATOR Sequential Engine ---

    def run_manual_ator(self, e):
        row = self.ator_mgmt_table.getSelectedRow()
        if row != -1:
            p = self.profiles[row]
            self.enqueue_profile_work(p, self.regenerate_token, (p,))

    def run_all_ator_sequential(self, e):
        for profile in list(self.profiles):
            if profile.ator_enabled:
                self.enqueue_profile_work(profile, self.regenerate_token, (profile,))

    def build_auth_request(self, step, variables):
        raw = render_template(step.get("request", ""), variables).lstrip("\r\n")
        header_text, body_text = response_parts(raw)
        headers = header_text.replace("\r\n", "\n").split("\n")
        if not headers or len(headers[0].split()) != 3 or not headers[0].split()[2].startswith("HTTP/"):
            raise AuthFlowError("Invalid HTTP request line.")
        host = None
        for line in headers[1:]:
            if ":" not in line:
                raise AuthFlowError("Invalid request header; separate the body with a blank line.")
            key, value = line.split(":", 1)
            if key.strip().lower() == "host":
                host = value.strip()
        if not host:
            raise AuthFlowError("Host header is required.")
        authority = re.match(r"^\[([^\]]+)\](?::(\d+))?$", host) if host.startswith("[") else re.match(r"^([^:\s/]+)(?::(\d+))?$", host)
        if not authority:
            raise AuthFlowError("Invalid Host header; use host[:port] or [IPv6]:port.")
        use_https = step.get("https", True)
        port = int(authority.group(2)) if authority.group(2) else (443 if use_https else 80)
        if not 1 <= port <= 65535:
            raise AuthFlowError("Host port must be between 1 and 65535.")
        headers = [h for h in headers if h.split(":", 1)[0].strip().lower() != "x-authflow-analyzer"]
        headers.append("X-AuthFlow-Analyzer: Internal-Regen")
        # Normalize only headers. Body whitespace and line endings are significant.
        message = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(body_text))
        service = self._helpers.buildHttpService(authority.group(1), port, use_https)
        return service, message

    def execute_auth_step(self, step, variables, result):
        started = time.time()
        result.status = "Running"
        try:
            result.inputs = dict((name, variables[name]) for name in template_variables(step.get("request", ""))
                                 if name in variables)
            validate_flow([step], variables, result.index)
            result.service, result.request = self.build_auth_request(step, variables)
            response = self._callbacks.makeHttpRequest(result.service, result.request)
            if not response or not response.getResponse():
                raise AuthFlowError("No response from auth server.")
            result.response = response.getResponse()
            result.http_status = self._helpers.analyzeResponse(result.response).getStatusCode()
            if not status_matches(result.http_status, step.get("expected_status", "")):
                raise AuthFlowError("Unexpected HTTP status %s." % result.http_status)
            response_text = self._helpers.bytesToString(result.response)
            extracted = {}
            errors = []
            for extractor, capture in zip(step.get("extractors", []), result.captures):
                try:
                    value = extract_value(extractor, response_text)
                    capture["value"] = value
                    capture["status"] = "Captured"
                    extracted[extractor["variable"]] = value
                except AuthFlowError as ex:
                    capture["status"] = "Failed"
                    capture["error"] = as_text(ex)
                    errors.append("Variable '%s': %s" % (extractor["variable"], as_text(ex)))
            if errors:
                raise AuthFlowError("; ".join(errors))
            result.variables = extracted
            result.status = "Success"
        except AuthFlowError as ex:
            result.status = "Failed"
            result.error = as_text(ex)
        except Exception:
            result.status = "Failed"
            result.error = "Could not execute auth request. Check the request and network connection."
        finally:
            result.elapsed_ms = max(0, int((time.time() - started) * 1000))
        return result

    def prepare_auth_test(self, profile, steps, initial, mode, index):
        if profile.auth_test and profile.auth_test.busy:
            raise AuthFlowError("A test is already running for this profile.")
        if mode not in ("step", "through", "full"):
            raise AuthFlowError("Unknown test mode.")
        if not steps or (mode != "full" and not 0 <= index < len(steps)):
            raise AuthFlowError("Add and select an auth step first.")
        session = AuthTestSession(steps, initial, profile.auth_test)
        session.reset_from(index if mode == "step" else 0)
        session.busy = True
        session.status = "Waiting to test..."
        profile.auth_test = session
        return session

    def execute_auth_test(self, profile, session, mode, index):
        try:
            with profile.auth_lock:
                indices = [index] if mode == "step" else range(len(session.steps) if mode == "full" else index + 1)
                for step_index in indices:
                    if profile.auth_test is not session or profile not in self.profiles or getattr(self, "unloaded", False):
                        return
                    result = session.results[step_index]
                    session.status = "Testing step %d/%d..." % (step_index + 1, len(session.steps))
                    try:
                        variables = session.inputs_for(step_index)
                    except AuthFlowError as ex:
                        result.status = "Blocked"
                        result.error = as_text(ex)
                        session.status = "Step %d blocked: run the preceding steps first." % (step_index + 1)
                        return
                    result.status = "Running"
                    SwingUtilities.invokeLater(lambda: self.refresh_auth_test_ui(profile))
                    # Publish a completed result object; the UI never reads captures
                    # while the network/extraction worker is mutating them.
                    result = self.execute_auth_step(session.steps[step_index], variables,
                                                    AuthStepResult(step_index, session.steps[step_index]))
                    session.results[step_index] = result
                    if profile.auth_test is not session:
                        return
                    SwingUtilities.invokeLater(lambda: self.refresh_auth_test_ui(profile))
                    if result.status != "Success":
                        session.status = "Step %d failed; later steps were not run." % (step_index + 1)
                        return
                session.status = ("Full flow passed (%d steps)." % len(session.steps) if mode == "full"
                                  else "Step %d passed. Captures are available to later test steps." % (index + 1))
        finally:
            session.busy = False
            SwingUtilities.invokeLater(lambda: self.refresh_auth_test_ui(profile))

    def profile_run_is_current(self, profile):
        source = getattr(profile, "source_profile", profile)
        with self.config_lock:
            present = source in self.profiles
        with source.state_lock:
            return (present and not getattr(self, "unloaded", False)
                    and source.config_revision == profile.config_revision)

    def sync_profile_credentials(self, profile):
        source = getattr(profile, "source_profile", profile)
        with source.state_lock:
            profile.variables = dict(source.variables)
            profile.init_token = source.init_token
            profile.last_token = source.last_token
            profile.auth_generation = source.auth_generation
            if profile.legacy_authorization:
                profile.headers_list = copy.deepcopy(source.headers_list)

    def automatic_ator_enabled(self, profile):
        source = getattr(profile, "source_profile", profile)
        with source.state_lock:
            return source.ator_enabled

    def regenerate_token(self, profile, expected_generation=None):
        source = getattr(profile, "source_profile", profile)
        with source.auth_lock:
            if profile is source:
                profile = source.snapshot()
            step_number = 0
            try:
                if not self.profile_run_is_current(profile):
                    raise AuthFlowError("Profile was changed or removed; run the flow again.")
                self.sync_profile_credentials(profile)
                if expected_generation is not None and profile.auth_generation != expected_generation:
                    return profile.last_token if profile.last_token != "None" else True
                source.is_regenerating = True
                steps = profile.get_auth_steps()
                variables = dict(profile.initial_variables)
                validate_flow(steps, variables)
                last_value = None
                for index, step in enumerate(steps):
                    step_number = index + 1
                    if not self.profile_run_is_current(profile):
                        raise AuthFlowError("Configuration changed during the run; run the flow again.")
                    label = "Step %d/%d" % (step_number, len(steps))
                    self.update_ator_status_ui(source, label)
                    self.add_log(profile.name, "[AUTH] " + label + " - " + step.get("name", ""))
                    result = self.execute_auth_step(step, variables, AuthStepResult(index, step))
                    if result.status != "Success":
                        raise AuthFlowError(result.error)
                    for capture in result.captures:
                        last_value = capture["value"]
                        self.add_log(profile.name, "[EXTRACT] " + label + " -> " + capture["variable"])
                    variables.update(result.variables)
                # Publish credentials atomically, only to the original profile revision.
                with self.config_lock:
                    with source.state_lock:
                        if not self.profile_run_is_current(profile):
                            raise AuthFlowError("Configuration changed during the run; run the flow again.")
                        source.variables = dict(variables)
                        if last_value is not None:
                            if source.init_token == "None":
                                source.init_token = last_value
                            source.last_token = last_value
                        if source.legacy_authorization and "AuthorToken" in variables:
                            for header in source.headers_list:
                                if header[0].lower() == "authorization" and not template_variables(header[1]):
                                    prefix = "Bearer " if header[1].lower().startswith("bearer ") else ""
                                    header[1] = prefix + variables["AuthorToken"]
                        source.auth_generation += 1
                        self.sync_profile_credentials(profile)
                self.save_config_action(None)
                self.update_ator_status_ui(source, "Success")
                SwingUtilities.invokeLater(lambda: self.refresh_variables_ui(source))
                self.add_log(profile.name, "[SUCCESS] Auth flow completed (%d steps)." % len(steps))
                return last_value if last_value is not None else True
            except AuthFlowError as ex:
                self.add_log(profile.name, "[ERROR] Step %d: %s" % (step_number, as_text(ex)))
                self.update_ator_status_ui(source, "Failed at step %d" % step_number if step_number else "Invalid Config")
                return None
            except Exception:
                self.add_log(profile.name, "[ERROR] Step %d: could not execute auth request." % step_number)
                self.update_ator_status_ui(source, "Error at step %d" % step_number)
                return None
            finally:
                source.is_regenerating = False

    def update_ator_status_ui(self, p, status, token=None):
        def upd():
            if p not in self.profiles:
                return
            index = self.profiles.index(p)
            self.ator_mgmt_model.setValueAt(status, index, 1)
            with p.state_lock:
                initial, last = p.init_token, p.last_token
            self.ator_mgmt_model.setValueAt(initial[:20] + "..." if len(initial) > 20 else initial, index, 2)
            self.ator_mgmt_model.setValueAt(last[:20] + "..." if len(last) > 20 else last, index, 3)
        SwingUtilities.invokeLater(upd)

    # --- HTTP Interception & Mirroring ---

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return
        profiles = self.selected_listener_profiles(toolFlag)
        if not profiles:
            return
        epoch = getattr(self, "results_epoch", 0)
        req_info = self._helpers.analyzeRequest(messageInfo)
        for header in req_info.getHeaders():
            if header.split(":", 1)[0].strip().lower() == "x-authflow-analyzer":
                return
        if not self.listener_slots.acquire(False):
            with self.config_lock:
                self.listener_dropped += 1
                dropped = self.listener_dropped
            if dropped == 1 or dropped % 100 == 0:
                self.add_log("System", "Listener UI queue full: %d requests skipped. Reduce incoming traffic." % dropped)
            return
        try:
            self.enqueue_listener_result(profiles, epoch, req_info, messageInfo)
        except Exception:
            self.listener_slots.release()
            self.add_log("System", "Could not capture listener request.")

    def enqueue_listener_result(self, profiles, epoch, req_info, messageInfo):
        profiles = [profile.snapshot() for profile in profiles]
        group = RequestGroup(0, req_info.getMethod(), as_text(req_info.getUrl()))
        group.responses["Base"] = self._callbacks.saveBuffersToTempFiles(messageInfo)
        base_response = messageInfo.getResponse()
        group.statuses["Base"] = self._helpers.analyzeResponse(base_response).getStatusCode() if base_response else "No Response"
        for profile in profiles:
            group.statuses[profile.id] = "Pending"
            group.profile_names[profile.id] = profile.name
        def add_row():
            self.listener_slots.release()
            if epoch != getattr(self, "results_epoch", 0) or getattr(self, "unloaded", False):
                return
            with self.results_lock:
                group.id = len(self.results_data) + 1
                self.results_data.append(group)
                self.ensure_result_columns([(p.id, p.name) for p in profiles])
                self.res_table_model.addRow(self.result_row(group))
            self.mirror_request(group, group.responses["Base"], profiles)
        SwingUtilities.invokeLater(add_row)

    def mirror_request(self, group, messageInfo, profiles):
        orig_req = messageInfo.getRequest()
        orig_svc = messageInfo.getHttpService()
        orig_headers = tuple(self._helpers.analyzeRequest(messageInfo).getHeaders())
        pool = self.get_worker_pool()
        for profile in profiles:
            if not pool.submit(profile.id, self.send_profile_request,
                               (group, profile, orig_headers, orig_req, orig_svc), tag=group):
                self.update_res_status_ui(group, profile.id, "Queue Full")

    def send_profile_request(self, group, profile, orig_headers, orig_req, orig_svc, retry=False):
        source = getattr(profile, "source_profile", profile)
        with source.auth_lock:
            if profile is source:
                profile = source.snapshot()
            with group.lock:
                group.profile_names.setdefault(profile.id, profile.name)
            self._send_profile_request(group, profile, orig_headers, orig_req, orig_svc, retry)

    def _send_profile_request(self, group, profile, orig_headers, orig_req, orig_svc, retry=False):
        try:
            if group.cancelled or getattr(self, "unloaded", False):
                return
            if not self.profile_run_is_current(profile):
                self.update_res_status_ui(group, profile.id, "Config Changed")
                return
            with profile.state_lock:
                self.sync_profile_credentials(profile)
                variables = dict(profile.initial_variables)
                variables.update(profile.variables)
                templates = [value for row in profile.headers_list + profile.match_replace_list for value in row]
                missing = set(name for value in templates for name in template_variables(value) if name not in variables)
                if missing and self.automatic_ator_enabled(profile) and not retry:
                    if self.regenerate_token(profile) is None:
                        self.update_res_status_ui(group, profile.id, "Auth Failed")
                        return
                    variables = dict(profile.variables)
                # Resolve the entire mapping before any network request is sent.
                headers_to_set = [[render_template(k, variables), render_template(v, variables)] for k, v in profile.headers_list]
                replacements = [[render_template(m, variables), render_template(r, variables)] for m, r in profile.match_replace_list]
                generation = profile.auth_generation
            new_headers = list(orig_headers)

            # 1. Remove requested headers
            removed_count = 0
            for rm_key in profile.headers_to_remove:
                target = rm_key.strip().lower()
                if target:
                    start_count = len(new_headers)
                    new_headers = [h for h in new_headers if ":" not in h or h.split(":")[0].strip().lower() != target]
                    if len(new_headers) < start_count:
                        removed_count += (start_count - len(new_headers))
            
            if removed_count > 0:
                self.add_log(profile.name, "Removed %d header(s) based on configuration." % removed_count)

            # 2. Apply replacements from Key-Value table
            for h_row in headers_to_set:
                key, val = h_row[0].strip(), h_row[1].strip()
                if key:
                    new_headers = [h for h in new_headers if ":" not in h or h.split(":")[0].strip().lower() != key.lower()]
                    new_headers.append(key + ": " + val)

            new_headers.append("X-AuthFlow-Analyzer: " + profile.name)

            body = orig_req[self._helpers.analyzeRequest(orig_req).getBodyOffset():]

            # Build initial message to get full string for Match & Replace
            temp_msg = self._helpers.buildHttpMessage(new_headers, body)
            req_str = self._helpers.bytesToString(temp_msg)

            # Apply Match and Replace rules
            for mr in replacements:
                match_str, replace_str = mr[0], mr[1]
                if match_str:
                    req_str = req_str.replace(match_str, replace_str)

            new_msg = self._helpers.stringToBytes(req_str)
            # Rebuild after body substitutions so Content-Length reflects the actual bytes.
            new_info = self._helpers.analyzeRequest(new_msg)
            new_msg = self._helpers.buildHttpMessage(list(new_info.getHeaders()), new_msg[new_info.getBodyOffset():])
            if group.cancelled or getattr(self, "unloaded", False):
                return
            if not self.profile_run_is_current(profile):
                self.update_res_status_ui(group, profile.id, "Config Changed")
                return
            with group.lock:
                group.responses[profile.id] = StoredMessage(orig_svc, new_msg, None)
            self.update_res_status_ui(group, profile.id, "Sending")
            resp = self._callbacks.makeHttpRequest(orig_svc, new_msg)

            if resp and resp.getResponse():
                with group.lock:
                    group.responses[profile.id] = self._callbacks.saveBuffersToTempFiles(resp)
                if not group.cancelled and self.automatic_ator_enabled(profile) and not retry and self.is_trigger_matched(profile, resp):
                    self.update_res_status_ui(group, profile.id, "ATOR...")
                    new_token = self.regenerate_token(profile, generation)
                    if new_token is not None:
                        # Retry original request with new token
                        self.send_profile_request(group, profile, orig_headers, orig_req, orig_svc, True)
                        return
                
                status = self._helpers.analyzeResponse(resp.getResponse()).getStatusCode()
                with group.lock:
                    group.statuses[profile.id] = status
                self.update_res_status_ui(group, profile.id, status)
            else:
                self.update_res_status_ui(group, profile.id, "No Response")
        except AuthFlowError as ex:
            self.add_log(profile.name, "[ERROR] " + as_text(ex))
            self.update_res_status_ui(group, profile.id, "Config Error")
        except Exception:
            self.add_log(profile.name, "[ERROR] Could not send profile request.")
            self.update_res_status_ui(group, profile.id, "Error")

    def is_trigger_matched(self, p, resp_info):
        r = resp_info.getResponse()
        s = str(self._helpers.analyzeResponse(r).getStatusCode())
        b = self._helpers.bytesToString(r)
        triggers = [t.strip() for t in p.trigger_condition.split(";")]
        for t in triggers:
            if t not in s and t not in b: return False
        return True

    def update_res_status_ui(self, group, profile_id, status):
        with group.lock:
            if group.cancelled:
                return
            group.statuses[profile_id] = status
            if getattr(group, "ui_pending", False):
                return
            group.ui_pending = True
        def upd():
            with group.lock:
                group.ui_pending = False
                statuses = dict(group.statuses)
            row_idx = group.id - 1
            if group.cancelled or not 0 <= row_idx < len(self.results_data) or self.results_data[row_idx] is not group:
                return
            for index, key in enumerate(self.result_column_keys):
                self.res_table_model.setValueAt(statuses.get(key, "-"), row_idx, index + 4)
            selected = self.res_table.getSelectedRow()
            if selected != -1 and self.res_table.convertRowIndexToModel(selected) == row_idx:
                self.update_detail_tabs(group)
        SwingUtilities.invokeLater(upd)

    def add_log(self, p, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        def append():
            self.log_table_model.insertRow(0, [timestamp, p, msg])
            if self.log_table_model.getRowCount() > 5000:
                self.log_table_model.setRowCount(5000)
        SwingUtilities.invokeLater(append)

    def ensure_result_columns(self, profiles):
        changed = False
        for profile in profiles:
            key, name = profile if isinstance(profile, (list, tuple)) else (profile, profile)
            if key != "Base" and key not in self.result_column_keys:
                self.result_column_keys.append(key)
                self.result_column_names[key] = name
                self.res_table_model.addColumn(name)
                changed = True
        if changed:
            self.refresh_result_column_labels()

    def refresh_result_column_labels(self):
        labels = [self.result_column_names[key] for key in self.result_column_keys]
        labels = [label + " [" + key[:8] + "]" if labels.count(label) > 1 or label in ("ID", "Method", "URL", "Base Status") else label
                  for key, label in zip(self.result_column_keys, labels)]
        self.res_table_model.setColumnIdentifiers(["ID", "Method", "URL", "Base Status"] + labels)
        self.reapply_all_renderers()

    def result_row(self, group):
        with group.lock:
            keys = ["Base"] + self.result_column_keys
            return [group.id, group.method, group.url] + [group.statuses.get(key, "-") for key in keys]

    def results_snapshot(self):
        with self.results_lock:
            groups = list(self.results_data)
        results = []
        names = set()
        for group in groups:
            with group.lock:
                responses = {}
                for name, message in group.responses.items():
                    service = message.getHttpService()
                    request, response = message.getRequest(), message.getResponse()
                    responses[name] = {
                        "service": {"host": as_text(service.getHost()), "port": int(service.getPort()),
                                    "protocol": as_text(service.getProtocol())},
                        "request_base64": as_text(self._helpers.base64Encode(request)) if request is not None else None,
                        "response_base64": as_text(self._helpers.base64Encode(response)) if response is not None else None}
                statuses = dict(group.statuses)
                names.update(responses)
                names.update(statuses)
                results.append({"id": group.id, "method": group.method, "url": group.url,
                                "profile_names": dict(group.profile_names),
                                "statuses": statuses, "responses": responses})
        return {"format": "authflow-results", "version": 1,
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "profiles": sorted(names - set(["Base"])), "results": results}

    def export_results_file(self):
        snapshot = self.results_snapshot()
        if not os.path.isdir(self.data_dir):
            try:
                os.makedirs(self.data_dir)
            except OSError as ex:
                if ex.errno != errno.EEXIST or not os.path.isdir(self.data_dir):
                    raise
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        suffix = 0
        while True:
            filename = "output%s%s.json" % (stamp, "_%d" % suffix if suffix else "")
            path = os.path.join(self.data_dir, filename)
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                break
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise
                suffix += 1
        try:
            with os.fdopen(descriptor, "w") as output:
                json.dump(snapshot, output, indent=2)
        except Exception:
            os.remove(path)
            raise
        return path

    def read_results_file(self, path):
        with open(path, "r") as source:
            data = json.load(source)
        if not isinstance(data, dict) or data.get("format") != "authflow-results" or data.get("version") != 1:
            raise AuthFlowError("Unsupported Results file. Choose an AuthFlow Results JSON export (version 1).")
        records = data.get("results")
        names = data.get("profiles")
        if not isinstance(records, list) or not isinstance(names, list) or not all(isinstance(n, (str, text_type)) and n and n != "Base" for n in names):
            raise AuthFlowError("Invalid Results list or profile names.")
        groups = []
        for record in records:
            if not isinstance(record, dict) or not all(isinstance(record.get(k), (str, text_type)) for k in ("method", "url")):
                raise AuthFlowError("Invalid Results record.")
            group = RequestGroup(0, record["method"], record["url"])
            statuses, responses = record.get("statuses"), record.get("responses")
            if not isinstance(statuses, dict) or not isinstance(responses, dict):
                raise AuthFlowError("Invalid Results statuses or responses.")
            for name in set(statuses) | set(responses):
                if not isinstance(name, (str, text_type)) or not name:
                    raise AuthFlowError("Invalid Results profile name.")
                if name != "Base" and name not in names:
                    names.append(name)
            for name, status in statuses.items():
                if isinstance(status, bool) or not isinstance(status, (int, str, text_type)):
                    raise AuthFlowError("Invalid Results status.")
            group.statuses = dict(statuses)
            labels = record.get("profile_names", {})
            if not isinstance(labels, dict) or not all(isinstance(v, (str, text_type)) and v for v in labels.values()):
                raise AuthFlowError("Invalid Results profile labels.")
            group.profile_names = labels
            for name, message in responses.items():
                if not isinstance(message, dict) or not isinstance(message.get("service"), dict):
                    raise AuthFlowError("Invalid HTTP message in Results.")
                service = message["service"]
                host, port, protocol = service.get("host"), service.get("port"), service.get("protocol")
                if (not isinstance(host, (str, text_type)) or not host or
                        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535 or
                        protocol not in ("http", "https")):
                    raise AuthFlowError("Invalid HTTP service in Results.")
                buffers = []
                for key in ("request_base64", "response_base64"):
                    if key not in message:
                        raise AuthFlowError("Missing HTTP buffer in Results.")
                    encoded = message[key]
                    if encoded is None:
                        buffers.append(None)
                        continue
                    if not isinstance(encoded, (str, text_type)) or not re.match(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", encoded):
                        raise AuthFlowError("Invalid Base64 HTTP buffer in Results.")
                    decoded = self._helpers.base64Decode(encoded)
                    if self._helpers.base64Encode(decoded) != encoded:
                        raise AuthFlowError("Invalid Base64 HTTP buffer in Results.")
                    buffers.append(decoded)
                http_service = self._helpers.buildHttpService(host, port, protocol == "https")
                group.responses[name] = StoredMessage(http_service, buffers[0], buffers[1])
            groups.append(group)
        return names, groups

    def append_imported_results(self, names, groups):
        with self.results_lock:
            labels = {}
            for group in groups:
                labels.update(group.profile_names)
            self.ensure_result_columns([(key, labels.get(key, key)) for key in names])
            for group in groups:
                group.id = len(self.results_data) + 1
                self.results_data.append(group)
                self.res_table_model.addRow(self.result_row(group))

    def export_results_action(self, e):
        self.results_file_label.setText("Export queued...")
        def export():
            try:
                path = self.export_results_file()
                SwingUtilities.invokeLater(lambda: self.results_file_label.setText("Exported: " + path))
                self.add_log("System", "Results exported to " + path)
            except Exception as ex:
                SwingUtilities.invokeLater(lambda error=ex: self.results_file_error("Export", error))
        self.enqueue_file_work(export)

    def enqueue_file_work(self, function):
        if getattr(self, "unloaded", False):
            return
        if not hasattr(self, "file_pool"):
            self.file_pool = ProfileWorkerPool(1, capacity=8)
        if not self.file_pool.submit("files", function):
            self.results_file_error("File operation", AuthFlowError("File queue full; wait for pending operations to finish."))

    def import_results_action(self, e):
        chooser = JFileChooser(self.data_dir)
        if chooser.showOpenDialog(self.main_panel) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        self.results_file_label.setText("Import queued: " + path)
        def read():
            try:
                names, groups = self.read_results_file(path)
                def display():
                    if getattr(self, "unloaded", False):
                        return
                    self.append_imported_results(names, groups)
                    self.results_file_label.setText("Imported %d results: %s" % (len(groups), path))
                    self.add_log("System", "Imported %d results from %s" % (len(groups), path))
                SwingUtilities.invokeAndWait(display)
            except Exception as ex:
                SwingUtilities.invokeLater(lambda error=ex: self.results_file_error("Import", error))
        self.enqueue_file_work(read)

    def results_file_error(self, operation, error):
        message = operation + " failed: " + as_text(error)
        self.add_log("System", message)
        JOptionPane.showMessageDialog(self.main_panel, message, operation + " Results", JOptionPane.ERROR_MESSAGE)

    def clear_results(self, e):
        with self.results_lock:
            self.results_epoch = getattr(self, "results_epoch", 0) + 1
            for group in self.results_data:
                with group.lock:
                    group.cancelled = True
            if hasattr(self, "worker_pool"):
                self.worker_pool.cancel_pending(lambda tag: isinstance(tag, RequestGroup))
            self.results_data = []
            self.result_column_keys = [p.id for p in self.profiles]
            self.result_column_names = dict((p.id, p.name) for p in self.profiles)
            self.res_table_model.setRowCount(0)
            self.res_table_model.setColumnIdentifiers(["ID", "Method", "URL", "Base Status"] + [p.name for p in self.profiles])
        self.reapply_all_renderers()
        self.detail_tabs.removeAll()
        self.detail_editors = []
        self.detail_group = None
        self.detail_messages = {}
        self.detail_profile_keys = []

    def create_search_listener(self):
        from javax.swing.event import DocumentListener
        class SL(DocumentListener):
            def __init__(self, outer): self.outer = outer
            def insertUpdate(self, e): self.outer.apply_filter()
            def removeUpdate(self, e): self.outer.apply_filter()
            def changedUpdate(self, e): self.outer.apply_filter()
        return SL(self)

    def apply_filter(self):
        from javax.swing import RowFilter
        txt = self.search_field.getText()
        self.row_sorter.setRowFilter(RowFilter.regexFilter("(?i)" + re.escape(txt)) if txt else None)

    def result_selection_changed(self, e):
        if not e.getValueIsAdjusting():
            row = self.res_table.getSelectedRow()
            if row != -1:
                model_row = self.res_table.convertRowIndexToModel(row)
                if model_row < len(self.results_data):
                    self.update_detail_tabs(self.results_data[model_row])

    def create_message_view(self, message):
        controller = ResultMessageController(message)
        request_editor = self._callbacks.createMessageEditor(controller, False)
        response_editor = self._callbacks.createMessageEditor(controller, False)
        request_editor.setMessage(message.getRequest(), True)
        response_editor.setMessage(message.getResponse(), False)
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel("Request"), BorderLayout.NORTH)
        request_panel.add(request_editor.getComponent(), BorderLayout.CENTER)
        response_panel = JPanel(BorderLayout())
        response_panel.add(JLabel("Response"), BorderLayout.NORTH)
        response_panel.add(response_editor.getComponent(), BorderLayout.CENTER)
        request_panel.setMinimumSize(Dimension(100, 100))
        response_panel.setMinimumSize(Dimension(100, 100))
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, request_panel, response_panel)
        split.setResizeWeight(0.5)
        split.setDividerLocation(0.5)
        split.addComponentListener(InitialSplitDivider())
        split.setOneTouchExpandable(True)
        return split, (controller, request_editor, response_editor)

    def update_detail_tabs(self, group):
        with group.lock:
            responses = dict(group.responses)
        previous = getattr(self, "detail_messages", {})
        if (getattr(self, "detail_group", None) is group and set(previous) == set(responses)
                and all(previous[key] is responses[key] for key in responses)):
            return
        self.detail_group, self.detail_messages = group, responses
        selected = self.detail_tabs.getSelectedIndex()
        previous_keys = getattr(self, "detail_profile_keys", [])
        selected_key = previous_keys[selected] if 0 <= selected < len(previous_keys) else None
        self.detail_tabs.removeAll()
        self.detail_editors = []
        self.detail_profile_keys = []
        ordered = [key for key in getattr(self, "result_column_keys", []) if key in responses]
        ordered.extend(sorted(key for key in responses if key != "Base" and key not in ordered))
        for name in ["Base"] + ordered:
            if name in responses:
                resp = responses[name]
                split, editors = self.create_message_view(resp)
                self.detail_tabs.addTab(group.profile_names.get(name, name), split)
                self.detail_editors.append(editors)
                self.detail_profile_keys.append(name)
                if name == selected_key:
                    self.detail_tabs.setSelectedIndex(self.detail_tabs.getTabCount() - 1)

    # IMessageEditorController
    def getHttpService(self): return None
    def getRequest(self): return None
    def getResponse(self): return None
