from burp import IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory
from javax.swing import (JPanel, JTabbedPane, JSplitPane, JScrollPane, JTable, JButton, 
                         JLabel, JTextField, JTextArea, JCheckBox, Box, BoxLayout, 
                         ListSelectionModel, SwingUtilities, BorderFactory, JMenuItem,
                         SwingConstants, JSeparator, JFileChooser)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import BorderLayout, FlowLayout, Dimension, Color, Font
import threading
import traceback
import sys
import json
import re
import os
from datetime import datetime

# --- Data Models ---

class Profile:
    def __init__(self, name):
        self.name = name
        self.headers_list = [] # List of [key, value] pairs
        self.ator_enabled = False
        self.auth_request = ""
        self.token_pre = ""
        self.token_post = ""
        self.trigger_condition = "401"
        self.init_token = "None"
        self.last_token = "None"
        self.is_regenerating = False

    def to_dict(self):
        return {
            "name": self.name,
            "headers_list": self.headers_list,
            "ator_enabled": self.ator_enabled,
            "auth_request": self.auth_request,
            "token_pre": self.token_pre,
            "token_post": self.token_post,
            "trigger_condition": self.trigger_condition,
            "init_token": self.init_token,
            "last_token": self.last_token
        }

    @staticmethod
    def from_dict(d):
        p = Profile(d["name"])
        p.headers_list = d.get("headers_list", [])
        p.ator_enabled = d.get("ator_enabled", False)
        p.auth_request = d.get("auth_request", "")
        p.token_pre = d.get("token_pre", "")
        p.token_post = d.get("token_post", "")
        p.trigger_condition = d.get("trigger_condition", "401")
        p.init_token = d.get("init_token", "None")
        p.last_token = d.get("last_token", "None")
        return p

class RequestGroup:
    def __init__(self, id, method, url):
        self.id = id
        self.method = method
        self.url = url
        self.responses = {} # profile_name -> IHttpRequestResponse

# --- UI Renderers ---

class StatusColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        cell = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column)
        if value:
            status = str(value)
            if status == "ATOR...":
                cell.setForeground(Color.RED)
                cell.setFont(cell.getFont().deriveFont(Font.BOLD))
            elif status.startswith("2"):
                cell.setForeground(Color(0, 150, 0)) # Green
                cell.setFont(cell.getFont().deriveFont(Font.PLAIN))
            elif status.startswith("4"):
                cell.setForeground(Color.RED) # Red
                cell.setFont(cell.getFont().deriveFont(Font.PLAIN))
            else:
                cell.setForeground(Color.BLACK)
                cell.setFont(cell.getFont().deriveFont(Font.PLAIN))
        return cell

# --- Main Extension Class ---

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("AuthFlow-Analyzer PRO")
        
        self.profiles = []
        self.results_data = []
        self.extension_enabled = True
        self.regen_lock = threading.RLock() # Reentrant lock for sequential queue
        self.config_file = "authflow_config.json"
        
        self.init_ui()
        
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)
        
        print("AuthFlow-Analyzer PRO loaded successfully.")

    def init_ui(self):
        self.main_panel = JPanel(BorderLayout())
        
        # --- Top Global Toolbar ---
        top_toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        top_toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY))
        
        self.global_enabled_cb = JCheckBox("Enable Extension", True)
        self.global_enabled_cb.addActionListener(lambda e: self.toggle_global_status(e))
        
        save_btn = JButton("Save Profiles", actionPerformed=self.save_config_action)
        load_btn = JButton("Load Config File", actionPerformed=self.load_config_action)
        
        top_toolbar.add(self.global_enabled_cb)
        top_toolbar.add(Box.createRigidArea(Dimension(20, 0)))
        top_toolbar.add(save_btn)
        top_toolbar.add(load_btn)
        self.main_panel.add(top_toolbar, BorderLayout.NORTH)

        self.tabs = JTabbedPane()
        
        # --- TAB 1: CONFIGURATION ---
        self.config_tab = JPanel(BorderLayout())
        
        # Profile List (Left)
        self.p_list_model = DefaultTableModel(["Profiles"], 0)
        self.p_list_table = JTable(self.p_list_model)
        self.p_list_table.getSelectionModel().addListSelectionListener(self.profile_selection_changed)
        
        left_pnl = JPanel(BorderLayout())
        left_pnl.add(JScrollPane(self.p_list_table), BorderLayout.CENTER)
        p_btns = JPanel(FlowLayout(FlowLayout.LEFT))
        p_btns.add(JButton("Add", actionPerformed=self.add_profile))
        p_btns.add(JButton("Remove", actionPerformed=self.remove_profile))
        left_pnl.add(p_btns, BorderLayout.SOUTH)
        left_pnl.setPreferredSize(Dimension(150, 600))

        # Profile Editor (Right)
        self.editor_pnl = JPanel()
        self.editor_pnl.setLayout(BoxLayout(self.editor_pnl, BoxLayout.Y_AXIS))
        self.editor_pnl.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 10))
        
        self.p_name_field = JTextField(20)
        
        # Headers Table
        self.h_table_model = DefaultTableModel(["Header Key", "Header Value"], 0)
        self.h_table = JTable(self.h_table_model)
        h_scroll = JScrollPane(self.h_table)
        h_scroll.setPreferredSize(Dimension(450, 150))
        
        h_btns = JPanel(FlowLayout(FlowLayout.LEFT))
        h_btns.add(JButton("Add Header Row", actionPerformed=self.add_header_row))
        h_btns.add(JButton("Remove Selected", actionPerformed=self.remove_header_row))
        
        # ATOR Inputs
        self.ator_enabled_cb = JCheckBox("Enable ATOR Regeneration")
        self.auth_req_area = JTextArea(10, 50)
        self.token_pre_field = JTextField(40)
        self.token_post_field = JTextField(40)
        self.trigger_field = JTextField(20)
        
        self.add_labeled_comp(self.editor_pnl, "Profile Name:", self.p_name_field)
        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        self.editor_pnl.add(JLabel("Headers to Replace (Key-Value):"))
        self.editor_pnl.add(h_scroll)
        self.editor_pnl.add(h_btns)
        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        self.editor_pnl.add(JSeparator())
        self.editor_pnl.add(Box.createRigidArea(Dimension(0, 10)))
        self.editor_pnl.add(self.ator_enabled_cb)
        self.add_labeled_comp(self.editor_pnl, "Auth Request (Raw):", JScrollPane(self.auth_req_area))
        self.add_labeled_comp(self.editor_pnl, "Token Start (Pre):", self.token_pre_field)
        self.add_labeled_comp(self.editor_pnl, "Token End (Post):", self.token_post_field)
        self.add_labeled_comp(self.editor_pnl, "Trigger Condition:", self.trigger_field)
        
        save_p_btn = JButton("Save Profile Changes", actionPerformed=self.save_profile_config)
        save_p_btn.setBackground(Color(220, 255, 220))
        self.editor_pnl.add(save_p_btn)
        
        self.config_tab.add(JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left_pnl, JScrollPane(self.editor_pnl)), BorderLayout.CENTER)

        # --- TAB 2: ATOR MANAGEMENT ---
        self.ator_mgmt_tab = JPanel(BorderLayout())
        self.ator_mgmt_model = DefaultTableModel(["Profile", "Status", "Init Token", "Last Token"], 0)
        self.ator_mgmt_table = JTable(self.ator_mgmt_model)
        
        ator_ctrl_pnl = JPanel(FlowLayout(FlowLayout.LEFT))
        ator_ctrl_pnl.add(JButton("Run ATOR Selected", actionPerformed=self.run_manual_ator))
        ator_ctrl_pnl.add(JButton("Run ATOR ALL (Sequential)", actionPerformed=self.run_all_ator_sequential))
        
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
        self.results_tab.add(search_bar, BorderLayout.NORTH)

        self.res_table_model = DefaultTableModel(["ID", "Method", "URL", "Base Status"], 0)
        self.res_table = JTable(self.res_table_model)
        self.res_table.setAutoCreateRowSorter(True)
        from javax.swing.table import TableRowSorter
        self.row_sorter = TableRowSorter(self.res_table_model)
        self.res_table.setRowSorter(self.row_sorter)
        self.res_table.getSelectionModel().addListSelectionListener(self.result_selection_changed)
        self.res_table.getColumnModel().getColumn(3).setCellRenderer(StatusColorRenderer())
        
        self.detail_tabs = JTabbedPane()
        res_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.res_table), self.detail_tabs)
        res_split.setDividerLocation(300)
        
        self.results_tab.add(res_split, BorderLayout.CENTER)
        self.results_tab.add(JButton("Clear All Results", actionPerformed=self.clear_results), BorderLayout.SOUTH)

        # --- TAB 4: LOGS ---
        self.logs_tab = JPanel(BorderLayout())
        self.log_table_model = DefaultTableModel(["Timestamp", "Profile", "Message"], 0)
        self.log_table = JTable(self.log_table_model)
        self.logs_tab.add(JScrollPane(self.log_table), BorderLayout.CENTER)
        self.logs_tab.add(JButton("Clear Logs", actionPerformed=lambda e: self.log_table_model.setRowCount(0)), BorderLayout.SOUTH)

        # Add All Tabs
        self.tabs.addTab("Config", self.config_tab)
        self.tabs.addTab("ATOR Management", self.ator_mgmt_tab)
        self.tabs.addTab("Results", self.results_tab)
        self.tabs.addTab("Logs", self.logs_tab)
        self.main_panel.add(self.tabs, BorderLayout.CENTER)

    def add_labeled_comp(self, pnl, label_text, comp):
        container = JPanel(FlowLayout(FlowLayout.LEFT))
        label = JLabel(label_text)
        label.setPreferredSize(Dimension(150, 25))
        container.add(label)
        container.add(comp)
        pnl.add(container)

    def getTabCaption(self): return "AuthFlow"
    def getUiComponent(self): return self.main_panel

    # --- Profile Management Logic ---

    def add_profile(self, e):
        name = "Profile " + str(len(self.profiles) + 1)
        p = Profile(name)
        self.profiles.append(p)
        self.p_list_model.addRow([name])
        self.ator_mgmt_model.addRow([name, "Idle", "None", "None"])
        self.res_table_model.addColumn(name)
        idx = self.res_table_model.getColumnCount() - 1
        self.res_table.getColumnModel().getColumn(idx).setCellRenderer(StatusColorRenderer())

    def remove_profile(self, e):
        row = self.p_list_table.getSelectedRow()
        if row != -1:
            self.profiles.pop(row)
            self.p_list_model.removeRow(row)
            self.ator_mgmt_model.removeRow(row)

    def add_header_row(self, e):
        self.h_table_model.addRow(["Authorization", "Bearer null"])

    def remove_header_row(self, e):
        row = self.h_table.getSelectedRow()
        if row != -1: self.h_table_model.removeRow(row)

    def profile_selection_changed(self, e):
        if not e.getValueIsAdjusting():
            row = self.p_list_table.getSelectedRow()
            if row != -1:
                p = self.profiles[row]
                self.p_name_field.setText(p.name)
                self.ator_enabled_cb.setSelected(p.ator_enabled)
                self.auth_req_area.setText(p.auth_request)
                self.token_pre_field.setText(p.token_pre)
                self.token_post_field.setText(p.token_post)
                self.trigger_field.setText(p.trigger_condition)
                
                # Load Headers Table
                self.h_table_model.setRowCount(0)
                for h in p.headers_list:
                    self.h_table_model.addRow([h[0], h[1]])

    def save_profile_config(self, e):
        row = self.p_list_table.getSelectedRow()
        if row != -1:
            p = self.profiles[row]
            p.name = self.p_name_field.getText()
            p.ator_enabled = self.ator_enabled_cb.isSelected()
            p.auth_request = self.auth_req_area.getText()
            p.token_pre = self.token_pre_field.getText()
            p.token_post = self.token_post_field.getText()
            p.trigger_condition = self.trigger_field.getText()
            
            # Save Headers from Table
            p.headers_list = []
            for i in range(self.h_table_model.getRowCount()):
                k = str(self.h_table_model.getValueAt(i, 0))
                v = str(self.h_table_model.getValueAt(i, 1))
                p.headers_list.append([k, v])
            
            self.p_list_model.setValueAt(p.name, row, 0)
            self.ator_mgmt_model.setValueAt(p.name, row, 0)
            self.save_config_action(None) # Auto-persist
            self.add_log("System", "Configuration saved and persisted for " + p.name)

    # --- Persistence ---

    def save_config_action(self, e):
        data = [p.to_dict() for p in self.profiles]
        try:
            with open(self.config_file, "w") as f:
                json.dump(data, f, indent=4)
        except Exception as ex: self.add_log("System", "Save failed: " + str(ex))

    def load_config_action(self, e):
        chooser = JFileChooser()
        if chooser.showOpenDialog(self.main_panel) == JFileChooser.APPROVE_OPTION:
            fpath = chooser.getSelectedFile().getAbsolutePath()
            try:
                with open(fpath, "r") as f:
                    data = json.load(f)
                self.profiles = [Profile.from_dict(d) for d in data]
                self.refresh_ui_full()
                self.add_log("System", "Config loaded from " + fpath)
            except Exception as ex: self.add_log("System", "Load failed: " + str(ex))

    def refresh_ui_full(self):
        self.p_list_model.setRowCount(0)
        self.ator_mgmt_model.setRowCount(0)
        self.res_table_model.setColumnCount(4) # ID, Method, URL, Base
        for p in self.profiles:
            self.p_list_model.addRow([p.name])
            self.ator_mgmt_model.addRow([p.name, "Idle", p.init_token, p.last_token])
            self.res_table_model.addColumn(p.name)
            idx = self.res_table_model.getColumnCount() - 1
            self.res_table.getColumnModel().getColumn(idx).setCellRenderer(StatusColorRenderer())

    # --- ATOR Sequential Engine ---

    def run_manual_ator(self, e):
        row = self.ator_mgmt_table.getSelectedRow()
        if row != -1:
            p = self.profiles[row]
            threading.Thread(target=self.regenerate_token, args=(p,)).start()

    def run_all_ator_sequential(self, e):
        def task():
            self.add_log("System", "Starting sequential ATOR for all enabled profiles...")
            for p in self.profiles:
                if p.ator_enabled:
                    self.regenerate_token(p)
            self.add_log("System", "Sequential ATOR finished.")
        threading.Thread(target=task).start()

    def regenerate_token(self, profile):
        self.add_log(profile.name, "[WAIT] Entering sequential lock...")
        with self.regen_lock:
            try:
                self.update_ator_status_ui(profile, "Processing...")
                self.add_log(profile.name, "[PROCESS] Cleaning and Parsing Request...")
                
                # 1. Clean raw request (removes leading/trailing whitespace from each line)
                raw_input = profile.auth_request.strip()
                if not raw_input:
                    self.add_log(profile.name, "[ERROR] Auth Request is empty.")
                    self.update_ator_status_ui(profile, "Missing Config"); return None
                
                lines = [line.strip() for line in raw_input.splitlines()]
                clean_raw = "\r\n".join(lines)
                
                # 2. Extract Host manually to avoid hangs in getUrl()
                host = None
                for line in lines:
                    if line.lower().startswith("host:"):
                        host = line.split(":", 1)[1].strip()
                        break
                
                if not host:
                    self.add_log(profile.name, "[ERROR] Host header not found in request.")
                    self.update_ator_status_ui(profile, "Bad Request"); return None

                self.add_log(profile.name, "[NET] Sending request to Host: " + host)
                req_bytes = self._helpers.stringToBytes(clean_raw)
                req_info = self._helpers.analyzeRequest(req_bytes)
                
                # Add identification header to prevent loop
                headers = list(req_info.getHeaders())
                headers.append("X-AuthFlow-Analyzer: Internal-Regen")
                body = req_bytes[req_info.getBodyOffset():]
                final_req = self._helpers.buildHttpMessage(headers, body)
                
                # Build service (Assumes HTTPS for most modern apps)
                svc = self._helpers.buildHttpService(host, 443, True)
                auth_resp = self._callbacks.makeHttpRequest(svc, final_req)
                
                if auth_resp and auth_resp.getResponse():
                    r_str = self._helpers.bytesToString(auth_resp.getResponse())
                    self.add_log(profile.name, "[NET] Received " + str(len(r_str)) + " bytes.")
                    
                    pre, post = profile.token_pre, profile.token_post
                    if not pre or not post:
                        self.add_log(profile.name, "[ERROR] Token boundaries (Pre/Post) are empty.")
                        self.update_ator_status_ui(profile, "No Pre/Post"); return None
                        
                    self.add_log(profile.name, "[EXTRACT] Searching for token...")
                    start_idx = r_str.find(pre)
                    if start_idx != -1:
                        start_idx += len(pre)
                        end_idx = r_str.find(post, start_idx)
                        if end_idx != -1:
                            token = r_str[start_idx:end_idx]
                            self.add_log(profile.name, "[SUCCESS] Token extracted.")
                            if profile.init_token == "None": profile.init_token = token
                            profile.last_token = token
                            self.update_ator_status_ui(profile, "Success", token)
                            return token
                        else: self.add_log(profile.name, "[ERROR] Post boundary not found.")
                    else: self.add_log(profile.name, "[ERROR] Pre boundary not found.")
                else:
                    self.add_log(profile.name, "[ERROR] No response from login server.")
                
                self.update_ator_status_ui(profile, "Failed")
                return None
            except Exception as ex:
                self.add_log(profile.name, "[EXCEPTION] " + str(ex))
                self.update_ator_status_ui(profile, "Error")
                return None

    def update_ator_status_ui(self, p, status, token=None):
        for i, prof in enumerate(self.profiles):
            if prof == p:
                def upd():
                    self.ator_mgmt_model.setValueAt(status, i, 1)
                    init_disp = p.init_token[:20] + "..." if len(p.init_token) > 20 else p.init_token
                    last_disp = p.last_token[:20] + "..." if len(p.last_token) > 20 else p.last_token
                    self.ator_mgmt_model.setValueAt(init_disp, i, 2)
                    self.ator_mgmt_model.setValueAt(last_disp, i, 3)
                SwingUtilities.invokeLater(upd); break

    # --- HTTP Interception & Mirroring ---

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.global_enabled_cb.isSelected() or messageIsRequest or toolFlag not in [4, 32, 64]: return
        
        req_info = self._helpers.analyzeRequest(messageInfo)
        for h in req_info.getHeaders():
            if h.startswith("X-AuthFlow-Analyzer:"): return
        
        g_id = len(self.results_data) + 1
        group = RequestGroup(g_id, req_info.getMethod(), str(messageInfo.getUrl()))
        group.responses["Base"] = self._callbacks.saveBuffersToTempFiles(messageInfo)
        self.results_data.append(group)
        
        def add_row():
            row = [g_id, group.method, group.url, str(self._helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode())]
            for _ in range(len(self.profiles)): row.append("-")
            self.res_table_model.addRow(row)
        SwingUtilities.invokeLater(add_row)
        
        if self.profiles: threading.Thread(target=self.mirror_request, args=(group, messageInfo)).start()

    def mirror_request(self, group, messageInfo):
        orig_req = messageInfo.getRequest()
        orig_svc = messageInfo.getHttpService()
        orig_headers = list(self._helpers.analyzeRequest(messageInfo).getHeaders())
        for p in self.profiles:
            self.send_profile_request(group, p, orig_headers, orig_req, orig_svc)

    def send_profile_request(self, group, profile, orig_headers, orig_req, orig_svc, retry=False):
        try:
            new_headers = list(orig_headers)
            # Apply replacements from Key-Value table
            for h_row in profile.headers_list:
                key, val = h_row[0], h_row[1]
                new_headers = [h for h in new_headers if not h.lower().startswith(key.lower() + ":")]
                new_headers.append(key + ": " + val)
            
            new_headers.append("X-AuthFlow-Analyzer: " + profile.name)
            
            body = orig_req[self._helpers.analyzeRequest(orig_req).getBodyOffset():]
            new_msg = self._helpers.buildHttpMessage(new_headers, body)
            resp = self._callbacks.makeHttpRequest(orig_svc, new_msg)
            
            if resp and resp.getResponse():
                if profile.ator_enabled and not retry and self.is_trigger_matched(profile, resp):
                    self.update_res_status_ui(group, profile.name, "ATOR...")
                    new_token = self.regenerate_token(profile)
                    if new_token:
                        # Update headers list with new token for future requests
                        for h_row in profile.headers_list:
                            if h_row[0].lower() == "authorization":
                                prefix = "Bearer " if "bearer" in h_row[1].lower() else ""
                                h_row[1] = prefix + new_token
                        self.save_config_action(None) # Persist new token
                        # Retry original request with new token
                        self.send_profile_request(group, profile, orig_headers, orig_req, orig_svc, True)
                        return
                
                group.responses[profile.name] = self._callbacks.saveBuffersToTempFiles(resp)
                status = str(self._helpers.analyzeResponse(resp.getResponse()).getStatusCode())
                self.update_res_status_ui(group, profile.name, status)
        except: traceback.print_exc()

    def is_trigger_matched(self, p, resp_info):
        r = resp_info.getResponse()
        s = str(self._helpers.analyzeResponse(r).getStatusCode())
        b = self._helpers.bytesToString(r)
        triggers = [t.strip() for t in p.trigger_condition.split(";")]
        for t in triggers:
            if t not in s and t not in b: return False
        return True

    def update_res_status_ui(self, group, p_name, status):
        row_idx = group.id - 1
        for i in range(self.res_table_model.getColumnCount()):
            if self.res_table_model.getColumnName(i) == p_name:
                def upd():
                    self.res_table_model.setValueAt(status, row_idx, i)
                    sel = self.res_table.getSelectedRow()
                    if sel != -1 and self.res_table.convertRowIndexToModel(sel) == row_idx:
                        self.update_detail_tabs(group)
                SwingUtilities.invokeLater(upd); break

    def add_log(self, p, msg):
        time = datetime.now().strftime("%H:%M:%S")
        SwingUtilities.invokeLater(lambda: self.log_table_model.insertRow(0, [time, p, msg]))

    def clear_results(self, e):
        self.res_table_model.setRowCount(0); self.results_data = []; self.detail_tabs.removeAll()

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

    def update_detail_tabs(self, group):
        self.detail_tabs.removeAll()
        for name in ["Base"] + [p.name for p in self.profiles]:
            if name in group.responses:
                resp = group.responses[name]
                pnl = JTabbedPane()
                q = self._callbacks.createMessageEditor(self, False); q.setMessage(resp.getRequest(), True)
                s = self._callbacks.createMessageEditor(self, False); s.setMessage(resp.getResponse(), False)
                pnl.addTab("Request", q.getComponent())
                pnl.addTab("Response", s.getComponent())
                self.detail_tabs.addTab(name, pnl)

    # IMessageEditorController
    def getHttpService(self): return None
    def getRequest(self): return None
    def getResponse(self): return None