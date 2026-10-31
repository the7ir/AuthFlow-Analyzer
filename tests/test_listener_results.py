"""Listener selection, reusable auth requests, and portable Results archives."""
import copy
import json
import os
import shutil
import tempfile
import threading
import unittest

from test_auth_flow import (ON_JYTHON, Engine, Helpers, MessageInfo, Profile,
                            RequestGroup, BurpExtender, StatusColorRenderer, step, response)
import AuthFlowAnalyzer as authflow


class Selection(object):
    def __init__(self, value=0): self.value = value
    def getSelectedRow(self): return self.value
    def getSelectedIndex(self): return self.value
    def setSelectedIndex(self, value): self.value = value
    def setSelected(self, value): self.value = value


class SettingsCallbacks(object):
    def __init__(self): self.settings = {}
    def saveExtensionSetting(self, key, value): self.settings[key] = value
    def loadExtensionSetting(self, key): return self.settings.get(key)


class ListenerTests(unittest.TestCase):
    def setUp(self):
        self.profiles = [Profile("Admin"), Profile("User"), Profile("Guest")]
        self.profiles[1].listener_enabled = False
        self.engine = Engine(self.profiles, [])
        self.engine.extension_enabled = True
        self.engine.load_listener_settings()

    def test_tool_switches_and_profile_selection_are_independent(self):
        engine = self.engine
        for name, flag in authflow.LISTENER_TOOLS:
            self.assertEqual(engine.selected_listener_profiles(flag), self.profiles)
            engine.listener_tools[name] = False
            self.assertEqual(engine.selected_listener_profiles(flag), [])
            engine.listener_tools[name] = True
        self.assertEqual(engine.selected_listener_profiles(1024), [])
        engine.listener_all_profiles = False
        self.assertEqual(engine.selected_listener_profiles(64), [self.profiles[0], self.profiles[2]])
        for profile in self.profiles:
            profile.listener_enabled = False
        self.assertEqual(engine.selected_listener_profiles(4), [])
        engine.listener_all_profiles = True
        self.assertEqual(engine.selected_listener_profiles(32), self.profiles)
        engine.extension_enabled = False
        self.assertEqual(engine.selected_listener_profiles(64), [])

    def test_selection_is_saved_cloned_and_legacy_profiles_default_to_enabled(self):
        profile = self.profiles[1]
        self.assertFalse(Profile.from_dict(profile.to_dict()).listener_enabled)
        self.assertFalse(profile.clone("Copy").listener_enabled)
        self.assertTrue(Profile.from_dict({"name": "Legacy"}).listener_enabled)

    def test_settings_and_templates_persist_across_extension_instances(self):
        engine = self.engine
        engine._callbacks = SettingsCallbacks()
        engine.listener_tools["Intruder"] = False
        engine.listener_all_profiles = False
        engine.request_templates = [{"name": "Login", "step": step("login")}]
        engine.save_listener_settings()
        loaded = BurpExtender()
        loaded._callbacks = engine._callbacks
        loaded.load_listener_settings()
        self.assertFalse(loaded.listener_tools["Intruder"])
        self.assertFalse(loaded.listener_all_profiles)
        self.assertEqual(loaded.request_templates, engine.request_templates)

    def test_bulk_ator_updates_every_profile_and_selected_editor_without_sending(self):
        engine = self.engine
        engine.p_list_table, engine.ator_enabled_cb = Selection(), Selection()
        for enabled in (True, False):
            engine.set_all_ator_enabled(enabled)
            self.assertTrue(all(p.ator_enabled == enabled for p in self.profiles))
            self.assertEqual(engine.ator_enabled_cb.value, enabled)
            self.assertTrue(all(p["ator_enabled"] == enabled for p in engine.saved[-1]))
        self.assertFalse(engine._callbacks.sent)

    def test_template_is_independent_and_preserves_protocol_and_extractors(self):
        engine = self.engine
        engine.refresh_request_templates = lambda: None
        engine.request_template_combo = Selection()
        original = step("login", "username=${username}")
        original["https"] = False
        engine.store_request_template("Login", original)
        original["request"] = "changed"
        self.assertIn("${username}", engine.request_templates[0]["step"]["request"])
        self.assertFalse(engine.request_templates[0]["step"]["https"])
        self.assertRaises(authflow.AuthFlowError, engine.store_request_template, "Login", step("again"))
        self.assertRaises(authflow.AuthFlowError, engine.store_request_template, "Empty", {"request": ""})


class ResultsFileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.engine = Engine([], [])
        self.engine.results_lock = threading.RLock()
        self.engine.data_dir = os.path.join(self.directory, "data")
        self.group = RequestGroup(9, "POST", u"https://example.test/path?q=\u00e9")
        message = MessageInfo(response("\x00\xff\x80binary"), "POST / HTTP/1.1\r\n\r\n\x00\xff",
                              Helpers().buildHttpService("::1", 8443, True))
        self.group.responses = {"Base": message, "Removed profile": message,
                                "No Response": MessageInfo(None, "GET / HTTP/1.1\r\n\r\n", message.service)}
        self.group.statuses = {"Base": 200, "Removed profile": 403, "Failed profile": "Auth Failed", "No Response": "No Response"}
        self.engine.results_data = [self.group]

    def tearDown(self):
        shutil.rmtree(self.directory)

    def test_round_trip_preserves_binary_buffers_services_names_and_errors(self):
        path = self.engine.export_results_file()
        self.assertTrue(os.path.basename(path).startswith("output"))
        self.assertEqual(os.path.dirname(path), self.engine.data_dir)
        names, groups = self.engine.read_results_file(path)
        self.assertIn("Removed profile", names)
        self.assertIn("Failed profile", names)
        self.assertEqual(groups[0].url, self.group.url)
        self.assertEqual(groups[0].statuses, self.group.statuses)
        for name, message in self.group.responses.items():
            restored = groups[0].responses[name]
            self.assertEqual(restored.getRequest(), message.getRequest())
            self.assertEqual(restored.getResponse(), message.getResponse())
            self.assertEqual(restored.getHttpService(), message.getHttpService())
        self.assertFalse(self.engine._callbacks.sent)

    def test_same_timestamp_never_overwrites_an_export(self):
        previous = authflow.datetime
        moment = previous.now()
        class FixedClock(object):
            @staticmethod
            def now(): return moment
            @staticmethod
            def utcnow(): return moment
        try:
            authflow.datetime = FixedClock
            first = self.engine.export_results_file()
            with open(first) as source:
                first_content = source.read()
            self.group.statuses["Base"] = 201
            second = self.engine.export_results_file()
            self.assertNotEqual(first, second)
            with open(first) as source:
                self.assertEqual(source.read(), first_content)
            self.assertEqual(self.engine.read_results_file(second)[1][0].statuses["Base"], 201)
        finally:
            authflow.datetime = previous

    def test_invalid_files_do_not_change_existing_results_or_send_requests(self):
        original = self.engine.results_snapshot()
        invalid = [[], {"format": "authflow-results", "version": 2}]
        for key, value in [("port", 0), ("protocol", "file"), ("host", "")]:
            data = copy.deepcopy(original)
            data["results"][0]["responses"]["Base"]["service"][key] = value
            invalid.append(data)
        for value in ("not-base64!", "YQ=", [], 42):
            data = copy.deepcopy(original)
            data["results"][0]["responses"]["Base"]["request_base64"] = value
            invalid.append(data)
        data = copy.deepcopy(original)
        data["results"].append({"method": "GET", "url": "/", "responses": [], "statuses": {}})
        invalid.append(data)
        path = os.path.join(self.directory, "invalid.json")
        for data in invalid:
            with open(path, "w") as output:
                json.dump(data, output)
            self.assertRaises(authflow.AuthFlowError, self.engine.read_results_file, path)
            self.assertEqual(self.engine.results_data, [self.group])
        self.assertFalse(self.engine._callbacks.sent)

    def test_empty_results_export_is_readable(self):
        self.engine.results_data = []
        self.assertEqual(self.engine.read_results_file(self.engine.export_results_file()), ([], []))

    def test_identical_profile_labels_keep_separate_ids_after_export_import(self):
        first, second = Profile("User"), Profile("User")
        message = self.group.responses["Base"]
        self.group.responses = {first.id: message, second.id: message}
        self.group.statuses = {first.id: 200, second.id: 403}
        self.group.profile_names = {first.id: "User", second.id: "User"}
        names, groups = self.engine.read_results_file(self.engine.export_results_file())
        self.assertEqual(set(names), set([first.id, second.id]))
        self.assertEqual(groups[0].profile_names, self.group.profile_names)
        self.assertEqual(groups[0].statuses, self.group.statuses)

    def test_config_write_failure_preserves_previous_file(self):
        self.engine.config_file = os.path.join(self.directory, "profiles.json")
        self.engine.profiles = [Profile("User")]
        BurpExtender.save_config_action(self.engine, None)
        with open(self.engine.config_file) as source:
            original = source.read()
        dump = authflow.json.dump
        def fail(data, output, **kwargs):
            output.write("partial")
            raise IOError("simulated disk write failure")
        try:
            authflow.json.dump = fail
            BurpExtender.save_config_action(self.engine, None)
        finally:
            authflow.json.dump = dump
        with open(self.engine.config_file) as source:
            self.assertEqual(source.read(), original)
        self.assertEqual(os.listdir(self.directory), ["profiles.json"])


@unittest.skipUnless(ON_JYTHON, "Swing requires Jython")
class FeatureSwingTests(unittest.TestCase):
    def test_ui_selection_templates_bulk_ator_and_imported_results(self):
        from javax.swing import SwingUtilities, JPanel
        class Editor(object):
            def setMessage(self, value, request): self.value = value
            def getComponent(self): return JPanel()
        class Callbacks(SettingsCallbacks):
            def createMessageEditor(self, controller, editable): return Editor()
        failures = []
        def check():
            try:
                engine = Engine([], [])
                engine.results_data = []
                engine.extension_enabled = True
                engine._callbacks = Callbacks()
                engine.status_renderer = StatusColorRenderer()
                engine.init_ui()
                engine.add_profile(None)
                engine.add_profile(None)
                engine.p_list_model.setValueAt(False, 0, 1)
                engine.listener_mode_combo.setSelectedIndex(1)
                self.assertEqual(engine.selected_listener_profiles(64), [engine.profiles[1]])
                engine.listener_tool_cbs["Repeater"].doClick()
                self.assertEqual(engine.selected_listener_profiles(64), [])
                engine.set_all_ator_enabled(True)
                self.assertTrue(engine.ator_enabled_cb.isSelected())
                engine.set_all_ator_enabled(False)
                self.assertFalse(engine.ator_enabled_cb.isSelected())
                engine.store_request_template("Login", step("login", "user=${user}"))
                engine.use_request_template(None)
                editor = engine.auth_step_tabs.getSelectedComponent()
                self.assertIn("${user}", editor.request_area.getText())
                editor.request_area.setText("draft change")
                self.assertNotEqual(engine.request_templates[0]["step"]["request"], "draft change")
                imported = RequestGroup(42, "GET", "https://example.test")
                imported.statuses = {"Archived user": 403, "Base": 200}
                imported.responses = {"Archived user": MessageInfo(response("denied", 403),
                                      "GET / HTTP/1.1\r\n\r\n", Helpers().buildHttpService("example.test", 443, True))}
                engine.append_imported_results(["Archived user"], [imported])
                self.assertEqual(imported.id, 1)
                self.assertEqual(len(engine.profiles), 2)
                column = engine.res_table_model.getColumnCount() - 1
                self.assertEqual(engine.res_table_model.getValueAt(0, column), 403)
                engine.res_table.setRowSelectionInterval(0, 0)
                self.assertEqual(engine.detail_tabs.getTitleAt(0), "Archived user")
                self.assertEqual(engine.detail_editors[0][2].value, response("denied", 403))
                engine.refresh_ui_full()
                self.assertEqual(engine.res_table_model.getValueAt(0, column), 403)
                engine.clear_results(None)
                self.assertFalse(engine.results_data)
                self.assertEqual(engine.detail_tabs.getTabCount(), 0)
                self.assertEqual(engine.res_table_model.getColumnCount(), 6)
            except Exception as ex:
                failures.append(ex)
        SwingUtilities.invokeAndWait(check)
        if failures:
            raise failures[0]
