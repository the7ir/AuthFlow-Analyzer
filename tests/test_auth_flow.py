"""Run with python -m unittest discover -s tests -v (CPython or Jython).

CPython uses import-only Swing/Burp stubs; HTTP callbacks are always simulated.
With Jython and the Burp API on the classpath, Swing tests also run headlessly.
"""
import copy
import base64
import json
import os
import sys
import tempfile
import threading
import types
import unittest

ON_JYTHON = sys.platform.startswith("java")
if not ON_JYTHON:
    def stub_module(name, names):
        module = types.ModuleType(name)
        for item in names.split():
            setattr(module, item, type(item, (object,), {}))
        sys.modules[name] = module
        return module

    stub_module("burp", "IBurpExtender ITab IHttpListener IMessageEditorController IContextMenuFactory IExtensionStateListener")
    swing = stub_module("javax.swing", "JPanel JTabbedPane JSplitPane JScrollPane JTable JButton JLabel JTextField JTextArea JCheckBox Box BoxLayout ListSelectionModel SwingUtilities BorderFactory JMenuItem SwingConstants JSeparator JFileChooser JComboBox DefaultCellEditor JOptionPane")
    swing.SwingUtilities.invokeLater = staticmethod(lambda callback: callback())
    stub_module("javax.swing.table", "DefaultTableModel DefaultTableCellRenderer")
    stub_module("java.awt", "BorderLayout FlowLayout Dimension Color Font")
    stub_module("java.awt.event", "ComponentAdapter")
    stub_module("java.lang", "Integer Object String Boolean")

from AuthFlowAnalyzer import (AuthFlowError, AuthStepEditor, BurpExtender, Profile,
                              RequestGroup, StatusColorRenderer, extract_value, render_template,
                              status_matches, validate_flow)


def extractor(name="token", method="JSON", selector="token", end="", source="Body"):
    return dict(variable=name, method=method, selector=selector, end=end, source=source)


def step(name, body="", extractors=None, host="auth.example:8443"):
    return dict(name=name, https=True, expected_status="2xx", extractors=extractors or [],
                request="POST /%s HTTP/1.1\nHost: %s\nContent-Length: 999\n\n%s" % (name, host, body))


def response(body="", status=200, headers=""):
    return "HTTP/1.1 %d Test\r\n%s\r\n%s" % (status, headers, body)


class MessageInfo(object):
    def __init__(self, message, request=None, service=None):
        self.message = message
        self.request, self.service = request, service

    def getResponse(self):
        return self.message

    def getRequest(self):
        return self.request

    def getHttpService(self):
        return self.service


class RequestInfo(object):
    def __init__(self, request):
        self.request = request

    def getHeaders(self):
        return self.request.split("\r\n\r\n", 1)[0].split("\r\n")

    def getBodyOffset(self):
        return self.request.index("\r\n\r\n") + 4

    def getMethod(self):
        return self.request.split()[0]

    def getUrl(self):
        return "https://example.test" + self.request.split()[1]


class ResponseInfo(object):
    def __init__(self, message):
        self.message = message

    def getStatusCode(self):
        return int(self.message.split()[1])


class HttpService(tuple):
    def getHost(self): return self[0]
    def getPort(self): return self[1]
    def getProtocol(self): return "https" if self[2] else "http"


class Helpers(object):
    def stringToBytes(self, value):
        return value

    def bytesToString(self, value):
        return value

    def buildHttpService(self, host, port, https):
        return HttpService((host, port, https))

    def base64Encode(self, value):
        return base64.b64encode(value.encode("latin-1")).decode("ascii")

    def base64Decode(self, value):
        return base64.b64decode(value).decode("latin-1")

    def buildHttpMessage(self, headers, body):
        headers = [h for h in headers if not h.lower().startswith("content-length:")]
        headers.append("Content-Length: %d" % len(body))
        return "\r\n".join(headers) + "\r\n\r\n" + body

    def analyzeRequest(self, request):
        if hasattr(request, "getRequest"):
            request = request.getRequest()
        return RequestInfo(request)

    def analyzeResponse(self, message):
        return ResponseInfo(message)


class Callbacks(object):
    def __init__(self, responses):
        self.responses = list(responses)
        self.sent = []
        self.on_send = None

    def makeHttpRequest(self, service, request):
        self.sent.append((service, request))
        if self.on_send:
            self.on_send()
        result = self.responses.pop(0)
        return MessageInfo(result, request, service) if result is not None else None

    def saveBuffersToTempFiles(self, message):
        return message


class Engine(BurpExtender):
    def __init__(self, profiles, responses):
        self.profiles = profiles
        self._helpers = Helpers()
        self._callbacks = Callbacks(responses)
        self.regen_lock = threading.RLock()
        self.config_lock = threading.RLock()
        self.logs = []
        self.statuses = []
        self.saved = []

    def add_log(self, profile, message):
        self.logs.append(message)

    def update_ator_status_ui(self, profile, status, token=None):
        self.statuses.append(status)

    def update_res_status_ui(self, group, name, status):
        self.statuses.append(status)

    def refresh_variables_ui(self, profile):
        pass

    def refresh_auth_test_ui(self, profile):
        pass

    def save_config_action(self, event):
        self.saved.append(json.loads(json.dumps([p.to_dict() for p in self.profiles])))


class FlowTests(unittest.TestCase):
    def make_flow(self):
        p = Profile("User")
        p.initial_variables = {"client": "demo"}
        p.auth_steps = [
            step("one", "client=${client}", [extractor("token1")]),
            step("two", "first=${token1}", [extractor("token2")]),
            step("three", "first=${token1}&second=${token2}", [extractor("AuthorToken")])]
        p.headers_list = [["Authorization", "Bearer ${AuthorToken}"], ["X-First", "${token1}"]]
        p.match_replace_list = [["OLD", "${token1}:${token2}:${AuthorToken}"]]
        return p

    def send(self, engine, profile):
        request = "POST /resource HTTP/1.1\r\nHost: api.example\r\nContent-Length: 3\r\n\r\nOLD"
        group = RequestGroup(1, "POST", "https://api.example/resource")
        engine.send_profile_request(group, profile, RequestInfo(request).getHeaders(), request,
                                    ("api.example", 443, True))
        return group

    def test_three_steps_then_header_and_body_substitution(self):
        p = self.make_flow()
        engine = Engine([p], [response('{"token":"one"}'), response('{"token":"two"}'),
                              response('{"token":"final-secret"}'), response("ok")])
        self.assertEqual(engine.regenerate_token(p), "final-secret")
        self.assertIn("client=demo", engine._callbacks.sent[0][1])
        self.assertIn("first=one", engine._callbacks.sent[1][1])
        self.assertIn("first=one&second=two", engine._callbacks.sent[2][1])
        self.assertEqual(p.variables["token1"], "one")
        self.assertEqual(engine._callbacks.sent[0][0], ("auth.example", 8443, True))
        group = self.send(engine, p)
        sent = engine._callbacks.sent[-1][1]
        self.assertIn("Authorization: Bearer final-secret\r\n", sent)
        self.assertIn("X-First: one\r\n", sent)
        self.assertTrue(sent.endswith("one:two:final-secret"))
        self.assertIn("Content-Length: 20\r\n", sent)
        self.assertIn(p.id, group.responses)
        self.assertEqual(p.headers_list[0][1], "Bearer ${AuthorToken}")
        self.assertNotIn("final-secret", "\n".join(engine.logs))
        self.assertEqual(engine.saved[-1][0]["variables"], p.variables)

    def test_failed_step_does_not_publish_partial_values_or_send_later_steps(self):
        p = self.make_flow()
        p.variables = {"token1": "old1", "AuthorToken": "old-final"}
        p.last_token = "old-final"
        engine = Engine([p], [response('{"token":"new1"}'), response('{}')])
        self.assertIsNone(engine.regenerate_token(p))
        self.assertEqual(len(engine._callbacks.sent), 2)
        self.assertEqual(p.variables, {"token1": "old1", "AuthorToken": "old-final"})
        self.assertEqual(p.last_token, "old-final")
        self.assertFalse(engine.saved)
        self.assertFalse(p.is_regenerating)
        self.assertEqual(engine.statuses[-1], "Failed at step 2")

    def test_old_values_cannot_satisfy_forward_reference(self):
        p = self.make_flow()
        p.auth_steps[0]["request"] += "&bad=${token2}"
        p.variables = {"token2": "stale"}
        engine = Engine([p], [])
        self.assertIsNone(engine.regenerate_token(p))
        self.assertFalse(engine._callbacks.sent)

    def test_status_error_and_missing_response_stop_flow(self):
        for result in [None, response('{"token":"error"}', 401)]:
            p = self.make_flow()
            engine = Engine([p], [result])
            self.assertIsNone(engine.regenerate_token(p))
            self.assertEqual(len(engine._callbacks.sent), 1)
            self.assertEqual(p.variables, {})

    def test_multiple_extractions_and_step_without_extraction(self):
        p = Profile("User")
        p.auth_steps = [step("setup"), step("login", extractors=[
            extractor("token"), extractor("cookie", "Header", "Set-Cookie")])]
        engine = Engine([p], [response(""), response('{"token":"abc"}', headers="Set-Cookie: sid=xyz\r\n")])
        self.assertEqual(engine.regenerate_token(p), "sid=xyz")
        self.assertEqual(p.variables, {"token": "abc", "cookie": "sid=xyz"})

    def test_auto_run_when_first_mirrored_request_needs_variables(self):
        p = self.make_flow()
        p.ator_enabled = True
        engine = Engine([p], [response('{"token":"one"}'), response('{"token":"two"}'),
                              response('{"token":"final"}'), response("ok")])
        self.send(engine, p)
        self.assertEqual(len(engine._callbacks.sent), 4)
        self.assertEqual(engine.statuses[-1], 200)

    def test_undefined_variable_without_ator_sends_nothing(self):
        p = self.make_flow()
        engine = Engine([p], [])
        self.send(engine, p)
        self.assertFalse(engine._callbacks.sent)
        self.assertEqual(engine.statuses[-1], "Config Error")

    def test_expiry_runs_entire_flow_and_retries_only_once(self):
        p = self.make_flow()
        p.ator_enabled = True
        p.variables = {"token1": "old1", "token2": "old2", "AuthorToken": "expired"}
        engine = Engine([p], [response("expired", 401), response('{"token":"one"}'),
                              response('{"token":"two"}'), response('{"token":"final"}'), response("still unauthorized", 401)])
        group = self.send(engine, p)
        self.assertEqual(len(engine._callbacks.sent), 5)
        self.assertIn("Authorization: Bearer final", engine._callbacks.sent[-1][1])
        self.assertIn(p.id, group.responses)
        self.assertEqual(engine.statuses[-1], 401)
        self.assertEqual(p.headers_list[0][1], "Bearer ${AuthorToken}")

    def test_concurrent_stale_generation_uses_completed_refresh(self):
        p = self.make_flow()
        engine = Engine([p], [response('{"token":"one"}'), response('{"token":"two"}'), response('{"token":"final"}')])
        generation = p.auth_generation
        self.assertEqual(engine.regenerate_token(p, generation), "final")
        self.assertEqual(engine.regenerate_token(p, generation), "final")
        self.assertEqual(len(engine._callbacks.sent), 3)

    def test_edit_during_run_does_not_publish_result(self):
        p = self.make_flow()
        engine = Engine([p], [response('{"token":"one"}')])
        def edit():
            p.config_revision += 1
        engine._callbacks.on_send = edit
        self.assertIsNone(engine.regenerate_token(p))
        self.assertFalse(p.variables)
        self.assertEqual(len(engine._callbacks.sent), 1)

    def test_profile_values_are_isolated(self):
        first, second = self.make_flow(), self.make_flow()
        engine = Engine([first, second], [response('{"token":"one"}'), response('{"token":"two"}'), response('{"token":"final"}')])
        engine.regenerate_token(first)
        self.assertFalse(second.variables)

    def test_serialization_and_legacy_migration(self):
        legacy = {"name": "Old", "auth_request": step("login")["request"],
                  "token_pre": '<token>', "token_post": '</token>',
                  "headers_list": [["Authorization", "Bearer old"]]}
        p = Profile.from_dict(legacy)
        self.assertEqual(len(p.auth_steps), 1)
        engine = Engine([p], [response('<token>fresh</token>')])
        self.assertEqual(engine.regenerate_token(p), "fresh")
        self.assertEqual(p.headers_list[0][1], "Bearer fresh")
        loaded = Profile.from_dict(json.loads(json.dumps(p.to_dict())))
        self.assertEqual(loaded.to_dict(), p.to_dict())
        flow = self.make_flow()
        self.assertEqual(Profile.from_dict(json.loads(json.dumps(flow.to_dict()))).to_dict(), flow.to_dict())

    def test_clone_has_independent_settings_and_runtime_state(self):
        source = self.make_flow()
        source.variables = {"AuthorToken": "existing"}
        source.is_regenerating = True
        duplicate = source.clone("User (Copy)")
        self.assertEqual(duplicate.name, "User (Copy)")
        self.assertEqual(duplicate.auth_steps, source.auth_steps)
        self.assertEqual(duplicate.variables, source.variables)
        self.assertFalse(duplicate.is_regenerating)
        duplicate.auth_steps[0]["extractors"][0]["variable"] = "changed"
        duplicate.headers_list[0][1] = "changed"
        duplicate.variables["AuthorToken"] = "changed"
        duplicate.initial_variables["client"] = "changed"
        self.assertEqual(source.auth_steps[0]["extractors"][0]["variable"], "token1")
        self.assertEqual(source.headers_list[0][1], "Bearer ${AuthorToken}")
        self.assertEqual(source.variables["AuthorToken"], "existing")
        self.assertEqual(source.initial_variables["client"], "demo")

    def test_http_ipv6_and_body_whitespace(self):
        engine = Engine([], [])
        configured = step("request", "  leading\n\ntrailing  \n", host="[::1]:8080")
        configured["https"] = False
        service, request = engine.build_auth_request(configured, {})
        self.assertEqual(service, ("::1", 8080, False))
        self.assertTrue(request.endswith("  leading\n\ntrailing  \n"))
        self.assertEqual(request.count("X-AuthFlow-Analyzer:"), 1)
        configured["request"] = "GET / HTTP/1.1\nHost: example.test\n\n"
        self.assertEqual(engine.build_auth_request(configured, {})[0], ("example.test", 80, False))

    def test_invalid_host_is_rejected(self):
        engine = Engine([], [])
        for host in ["bad:port", "example:99999", "http://example", ""]:
            self.assertRaises(AuthFlowError, engine.build_auth_request, step("bad", host=host), {})


class AuthTestingTests(unittest.TestCase):
    def setUp(self):
        self.profile = Profile("Test user")
        self.profile.variables = {"AuthorToken": "live-token"}
        self.steps = [step("verify", extractors=[extractor("verifyToken")]),
                      step("exchange", "verify=${verifyToken}", [extractor("sessionToken")]),
                      step("authorize", "verify=${verifyToken}&session=${sessionToken}", [extractor("AuthorToken")])]
        self.responses = [response('{"token":"verify-123"}'), response('{"token":"session-456"}'),
                          response('{"token":"final-789"}')]
        self.engine = Engine([self.profile], self.responses)

    def run_test(self, mode="step", index=0, steps=None, initial=None):
        session = self.engine.prepare_auth_test(self.profile, self.steps if steps is None else steps,
                                               initial or {}, mode, index)
        self.engine.execute_auth_test(self.profile, session, mode, index)
        return session

    def test_stepwise_capture_and_reuse_without_replaying_previous_requests(self):
        first = self.run_test().results[0]
        self.assertEqual(first.captures[0]["value"], "verify-123")
        self.assertEqual(first.http_status, 200)
        self.assertIsNotNone(first.elapsed_ms)
        self.assertEqual(first.getRequest(), self.engine._callbacks.sent[0][1])
        self.assertEqual(first.getResponse(), self.responses[0])
        second = self.run_test(index=1).results[1]
        self.assertEqual(len(self.engine._callbacks.sent), 2)
        self.assertIn("verify=verify-123", second.request)
        self.assertEqual(second.inputs, {"verifyToken": "verify-123"})
        self.assertEqual(second.variables, {"sessionToken": "session-456"})
        last = self.run_test(index=2).results[2]
        self.assertIn("verify=verify-123&session=session-456", last.request)
        self.assertEqual(last.captures[0]["value"], "final-789")
        self.assertEqual(self.profile.variables, {"AuthorToken": "live-token"})
        self.assertFalse(self.engine.saved)
        self.assertEqual(self.profile.auth_steps, [])

    def test_can_test_first_step_while_future_steps_are_incomplete(self):
        self.steps[1]["request"] = ""
        self.steps[2]["extractors"] = [extractor(method="Regex", selector="[")]
        session = self.run_test()
        self.assertEqual(session.results[0].status, "Success")
        self.assertEqual(session.results[1].status, "Not run")
        self.assertEqual(len(self.engine._callbacks.sent), 1)

    def test_missing_previous_step_is_blocked_without_using_live_variables(self):
        self.profile.variables["verifyToken"] = "stale"
        session = self.run_test(index=1)
        self.assertEqual(session.results[1].status, "Blocked")
        self.assertIn("step 1", session.results[1].error)
        self.assertFalse(self.engine._callbacks.sent)
        self.assertFalse(session.busy)

    def test_full_flow_and_through_selected_start_from_fresh_values(self):
        session = self.run_test(mode="through", index=1)
        self.assertEqual([r.status for r in session.results], ["Success", "Success", "Not run"])
        self.engine._callbacks.responses = [response('{"token":"new-verify"}')] + self.responses[1:]
        session = self.run_test(mode="full")
        self.assertEqual(len(self.engine._callbacks.sent), 5)
        self.assertIn("verify=new-verify", session.results[1].request)
        self.assertTrue(all(r.status == "Success" for r in session.results))
        self.assertIn("Full flow passed", session.status)
        self.assertFalse(self.engine.saved)
        self.assertEqual(self.profile.variables, {"AuthorToken": "live-token"})

    def test_editing_later_step_preserves_valid_earlier_captures(self):
        self.run_test(mode="full")
        self.steps[1]["request"] += "&updated=1"
        self.engine._callbacks.responses = [response('{"token":"updated-session"}')]
        session = self.run_test(index=1)
        self.assertEqual(session.results[0].variables, {"verifyToken": "verify-123"})
        self.assertIn("verify=verify-123&updated=1", session.results[1].request)
        self.assertEqual(session.results[2].status, "Not run")
        self.assertEqual(len(self.engine._callbacks.sent), 4)

    def test_rerun_or_edit_of_producer_invalidates_later_results(self):
        self.run_test(mode="full")
        self.engine._callbacks.responses = [response('{"token":"new-verify"}')]
        session = self.run_test()
        self.assertEqual([r.status for r in session.results], ["Success", "Not run", "Not run"])
        self.steps[0]["request"] += "edited"
        session = self.run_test(index=1)
        self.assertEqual(session.results[0].status, "Not run")
        self.assertEqual(session.results[1].status, "Blocked")
        self.assertIsNone(session.results[1].request)
        self.assertEqual(len(self.engine._callbacks.sent), 4)

    def test_initial_value_change_invalidates_previous_captures(self):
        self.run_test(initial={"user": "first"})
        session = self.run_test(index=1, initial={"user": "second"})
        self.assertEqual(session.results[1].status, "Blocked")
        self.assertEqual(len(self.engine._callbacks.sent), 1)

    def test_capture_failure_keeps_response_and_all_extractor_outcomes(self):
        self.steps[0]["extractors"] = [extractor("verifyToken"), extractor("missing", selector="missing"),
                                        extractor("another", selector="token")]
        session = self.run_test(mode="full")
        result = session.results[0]
        self.assertEqual(result.status, "Failed")
        self.assertEqual([c["status"] for c in result.captures], ["Captured", "Failed", "Captured"])
        self.assertEqual(result.captures[0]["value"], "verify-123")
        self.assertIn("JSON path", result.captures[1]["error"])
        self.assertEqual(result.response, self.responses[0])
        self.assertEqual(result.variables, {})
        self.assertEqual(session.results[1].status, "Not run")
        self.assertEqual(len(self.engine._callbacks.sent), 1)
        self.assertEqual(self.run_test(index=1).results[1].status, "Blocked")

    def test_http_failure_and_no_response_have_inspectable_request(self):
        for reply in [response("rejected", 403), None]:
            self.engine._callbacks.responses = [reply]
            session = self.run_test()
            result = session.results[0]
            self.assertEqual(result.status, "Failed")
            self.assertIsNotNone(result.request)
            self.assertEqual(result.response, reply)
            self.assertEqual(result.captures[0]["status"], "Not run")
            self.assertTrue(result.error)

    def test_variable_names_are_case_sensitive_and_wrong_case_sends_nothing(self):
        self.run_test()
        self.steps[1]["request"] = self.steps[1]["request"].replace("${verifyToken}", "${VerifyToken}")
        session = self.run_test(index=1)
        self.assertEqual(session.results[1].status, "Failed")
        self.assertIn("VerifyToken", session.results[1].error)
        self.assertEqual(len(self.engine._callbacks.sent), 1)

    def test_reset_during_request_prevents_remaining_requests(self):
        self.engine._callbacks.on_send = lambda: setattr(self.profile, "auth_test", None)
        session = self.run_test(mode="full")
        self.assertEqual(len(self.engine._callbacks.sent), 1)
        self.assertIsNone(self.profile.auth_test)
        self.assertFalse(session.busy)
        self.assertEqual(self.profile.variables, {"AuthorToken": "live-token"})

    def test_session_is_not_saved_cloned_or_shared_and_double_start_is_rejected(self):
        session = self.engine.prepare_auth_test(self.profile, self.steps, {}, "step", 0)
        self.assertRaises(AuthFlowError, self.engine.prepare_auth_test, self.profile, self.steps, {}, "step", 0)
        self.engine.execute_auth_test(self.profile, session, "step", 0)
        self.assertNotIn("auth_test", self.profile.to_dict())
        self.assertIsNone(self.profile.clone("Clone").auth_test)
        self.assertIsNone(Profile("Other").auth_test)

    def test_full_test_uses_same_requests_and_extraction_as_live_flow(self):
        session = self.run_test(mode="full")
        self.profile.auth_steps = self.steps
        self.engine._callbacks.responses = self.responses[:]
        self.assertEqual(self.engine.regenerate_token(self.profile), "final-789")
        self.assertEqual(self.engine._callbacks.sent[:3], self.engine._callbacks.sent[3:])
        self.assertEqual(self.profile.variables["AuthorToken"], session.results[-1].variables["AuthorToken"])


class ExtractionTests(unittest.TestCase):
    def test_json_paths_and_pointer(self):
        message = response('{"data":{"tokens":[{"value":"abc"}]},"a/b":{"~key":0}}')
        for path in ["data.tokens[0].value", "$.data.tokens.0.value", "/data/tokens/0/value"]:
            self.assertEqual(extract_value(extractor(selector=path), message), "abc")
        self.assertEqual(extract_value(extractor(selector="/a~1b/~0key"), message), "0")

    def test_delimiters_regex_header_and_sources(self):
        message = response('<token>body-token</token>', headers="X-Token: header-token\r\n")
        self.assertEqual(extract_value(extractor(method="Delimiters", selector="<token>", end="</token>"), message), "body-token")
        self.assertEqual(extract_value(extractor(method="Regex", selector=r"<token>(?P<value>.*?)</token>", end="value"), message), "body-token")
        self.assertEqual(extract_value(extractor(method="Regex", selector=r"<token>(.*?)</token>"), message), "body-token")
        self.assertEqual(extract_value(extractor(method="Header", selector="x-TOKEN"), message), "header-token")
        self.assertEqual(extract_value(extractor(method="Delimiters", source="Response", selector="X-Token: ", end="\r\n"), message), "header-token")

    def test_failed_and_empty_extractions(self):
        for rule, body in [(extractor(), '{}'), (extractor(), '{"token":null}'),
                           (extractor(), '{"token":""}'), (extractor(), 'invalid'),
                           (extractor(method="Regex", selector="missing(.*)"), 'abc'),
                           (extractor(method="Header", selector="Missing"), 'abc'),
                           (extractor(method="Delimiters", selector="<", end=">"), '<>')]:
            self.assertRaises(AuthFlowError, extract_value, rule, response(body))

    def test_templates_are_literal_and_single_pass(self):
        self.assertEqual(render_template("${one}:${two}", {"one": "${two}", "two": r"a\1$+"}), r"${two}:a\1$+")
        self.assertRaises(AuthFlowError, render_template, "${missing}", {})
        self.assertRaises(AuthFlowError, render_template, "${bad-name}", {})

    def test_flow_validation_and_status_conditions(self):
        for condition in ["2xx", "200-299", "200,302", ""]:
            self.assertTrue(status_matches(200, condition))
        self.assertFalse(status_matches(401, "200-299,302"))
        self.assertRaises(AuthFlowError, status_matches, 200, "anything")
        self.assertRaises(AuthFlowError, validate_flow, [step("one", extractors=[extractor("bad-name")])], {})
        self.assertRaises(AuthFlowError, validate_flow, [step("one", extractors=[extractor(), extractor()])], {})
        self.assertRaises(AuthFlowError, validate_flow, [step("one", extractors=[extractor(method="Regex", selector="(abc)", end="2")])], {})


@unittest.skipUnless(ON_JYTHON, "Swing requires Jython")
class SwingTests(unittest.TestCase):
    def test_auth_step_buttons_use_draft_values_and_display_capture_and_http_details(self):
        from javax.swing import JPanel, SwingUtilities
        finished = threading.Event()
        failures = []
        holder = []
        token = "verify-" + "x" * 150
        class Editor(object):
            def __init__(self):
                self.panel = JPanel()
            def setMessage(self, value, request):
                self.value = value
            def getComponent(self):
                return self.panel
        class DebugCallbacks(Callbacks):
            def createMessageEditor(self, controller, editable):
                return Editor()
        class DebugEngine(BurpExtender):
            def execute_auth_test(self, profile, session, mode, index):
                try:
                    BurpExtender.execute_auth_test(self, profile, session, mode, index)
                finally:
                    finished.set()
        def on_edt(action):
            def checked():
                try:
                    action()
                except Exception as ex:
                    failures.append(ex)
            SwingUtilities.invokeAndWait(checked)
            if failures:
                raise failures[0]
        def setup_and_test_first():
            engine = DebugEngine()
            holder.append(engine)
            engine.profiles, engine.results_data = [], []
            engine.regen_lock = threading.RLock()
            engine.status_renderer = StatusColorRenderer()
            engine._helpers = Helpers()
            engine._callbacks = DebugCallbacks([response(json.dumps({"token": token})), response('{"token":"session-value"}')])
            engine.init_ui()
            engine.add_profile(None)
            engine.add_auth_step(None)
            editor = engine.auth_step_tabs.getSelectedComponent()
            editor.request_area.setText(step("verify")["request"])
            editor.extractor_model.addRow(["verifyToken", "Body", "JSON", "token", ""])
            engine.add_auth_step(None) # An unfinished later step must not prevent step 1 testing.
            engine.auth_step_tabs.setSelectedIndex(0)
            engine.auth_test_buttons[0].doClick()
        on_edt(setup_and_test_first)
        self.assertTrue(finished.wait(10))
        engine = holder[0]
        def inspect_first_and_test_second():
            self.assertEqual(engine.profiles[0].auth_steps, [])
            self.assertEqual(engine.auth_test_model.getValueAt(0, 1), "Success")
            self.assertEqual(engine.auth_capture_value.getText(), token)
            self.assertEqual(engine.auth_test_editors[1].value, engine._callbacks.sent[0][1])
            self.assertEqual(engine.auth_test_editors[2].value, response(json.dumps({"token": token})))
            engine.auth_step_tabs.setSelectedIndex(1)
            editor = engine.auth_step_tabs.getSelectedComponent()
            editor.request_area.setText(step("exchange", "verify=${verifyToken}")["request"])
            editor.extractor_model.addRow(["sessionToken", "Body", "JSON", "token", ""])
            finished.clear()
            engine.auth_test_buttons[0].doClick()
        on_edt(inspect_first_and_test_second)
        self.assertTrue(finished.wait(10))
        def inspect_second_and_profile_isolation():
            self.assertEqual(engine.auth_test_model.getValueAt(1, 1), "Success")
            self.assertEqual(engine.auth_capture_value.getText(), "session-value")
            self.assertEqual(len(engine._callbacks.sent), 2)
            self.assertIn("verify=" + token, engine.auth_test_editors[1].value)
            engine.auth_capture_table.setRowSelectionInterval(1, 1)
            self.assertEqual(engine.auth_capture_value.getText(), token)
            engine.add_profile(None)
            self.assertEqual(engine.auth_test_model.getRowCount(), 0)
            self.assertEqual(engine.auth_capture_value.getText(), "")
            engine.p_list_table.setRowSelectionInterval(0, 0)
            self.assertEqual(engine.auth_test_model.getRowCount(), 2)
            engine.reset_auth_test(None)
            self.assertEqual(engine.auth_test_model.getRowCount(), 0)
            self.assertIsNone(engine.profiles[0].auth_test)
        on_edt(inspect_second_and_profile_isolation)

    def test_step_editor_round_trip(self):
        from javax.swing import SwingUtilities
        failures = []
        def check():
            try:
                configured = step("login", "${initial}", [extractor("token1"), extractor("session", "Header", "Set-Cookie")])
                editor = AuthStepEditor(configured)
                self.assertEqual(editor.to_step(), configured)
                editor.add_extractor(None)
                editor.extractor_table.setRowSelectionInterval(2, 2)
                editor.remove_extractor(None)
                self.assertEqual(editor.to_step(), configured)
            except Exception as ex:
                failures.append(ex)
        SwingUtilities.invokeAndWait(check)
        if failures:
            raise failures[0]

    def test_config_save_reorder_and_reload(self):
        from javax.swing import SwingUtilities
        failures = []
        descriptor, filename = tempfile.mkstemp()
        os.close(descriptor)
        def check():
            try:
                engine = BurpExtender()
                engine.profiles = []
                engine.results_data = []
                engine.status_renderer = StatusColorRenderer()
                engine.config_lock = threading.RLock()
                engine.config_file = filename
                engine.init_ui()
                engine.add_profile(None)
                for name in ["first", "second"]:
                    engine.add_auth_step(None)
                    editor = engine.auth_step_tabs.getSelectedComponent()
                    editor.name_field.setText(name)
                    editor.request_area.setText(step(name)["request"])
                engine.move_auth_step(-1)
                self.assertTrue(engine.save_profile_config(None))
                self.assertEqual([s["name"] for s in engine.profiles[0].auth_steps], ["second", "first"])
                engine.remove_auth_step(None)
                self.assertTrue(engine.save_profile_config(None))
                with open(filename) as saved:
                    loaded = Profile.from_dict(json.load(saved)[0])
                self.assertEqual(loaded.auth_steps[0]["name"], "first")
                engine.refresh_ui_full()
                self.assertEqual(engine.auth_step_tabs.getTabCount(), 1)
                source = engine.profiles[0]
                engine.p_note_area.setText("unsaved note to clone")
                engine.clone_profile(None)
                self.assertEqual(len(engine.profiles), 2)
                self.assertEqual(engine.profiles[1].name, source.name + " (Copy)")
                self.assertEqual(engine.profiles[1].note, "unsaved note to clone")
                self.assertEqual(engine.p_list_table.getSelectedRow(), 1)
                engine.p_list_table.setRowSelectionInterval(0, 0)
                engine.clone_profile(None)
                self.assertEqual(engine.profiles[2].name, source.name + " (Copy) 2")
                engine.profiles[2].auth_steps[0]["request"] = "changed"
                self.assertNotEqual(source.auth_steps[0]["request"], "changed")
                from javax.swing import JButton
                from java.awt import BorderLayout
                toolbar = engine.main_panel.getLayout().getLayoutComponent(BorderLayout.NORTH).getComponent(0)
                labels = [button.getText() for button in toolbar.getComponents() if isinstance(button, JButton)]
                self.assertEqual(labels, ["Save Profiles", "Load Config File", "Save Profile Changes", "Clear All Results", "Clear Logs"])
            except Exception as ex:
                failures.append(ex)
        try:
            SwingUtilities.invokeAndWait(check)
            if failures:
                raise failures[0]
        finally:
            os.remove(filename)

    def test_results_show_request_and_response_together(self):
        from javax.swing import JPanel, JTabbedPane, JSplitPane, SwingUtilities
        failures = []
        class Result(object):
            def getRequest(self):
                return "request"
            def getResponse(self):
                return "response"
            def getHttpService(self):
                return "service"
        class Editor(object):
            def __init__(self, controller):
                self.controller = controller
                self.panel = JPanel()
            def setMessage(self, message, is_request):
                self.message, self.is_request = message, is_request
            def getComponent(self):
                return self.panel
        class EditorCallbacks(object):
            def createMessageEditor(self, controller, editable):
                return Editor(controller)
        def check():
            try:
                engine = BurpExtender()
                engine.profiles = [Profile("User")]
                engine._callbacks = EditorCallbacks()
                engine.detail_tabs = JTabbedPane()
                group = RequestGroup(1, "GET", "https://example.test")
                group.responses = {"Base": Result(), "User": Result()}
                engine.update_detail_tabs(group)
                self.assertEqual(engine.detail_tabs.getTabCount(), 2)
                split = engine.detail_tabs.getComponentAt(0)
                self.assertIsInstance(split, JSplitPane)
                self.assertEqual(split.getOrientation(), JSplitPane.HORIZONTAL_SPLIT)
                self.assertEqual(split.getResizeWeight(), 0.5)
                controller, request, response_editor = engine.detail_editors[0]
                self.assertEqual(controller.getHttpService(), "service")
                self.assertEqual(request.message, "request")
                self.assertTrue(request.is_request)
                self.assertFalse(response_editor.is_request)
                engine.detail_tabs.setSelectedIndex(1)
                engine.update_detail_tabs(group)
                self.assertEqual(engine.detail_tabs.getTitleAt(engine.detail_tabs.getSelectedIndex()), "User")
            except Exception as ex:
                failures.append(ex)
        SwingUtilities.invokeAndWait(check)
        if failures:
            raise failures[0]


if __name__ == "__main__":
    unittest.main()
