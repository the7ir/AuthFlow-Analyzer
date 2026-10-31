import threading
import time
import unittest
from collections import deque

from test_auth_flow import (Engine, Helpers, MessageInfo, Profile, RequestGroup,
                            BurpExtender, step, extractor, response)
import AuthFlowAnalyzer as authflow


def wait_idle(pool, timeout=5):
    deadline = time.time() + timeout
    with pool.condition:
        while pool.pending or pool.active:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise AssertionError("Worker pool did not finish")
            pool.condition.wait(remaining)


class WorkerPoolTests(unittest.TestCase):
    def test_profiles_overlap_but_same_profile_remains_fifo(self):
        pool = authflow.ProfileWorkerPool(2)
        entered, other_done, release = threading.Event(), threading.Event(), threading.Event()
        order = []
        def first():
            entered.set()
            release.wait(3)
            order.append(1)
        try:
            self.assertTrue(pool.submit("a", first))
            self.assertTrue(entered.wait(2))
            self.assertTrue(pool.submit("a", lambda: order.append(2)))
            self.assertTrue(pool.submit("b", other_done.set))
            self.assertTrue(other_done.wait(2), "Another profile should run while profile A is blocked")
            self.assertEqual(order, [])
            release.set()
            wait_idle(pool)
            self.assertEqual(order, [1, 2])
        finally:
            release.set()
            pool.close()

    def test_queue_limit_resize_cancellation_and_shutdown(self):
        pool = authflow.ProfileWorkerPool(1, capacity=2)
        started, release, second = threading.Event(), threading.Event(), threading.Event()
        calls = []
        def hold():
            started.set()
            release.wait(3)
        try:
            pool.submit("a", hold)
            self.assertTrue(started.wait(2))
            self.assertTrue(pool.submit("a", lambda: calls.append("cancelled"), tag="result"))
            self.assertTrue(pool.submit("b", second.set, tag="manual"))
            self.assertFalse(pool.submit("c", lambda: None))
            pool.cancel_pending(lambda tag: tag == "result")
            pool.resize(2)
            self.assertTrue(second.wait(2))
            release.set()
            wait_idle(pool)
            self.assertEqual(calls, [])
            pool.close()
            self.assertFalse(pool.submit("a", lambda: None))
        finally:
            release.set()
            pool.close()

    def test_worker_survives_task_and_error_handler_failure(self):
        def fail(*args): raise ValueError("intentional")
        done = threading.Event()
        pool = authflow.ProfileWorkerPool(1, on_error=fail)
        try:
            pool.submit("a", fail)
            pool.submit("a", done.set)
            self.assertTrue(done.wait(2))
        finally:
            pool.close()


class QueuedUI(object):
    def __init__(self):
        self.queue, self.lock = deque(), threading.Lock()
    def invokeLater(self, callback):
        with self.lock: self.queue.append(callback)
    def drain(self):
        while True:
            with self.lock:
                if not self.queue: return
                callback = self.queue.popleft()
            callback()


class Table(object):
    def __init__(self):
        self.columns, self.rows = ["ID", "Method", "URL", "Base Status"], []
    def addColumn(self, name):
        self.columns.append(name)
        for row in self.rows: row.append(None)
    def setColumnIdentifiers(self, names): self.columns = list(names)
    def addRow(self, row): self.rows.append(list(row))
    def setValueAt(self, value, row, column): self.rows[row][column] = value
    def getColumnCount(self): return len(self.columns)
    def getColumnName(self, index): return self.columns[index]
    def getRowCount(self): return len(self.rows)
    def setRowCount(self, count): self.rows = self.rows[:count]
    def getSelectedRow(self): return -1
    def removeAll(self): pass


class ConcurrentCallbacks(object):
    def __init__(self):
        self.sent, self.lock, self.before_response = [], threading.Lock(), None
    def saveBuffersToTempFiles(self, message): return message
    def makeHttpRequest(self, service, request):
        with self.lock: self.sent.append(request)
        if self.before_response: self.before_response(request)
        return MessageInfo(response(request), request, service)


class ListenerHarness(Engine):
    def __init__(self, profiles):
        Engine.__init__(self, profiles, [])
        self._callbacks = ConcurrentCallbacks()
        self.extension_enabled = True
        self.load_listener_settings()
        self.results_data, self.result_column_keys, self.result_column_names = [], [], {}
        self.results_lock = threading.RLock()
        self.listener_slots = threading.BoundedSemaphore(256)
        self.listener_dropped = 0
        self.res_table_model, self.res_table, self.detail_tabs = Table(), Table(), Table()
        self.ensure_result_columns([(p.id, p.name) for p in profiles])
    def reapply_all_renderers(self): pass
    def update_res_status_ui(self, group, name, status):
        BurpExtender.update_res_status_ui(self, group, name, status)


class ConcurrentListenerTests(unittest.TestCase):
    def setUp(self):
        self.old_ui, self.ui = authflow.SwingUtilities, QueuedUI()
        authflow.SwingUtilities = self.ui
        self.profiles = [Profile("Admin"), Profile("User"), Profile("Guest")]
        self.engine = ListenerHarness(self.profiles)
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        if hasattr(self.engine, "worker_pool"):
            self.engine.worker_pool.close()
            for thread in self.engine.worker_pool.threads:
                thread.join(2)
        authflow.SwingUtilities = self.old_ui

    def capture(self, path="/one", headers="", flag=64, is_request=False):
        message = MessageInfo(response("base"), "GET %s HTTP/1.1\r\nHost: example.test\r\n%s\r\n" % (path, headers),
                              self.engine._helpers.buildHttpService("example.test", 443, True))
        self.engine.processHttpMessage(flag, is_request, message)

    def finish(self):
        self.ui.drain()
        wait_idle(self.engine.get_worker_pool())
        self.ui.drain()

    def test_listener_filters_prevent_capture_and_network_requests(self):
        self.capture(flag=1024)
        self.capture(is_request=True)
        self.capture(headers="X-AuthFlow-Analyzer: Internal-Regen\r\n")
        self.engine.listener_tools["Repeater"] = False
        self.capture()
        self.ui.drain()
        self.assertFalse(self.engine.results_data)
        self.assertFalse(self.engine._callbacks.sent)
        self.engine.listener_tools["Repeater"] = True
        self.engine.listener_all_profiles = False
        for profile in self.profiles: profile.listener_enabled = False
        self.capture()
        self.assertFalse(self.engine.results_data)
        self.profiles[1].listener_enabled = True
        self.capture()
        self.finish()
        self.assertEqual(len(self.engine._callbacks.sent), 1)
        self.assertEqual(set(self.engine.results_data[0].responses), set(["Base", self.profiles[1].id]))

    def test_many_requests_keep_every_response_in_its_profile_and_request_row(self):
        for index in range(40): self.capture("/request-%d" % index)
        self.finish()
        self.assertEqual(len(self.engine._callbacks.sent), 120)
        for index, group in enumerate(self.engine.results_data):
            self.assertEqual(group.id, index + 1)
            self.assertEqual(len(group.responses), 4)
            for column, profile in enumerate(self.profiles):
                message = group.responses[profile.id]
                self.assertIn("GET /request-%d HTTP" % index, message.getResponse())
                self.assertIn("X-AuthFlow-Analyzer: " + profile.name, message.getResponse())
                self.assertEqual(self.engine.res_table_model.rows[index][column + 4], 200)

    def test_clear_cancels_queued_work_and_late_response_cannot_overwrite_new_row(self):
        started = threading.Event()
        self.engine.worker_threads = 1
        def hold(request):
            if "GET /old " in request:
                started.set()
                self.release.wait(3)
        self.engine._callbacks.before_response = hold
        self.capture("/old")
        self.ui.drain()
        self.assertTrue(started.wait(2))
        old_group = self.engine.results_data[0]
        self.engine.clear_results(None)
        self.capture("/new")
        self.ui.drain()
        self.release.set()
        self.finish()
        self.assertTrue(old_group.cancelled)
        self.assertEqual(len(self.engine.results_data), 1)
        self.assertEqual(self.engine.results_data[0].id, 1)
        self.assertEqual(len(self.engine._callbacks.sent), 4)
        for message in list(self.engine.results_data[0].responses.values())[1:]:
            self.assertIn("GET /new HTTP", message.getRequest())

    def test_profile_rename_and_replacement_do_not_mix_result_columns(self):
        started = threading.Event()
        def hold(request):
            if "X-AuthFlow-Analyzer: Admin" in request:
                started.set()
                self.release.wait(3)
        self.engine._callbacks.before_response = hold
        original = self.profiles[0]
        self.capture()
        self.ui.drain()
        self.assertTrue(started.wait(2))
        with original.state_lock:
            original.name = "Renamed"
            original.config_revision += 1
        replacement = Profile("Admin")
        with self.engine.config_lock:
            self.engine.profiles = [replacement]
        self.release.set()
        self.finish()
        first = self.engine.results_data[0]
        self.assertIn(original.id, first.responses)
        self.assertNotIn(replacement.id, first.responses)
        self.assertEqual(first.profile_names[original.id], "Admin")
        self.capture("/replacement")
        self.finish()
        second = self.engine.results_data[1]
        self.assertIn(replacement.id, second.responses)
        self.assertNotEqual(self.engine.result_column_keys.index(original.id), self.engine.result_column_keys.index(replacement.id))
        self.assertEqual(len(set(self.engine.res_table_model.columns)), len(self.engine.res_table_model.columns))

    def test_config_edit_before_dispatch_does_not_send_stale_requests(self):
        self.capture()
        for profile in self.profiles:
            with profile.state_lock: profile.config_revision += 1
        self.finish()
        self.assertFalse(self.engine._callbacks.sent)
        self.assertTrue(all(self.engine.results_data[0].statuses[p.id] == "Config Changed" for p in self.profiles))

    def test_clear_before_ui_dispatch_discards_old_capture(self):
        self.capture()
        self.engine.clear_results(None)
        self.finish()
        self.assertFalse(self.engine.results_data)
        self.assertFalse(self.engine._callbacks.sent)

    def test_full_queue_reports_rejected_profiles_and_does_not_send_them(self):
        started = threading.Event()
        self.engine.worker_pool = authflow.ProfileWorkerPool(1, capacity=1)
        def hold():
            started.set()
            self.release.wait(3)
        self.engine.worker_pool.submit("manual", hold)
        self.assertTrue(started.wait(2))
        self.capture()
        self.ui.drain()
        group = self.engine.results_data[0]
        self.assertEqual(group.statuses[self.profiles[1].id], "Queue Full")
        self.assertEqual(group.statuses[self.profiles[2].id], "Queue Full")
        self.release.set()
        self.finish()
        self.assertEqual(len(self.engine._callbacks.sent), 1)

    def test_sorted_view_selects_correct_model_row_on_async_update(self):
        self.capture("/first")
        self.capture("/second")
        self.finish()
        selected = []
        self.engine.res_table.getSelectedRow = lambda: 0
        self.engine.res_table.convertRowIndexToModel = lambda row: 1
        self.engine.update_detail_tabs = lambda group: selected.append(group)
        first, second = self.engine.results_data
        self.engine.update_res_status_ui(first, self.profiles[0].id, 401)
        self.ui.drain()
        self.assertEqual(selected, [])
        self.engine.update_res_status_ui(second, self.profiles[1].id, 403)
        self.ui.drain()
        self.assertEqual(selected, [second])
        self.assertEqual(self.engine.res_table_model.rows[0][4], 401)
        self.assertEqual(self.engine.res_table_model.rows[1][5], 403)


class ParallelAuthTests(unittest.TestCase):
    def test_same_profile_refresh_is_deduplicated_while_other_profile_runs(self):
        profiles = [Profile("A"), Profile("B")]
        for p in profiles: p.auth_steps = [step(p.name, extractors=[extractor("AuthorToken")])]
        engine = Engine(profiles, [])
        entered, release, other_done = threading.Event(), threading.Event(), threading.Event()
        calls, results = [], []
        class Callbacks(object):
            def makeHttpRequest(self, service, request):
                calls.append(request)
                if "POST /A " in request:
                    entered.set()
                    release.wait(3)
                return MessageInfo(response('{"token":"fresh"}'))
        engine._callbacks = Callbacks()
        def run(profile, done=None):
            results.append(engine.regenerate_token(profile, 0))
            if done: done.set()
        threads = [threading.Thread(target=run, args=(profiles[0],)),
                   threading.Thread(target=run, args=(profiles[0],)),
                   threading.Thread(target=run, args=(profiles[1], other_done))]
        try:
            threads[0].start()
            self.assertTrue(entered.wait(2))
            threads[1].start()
            threads[2].start()
            self.assertTrue(other_done.wait(2), "Profile B auth must not wait on profile A")
        finally:
            release.set()
            for thread in threads:
                if thread.ident is not None: thread.join(3)
        self.assertEqual(len(calls), 2)
        self.assertEqual(results, ["fresh", "fresh", "fresh"])
