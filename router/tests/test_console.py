"""The operator console: what it asserts, what it refuses to imply.

Three classes of thing are pinned here, and they fail for different reasons:

  RENDERING — the page contains what it claims to contain.
  CONTAINMENT — agent-authored text reaches the page as inert text. This is
    the one that matters: the console renders message bodies, and on a
    delegation-only fleet a peer body is by construction one agent
    instructing another.
  HONEST ABSENCE — a fact this router cannot see renders as UNKNOWN and not
    as nothing. A page that silently omits the container row leaves poll age
    looking like a clean bill of health, which is the failure the whole
    `--host-facts` shape exists to prevent.

The third class is the easiest to regress and the hardest to notice, because
its failure mode is a page that looks fine.
"""

import json
import re
import unittest
from datetime import datetime, timedelta, timezone

from router import console, outbound, service
from router.status import StatusTracker
from router.tests.helpers import RouterTestCase, write_request
from router.tests.peer_helpers import addr, make_peer_config, write_outcome


def _ts(delta_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


class _ConsoleTestCase(RouterTestCase):
    """analyst -> coder on the peer lane, plus `lonely`, which is configured
    and has no counterpart at all, so the excluded senses have occupants."""

    def setUp(self):
        super().setUp()
        self.cfg = make_peer_config(self, {
            "analyst": {},
            "coder": {"peer_senders": ["analyst"]},
            "lonely": {},
        })
        self._req = 0

    def queue(self, subject="a subject", body="a body", to="coder"):
        """Write a submit-request and leave it for a drain to pick up."""
        self._req += 1
        req_id = f"{self._req:08d}"
        write_request(self.cfg, "analyst", req_id, to=[addr(to)],
                      subject=subject, body_text=body)
        return req_id

    def task(self, subject="a subject", body="a body", to="coder"):
        """Queue and drain immediately. NOTE this drains OUT OF BAND, so the
        status counters never see it — a test about counters must queue and
        then poll, so the poll does the draining and records it."""
        req_id = self.queue(subject=subject, body=body, to=to)
        outbound.drain_instance(self.cfg, "analyst")
        return req_id

    def page(self, **kwargs):
        return console.render_html(self.cfg, **kwargs)

    def host_facts(self, doc):
        path = self.tmp / "host-facts.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path


class RenderingTests(_ConsoleTestCase):
    def test_a_delivered_message_appears_with_its_metadata(self):
        self.task(subject="Refactor the parser", body="split the tokenizer")
        data = console.gather(self.cfg)

        self.assertEqual(len(data["messages"]), 1)
        msg = data["messages"][0]
        self.assertEqual((msg["sender"], msg["recipient"], msg["tree"]),
                         ("analyst", "coder", "peer"))
        self.assertEqual(msg["subject"], "Refactor the parser")
        self.assertEqual(msg["body_text"], "split the tokenizer")

    def test_routing_metadata_comes_from_the_ledger_not_the_spool_document(self):
        """The spool document is agent-adjacent; the ledger is router-private.
        Rewriting the document's `from` must not change who the page says
        sent the message — that is the whole reason the two are read from
        different places."""
        self.task()
        spool = next((self.cfg.instances["coder"].peer_root / "messages").glob("*.json"))
        doc = json.loads(spool.read_text())
        doc["from"] = "somebody-else@example.invalid"
        doc["to"] = "somebody-else@example.invalid"
        spool.write_text(json.dumps(doc))

        msg = console.gather(self.cfg)["messages"][0]

        self.assertEqual(msg["sender"], "analyst")
        self.assertEqual(msg["recipient"], "coder")

    def test_traffic_counts_by_pair_and_lane(self):
        self.task()
        self.task()
        pairs = console.gather(self.cfg)["traffic"]
        self.assertEqual(len(pairs), 1)
        self.assertEqual((pairs[0]["sender"], pairs[0]["recipient"],
                          pairs[0]["tree"], pairs[0]["count"]),
                         ("analyst", "coder", "peer", 2))

    def test_a_recorded_outcome_reaches_the_message_row(self):
        self.task()
        notice_id = console.gather(self.cfg)["messages"][0]["notice_id"]
        write_outcome(self.cfg, "coder", notice_id, "denied")
        service.run_once(self.cfg)

        # NOT messages[0]: a `denied` outcome sends a DSN to the sender, and
        # that DSN is itself a delivered notice with a newer timestamp, so it
        # sorts to the front. Look the original up by id.
        messages = {m["notice_id"]: m for m in console.gather(self.cfg)["messages"]}
        self.assertEqual(messages[notice_id]["outcome"], "denied")

    def test_a_router_authored_dsn_is_attributed_to_the_router(self):
        """The DSN the outcome above produces is a message too, and the page
        must not present it as though an agent wrote it."""
        self.task()
        notice_id = console.gather(self.cfg)["messages"][0]["notice_id"]
        write_outcome(self.cfg, "coder", notice_id, "denied")
        service.run_once(self.cfg)

        dsn = [m for m in console.gather(self.cfg)["messages"]
               if m["recipient"] == "analyst"]
        self.assertEqual(len(dsn), 1, "the sender should have received one DSN")
        self.assertTrue(dsn[0]["router_authored"])
        self.assertEqual(dsn[0]["sender"], "the router (DSN)")
        self.assertIn("Written by this router", self.page())

    def test_the_page_renders_and_names_the_instances(self):
        self.task()
        html = self.page()
        for name in ("analyst", "coder", "lonely"):
            self.assertIn(name, html)
        self.assertIn("Router console", html)


class ContainmentTests(_ConsoleTestCase):
    """Agent-authored text reaches the page as inert text."""

    HOSTILE = ("<script>alert('xss')</script>\n"
               "<img src=x onerror=alert(1)>\n"
               "\"quoted\" & ampersand")

    def test_a_hostile_body_cannot_form_a_tag(self):
        self.task(body=self.HOSTILE)
        html = self.page()

        body = [b for b in re.findall(r"<pre>(.*?)</pre>", html, re.S) if "onerror" in b]
        self.assertEqual(len(body), 1, "the hostile body should render, escaped")
        self.assertNotIn("<", body[0], "a raw < in the body can open a tag")
        self.assertNotIn(">", body[0], "a raw > in the body can close a tag")
        self.assertIn("&lt;script&gt;", body[0])

    def test_a_hostile_subject_cannot_form_a_tag(self):
        """Subjects land in a table cell rather than a <pre>, so they are a
        separate escape path and get their own test."""
        self.task(subject="<img src=x onerror=alert(1)>")
        html = self.page()

        self.assertNotIn("<img", html.lower())
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)

    def test_the_page_carries_no_script_of_its_own(self):
        """Bodies are behind <details>, which needs no JS. A page with no
        script is a page with nothing for injected markup to reach even if an
        escape were missed — so this is defence in depth, and it is only
        defence in depth while it stays true."""
        self.task(body=self.HOSTILE)
        html = self.page()
        self.assertNotIn("<script", html.lower())
        self.assertIn("<details>", html)

    def test_the_page_declares_a_locked_down_csp(self):
        self.assertIn("default-src 'none'", self.page())

    def test_every_body_states_its_author_next_to_the_text(self):
        """Attribution is structural, not a caption at the top of the page
        that an operator scrolls past: the block containing the body carries
        the author."""
        self.task(body="do the thing")
        html = self.page()

        block = re.search(r'<div class="body">(.*?)</div>\s*</details>', html, re.S)
        self.assertIsNotNone(block, "a body should render inside a body block")
        self.assertIn("Written by analyst", block.group(1))
        self.assertIn("not a statement by the router", block.group(1))

    def test_a_namespace_mode_recipient_says_the_whole_document_is_agent_writable(self):
        cfg = make_peer_config(self, {
            "a": {"peers": ["b"]},
            "b": {"peers": ["a"], "mode": "namespace"},
        })
        write_request(cfg, "a", "00000001", to=[addr("b")], body_text="mail body")
        outbound.drain_instance(cfg, "a")

        msg = console.gather(cfg)["messages"][0]
        self.assertTrue(msg["spool_agent_writable"])
        self.assertIn("agent-writable", console.render_html(cfg))


class HonestAbsenceTests(_ConsoleTestCase):
    """A fact this router cannot see renders as UNKNOWN, never as nothing.

    The documents here are the adapter's real `--host-facts` shape: schema,
    generated_ts, exit_meaning, and phases carrying claims and verdicts. This
    console reads those verdicts and recomputes none of them.
    """

    def facts_doc(self, *, phases=None, meaning="ok", age=0, schema=2, **extra):
        doc = {"schema": schema, "generated_ts": _ts(-age),
               "generated_by": "amap-sandy.py verify", "exit_status": 0,
               "exit_meaning": meaning, "phases": phases or []}
        doc.update(extra)
        return self.host_facts(doc)

    @staticmethod
    def container_phase(*results, unrunnable="", skipped="", reason=""):
        # `id` is schema 2's stable name, not bringup's phase number. The
        # positional ids "8.1"/"8.2" were a POSITION IN A PROGRAM, and that
        # program is deleted; an id that outlives its program is stable and
        # meaningless at once.
        #
        # `skipped`/`unrunnable` have no producer under schema 2 and stay here
        # only to drive the console branches that are likewise kept-unreachable.
        check = lambda i, r: {"claim": f"claim {i}", "result": r,
                              "remedy": f"remedy {i}",
                              **({"reason": reason} if reason and r == "UNKNOWN" else {})}
        return {"id": "router-container", "title": "the router's container",
                "skipped": skipped, "unrunnable": unrunnable,
                "checks": [check(i, r) for i, r in enumerate(results)]}

    def test_without_host_facts_the_container_state_is_unknown_not_omitted(self):
        html = self.page()
        self.assertIn("Container", html)
        self.assertIn("unknown", html.lower())

    def test_without_host_facts_not_enrolled_is_unanswered_not_empty(self):
        """The trap: rendering "none" for a question this router cannot
        answer tells an operator their fleet policy is clean when nothing
        checked it. `not_enrolled` is INVISIBLE here — a sandbox that was
        never enrolled appears in no config of mine."""
        data = console.gather(self.cfg)
        self.assertFalse(data["excluded"]["not_enrolled_known"])
        self.assertIsNone(data["excluded"]["not_enrolled"])
        self.assertIn("UNANSWERED", self.page())

    def test_host_facts_present_but_carrying_no_enrolment_list_stay_unanswered(self):
        """The v1 document reports VERDICTS, not data: there is no
        `not_enrolled` field in it yet. Present facts must not be mistaken
        for an answer to a question they do not contain — that would be the
        same false green in a new place."""
        path = self.facts_doc(phases=[self.container_phase("PASS")])
        data = console.gather(self.cfg, host_facts_path=path)

        self.assertTrue(data["host"]["available"])
        self.assertFalse(data["excluded"]["not_enrolled_known"])
        self.assertIn("UNANSWERED", self.page(host_facts_path=path))

    def test_a_named_enrolment_list_is_used_when_the_document_carries_one(self):
        """The field the adapter shipped — named by its SHAPE rather than by
    their sha, which this repo cannot resolve — in the shape pinned for
        it before it existed."""
        path = self.facts_doc(phases=[self.container_phase("PASS")],
                              not_enrolled=["orchard-1a2b3c4d"])
        data = console.gather(self.cfg, host_facts_path=path)

        self.assertTrue(data["excluded"]["not_enrolled_known"])
        self.assertEqual(data["excluded"]["not_enrolled"], ["orchard-1a2b3c4d"])
        self.assertIn("orchard-1a2b3c4d", self.page(host_facts_path=path))

    def test_an_empty_enrolment_list_answers_none_and_is_not_unanswered(self):
        """ABSENT AND `[]` ARE DIFFERENT ANSWERS, and this is the half that
        was missing: absence was pinned, a populated list was pinned, empty
        was not.

        The adapter OMITS the field when the lookup failed and emits `[]`
        when genuinely nothing is excluded, so `[]` is a real answer and must
        render as "none" — not as UNANSWERED, which would hide a clean result
        behind a question mark, and not by being confused with absence, which
        would manufacture a clean bill of health out of a failed lookup.

        Note this test and the absence test above are OPPOSITE MUTATIONS by
        construction: a change that treats `[]` as unknown fails this one and
        leaves that one green, and a change that treats absence as `[]` does
        the reverse. Neither can be satisfied by the other's condition, which
        is the property the `cannot_run` test was missing."""
        path = self.facts_doc(phases=[self.container_phase("PASS")],
                              not_enrolled=[])
        data = console.gather(self.cfg, host_facts_path=path)

        self.assertTrue(data["excluded"]["not_enrolled_known"],
                        "an emitted empty list is an answer, not a silence")
        self.assertEqual(data["excluded"]["not_enrolled"], [])
        html = self.page(host_facts_path=path)
        self.assertNotIn("UNANSWERED", html)
        self.assertIn("none", html)

    def test_a_passing_container_phase_reads_as_healthy(self):
        path = self.facts_doc(phases=[self.container_phase("PASS", "PASS")])
        self.assertIn("container healthy", self.page(host_facts_path=path))

    def test_a_failing_check_makes_the_container_not_healthy(self):
        """FAIL beats UNKNOWN beats PASS — one failing claim is a failing
        phase, whatever else passed."""
        path = self.facts_doc(phases=[self.container_phase("PASS", "FAIL")])
        html = self.page(host_facts_path=path)
        self.assertIn("container NOT healthy", html)
        self.assertIn("remedy 1", html, "a failing check must show its remedy")

    def test_an_unknown_check_is_not_a_pass(self):
        path = self.facts_doc(phases=[self.container_phase("PASS", "UNKNOWN")])
        self.assertIn("container state unknown", self.page(host_facts_path=path))

    def test_cannot_run_is_its_own_state_and_not_folded_into_either_neighbour(self):
        """The adapter's word for "this read produced no verdict". Rendering
        it as healthy is the false green the arrangement exists to refuse;
        rendering it as broken raises an alarm about something nobody
        looked at."""
        path = self.facts_doc(meaning="cannot_run",
                              phases=[self.container_phase("UNKNOWN")])
        html = self.page(host_facts_path=path)

        # The PILL specifically, not merely the words somewhere on the page:
        # the banner below says something similar, and asserting on prose that
        # two different elements can satisfy pins neither of them. (Found by
        # mutation: removing the pill's branch left this test green.)
        self.assertIn('<span class="pill unk">check could not run</span>', html)
        self.assertIn("neither a pass nor a failure", html)
        self.assertNotIn("container healthy", html)
        self.assertNotIn("container NOT healthy", html)
        self.assertNotIn("container state unknown", html)

    def test_declined_is_its_own_state_too(self):
        path = self.facts_doc(meaning="declined")
        self.assertIn("check declined", self.page(host_facts_path=path))

    def test_an_unrunnable_phase_is_distinguished_from_a_check_that_ran(self):
        """A phase that examined nothing and a check that examined something
        and could not tell call for different action, so they do not share a
        word."""
        path = self.facts_doc(phases=[
            self.container_phase(unrunnable="docker not found on PATH")])
        html = self.page(host_facts_path=path)

        self.assertIn("unrunnable", html)
        self.assertIn("docker not found on PATH", html)

    def test_stale_host_facts_are_marked_stale_rather_than_shown_as_current(self):
        """The symmetric lesson to status.json outliving its container: a
        --check that ran two hours ago describes a container that may since
        have died."""
        path = self.facts_doc(phases=[self.container_phase("PASS")],
                              age=2 * console.HOST_FACTS_STALE_SECONDS)
        self.assertTrue(console.load_host_facts(path)["stale"])
        html = self.page(host_facts_path=path)
        self.assertIn("container was healthy", html)
        self.assertNotIn("container healthy", html)

    def test_host_facts_without_a_timestamp_are_refused(self):
        """An undated container fact is exactly the 'existence alone is
        worthless' case, so it is refused rather than rendered as current."""
        path = self.host_facts({"schema": 2, "exit_meaning": "ok", "phases": []})
        facts = console.load_host_facts(path)
        self.assertFalse(facts["available"])
        self.assertIn("generated_ts", facts["reason"])

    def test_an_unrecognised_schema_is_refused_rather_than_guessed_at(self):
        """Field names carry meaning. Reading a future document by assuming
        this one's meanings is how a console reports confidently about
        something it does not understand.

        DERIVED from the constant, not written as a literal. This test said
        `schema=2` until the schema-2 adoption made 2 the understood one and
        the test started asserting that a document we now read is refused.
        `+ 1` means "one past whatever we understand", which is the claim,
        and it survives the next bump without anyone remembering to edit it.
        """
        unknown = console.HOST_FACTS_SCHEMA + 1
        path = self.facts_doc(schema=unknown,
                              phases=[self.container_phase("PASS")])
        facts = console.load_host_facts(path)
        self.assertFalse(facts["available"])
        self.assertIn("schema", facts["reason"])
        self.assertIn("unknown", self.page(host_facts_path=path).lower())

    def test_poll_age_and_container_state_are_presented_as_two_facts(self):
        path = self.facts_doc(phases=[self.container_phase("PASS")])
        html = self.page(host_facts_path=path)
        self.assertIn("Drain loop", html)
        self.assertIn("two facts, not one light", html)


class CounterCellTests(_ConsoleTestCase):
    """Three states in one column, and only one of them is a number.

    A fleet of fifty agents where three are talking renders as a wall of
    zeros, and the rows carrying the signal are lost in it. So zero is blank.
    But blank must then mean zero and nothing else, which is what makes the
    third state necessary rather than fussy.
    """

    def poll(self, cfg=None):
        """One real poll, which is what writes `status.json` — `run_once`
        drains but records nothing, so a test that only drains leaves every
        counter unobserved."""
        service.poll_once(cfg or self.cfg, StatusTracker())

    def instance_row(self, name: str) -> str:
        html = self.page()
        row = html.split(f"<td class='mono'>{name}</td>", 1)[1]
        return row.split("</tr>", 1)[0]

    def test_a_nonzero_counter_shows_its_number(self):
        self.queue()
        self.poll()
        self.assertIn(">1<", self.instance_row("analyst"),
                      "a counter with traffic must show the count")

    def test_a_zero_counter_is_blank_not_a_zero(self):
        """The whole point: on a real fleet the quiet agents are the
        majority, and their zeros bury the few rows that matter."""
        self.queue()
        self.poll()
        row = self.instance_row("lonely")
        self.assertIn("<td class='num'></td>", row,
                      "a zero counter should render empty")
        self.assertNotIn(">0<", row)

    def test_an_unpolled_instance_is_a_dot_not_a_blank_and_not_a_zero(self):
        """THE BUG THIS FOUND. `totals.get(key, 0)` rendered 0 for an
        instance that had never been polled, which is indistinguishable from
        one polled a thousand times that did nothing — and with `status.json`
        absent it rendered a whole table of zeros reading as "all quiet" when
        the truth was "nothing has been observed".

        Now: no status entry renders `·`, which is neither the blank that
        means zero nor a number. Same absent-versus-empty distinction as
        `not_enrolled`, in a third place."""
        row = self.instance_row("analyst")  # never polled: no `run`/`run_once`
        self.assertIn("·", row, "an unobserved counter must not read as zero")
        self.assertNotIn(">0<", row)
        self.assertNotIn("<td class='num'></td>", row,
                         "unobserved must not render as the blank that means zero")

    def test_a_status_entry_with_no_counters_reads_as_unobserved(self):
        """"Observed" means there ARE counters, not that a key exists.

        Unreachable through `record_poll`, which always writes a full
        `totals` — but reachable from a status.json written by an older
        version or edited by hand, and that file is just a file on disk. An
        entry with no counters has nothing to report, which is not the same
        as counters that are zero.

        This exists because the mutation that swapped these two spellings
        survived: they are identical for every document this router
        produces, so nothing could tell them apart until a test fed the
        document that distinguishes them."""
        self.queue()
        self.poll()
        status_path = self.cfg.state_dir / "status.json"
        doc = json.loads(status_path.read_text())
        doc["instances"]["lonely"]["totals"] = {}
        status_path.write_text(json.dumps(doc))

        row = self.instance_row("lonely")
        self.assertIn("·", row, "no counters means nothing to report, not zero")
        self.assertNotIn("<td class='num'></td>", row)

    def test_the_legend_distinguishes_blank_from_the_dot(self):
        """A convention the reader cannot see is not a convention. Both
        meanings are stated, and stated as different things."""
        html = self.page()
        self.assertIn("A blank counter is zero", html)
        self.assertIn("A dot (·) is not zero", html)

    def test_polled_and_unpolled_rows_are_distinguishable_in_one_table(self):
        """The states have to be told apart side by side, not just each on
        its own: this is the comparison an operator actually makes."""
        self.queue()
        self.poll()
        polled = self.instance_row("lonely")
        self.assertIn("<td class='num'></td>", polled, "polled and quiet is blank")
        self.assertNotIn("·", polled)

        # A fleet that has never been polled: every counter is a dot, and not
        # one of them is a zero or a blank.
        fresh = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        html = console.render_html(fresh)
        self.assertIn("·", html, "no instance has been polled, so all are dots")
        self.assertNotIn(">0<", html)
        self.assertNotIn("<td class='num'></td>", html)


class SlugNamespaceTests(HonestAbsenceTests):
    """`not_enrolled` carries SANDY SLUGS, which are a different namespace
    from router instance names.

    A slug is `name-<hash>` with whatever characters the workspace path
    produced; an instance name is derived from one by lowercasing and
    replacing everything outside `[a-z0-9-]`. They coincide for most
    sandboxes and diverge for any slug with uppercase, `_` or `.` — 9 of 42
    on the operator's box. Both land in one column of the excluded table, so
    the page has to say which is which.

    The slugs below are SYNTHETIC, and deliberately so. They carry the shapes
    the derivation rule has to survive — uppercase, `_`, an already-legal
    name — over hashes that identify no workspace. What this test protects is
    the RULE against awkward string shapes, and a shape is a property of a
    string rather than of anyone's machine, so real slugs bought it nothing
    and disclosed a live path hash for each one.
    """

    SLUGS = ["MixedCase_repo-0badcafe", "snake_case_lab-c0ffee01",
             "already-legal-deadbeef"]
    #: what `instance_name_for_slug` WOULD produce — never rendered by this page
    WOULD_DERIVE_TO = ["mixedcase-repo-0badcafe", "snake-case-lab-c0ffee01"]

    def enrolled_page(self):
        return self.page(host_facts_path=self.facts_doc(
            phases=[self.container_phase("PASS")], not_enrolled=self.SLUGS))

    def test_slugs_render_verbatim(self):
        html = self.enrolled_page()
        for slug in self.SLUGS:
            self.assertIn(slug, html)

    def who_cell(self, sense: str) -> str:
        """The `who` cell of one row of the excluded table, alone.

        EVERY assertion in this class is scoped to a single cell, and both
        reasons are worth keeping. Asserting over the whole page missed in
        two different directions within one sitting: once answered by an
        explanatory paragraph that used a real-looking derived name as an
        illustration, and once answered by a SECOND ROW that emitted the same
        label, so blanking the first row's label left the test green. Same
        defect both times — an assertion satisfied by output it was not
        pinning — and per-cell scoping is what removes it."""
        html = self.enrolled_page()
        row = html.split(f"<b>{sense}</b>", 1)[1]
        return re.findall(r"<td>(.*?)</td>", row, re.S)[0]

    def not_enrolled_cell(self) -> str:
        return self.who_cell("Not enrolled")

    def test_the_page_never_derives_an_instance_name_from_a_slug(self):
        """Two reasons, and either alone is sufficient. A not-enrolled
        sandbox HAS no instance — nothing in router.json, nothing under
        state_dir — so a derived name would invent an identity for something
        that deliberately has none. And the derivation does not disambiguate:
        two slugs can produce one name, so a derived match can land on the
        wrong row."""
        cell = self.not_enrolled_cell()
        for slug in self.SLUGS:
            self.assertIn(slug, cell)
        for derived in self.WOULD_DERIVE_TO:
            self.assertNotIn(derived, cell,
                             f"the page derived {derived!r} from a slug")

    def test_the_slug_column_says_no_router_instance_exists(self):
        self.assertIn("no router instance exists", self.enrolled_page())

    def test_instance_name_rows_are_labelled_as_instance_names(self):
        """The other two senses list instance names, and saying so is what
        keeps the reader from reading all three rows as one namespace.

        Asserted PER ROW. Both rows carry the same label, so a page-wide
        assertion is satisfied by either one and pins neither — blanking the
        first row's label left exactly that version of this test green."""
        for sense in ("No edge", "Never polled"):
            with self.subTest(sense=sense):
                self.assertIn("router instance names", self.who_cell(sense),
                              f"the {sense!r} row does not say which namespace "
                              f"its identifiers are in")

    def test_the_page_explains_that_two_namespaces_share_the_column(self):
        html = self.enrolled_page()
        self.assertIn("Two namespaces share that column", html)
        self.assertIn("no instance name at all", html)

    def test_slugs_are_sorted_case_insensitively(self):
        """The adapter emits `sorted()`, which puts capitalised slugs ahead of
        lowercase ones, and said the order is not part of the contract. A
        column where `MixedCase_repo` sorts above `snake_case_lab` reads as though
        the case meant something."""
        html = self.enrolled_page()
        positions = [html.index(s) for s in
                     ["already-legal-deadbeef", "MixedCase_repo-0badcafe",
                      "snake_case_lab-c0ffee01"]]
        self.assertEqual(positions, sorted(positions),
                         "slugs should read a… M… s…, not M… a… s…")

    def test_a_slug_cannot_inject_markup(self):
        """Slugs come from workspace paths by way of another repo's document.
        They are display strings on this page like any other."""
        path = self.facts_doc(phases=[self.container_phase("PASS")],
                              not_enrolled=["<img src=x onerror=alert(1)>-deadbeef"])
        html = self.page(host_facts_path=path)
        self.assertNotIn("<img", html.lower())
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;-deadbeef", html)


class PhaseVerdictTests(unittest.TestCase):
    """`phase_verdict` aggregates the adapter's results and recomputes none
    of them."""

    @staticmethod
    def phase(*results, **kw):
        return {"id": "8.1", "checks": [{"result": r} for r in results], **kw}

    def test_all_pass_is_pass(self):
        self.assertEqual(console.phase_verdict(self.phase("PASS", "PASS")), "pass")

    def test_any_fail_is_fail_even_beside_unknown(self):
        self.assertEqual(
            console.phase_verdict(self.phase("PASS", "UNKNOWN", "FAIL")), "fail")

    def test_any_unknown_without_a_fail_is_unknown(self):
        self.assertEqual(console.phase_verdict(self.phase("PASS", "UNKNOWN")), "unknown")

    def test_unrunnable_wins_over_its_checks(self):
        self.assertEqual(
            console.phase_verdict(self.phase("PASS", unrunnable="no docker")),
            "unrunnable")

    def test_a_phase_with_no_checks_is_unknown_not_pass(self):
        """An empty check list examined nothing; "nothing failed" is not the
        same as "everything passed"."""
        self.assertEqual(console.phase_verdict({"id": "8.1", "checks": []}), "unknown")


class ExcludedTests(_ConsoleTestCase):
    """Three senses, three remedies, kept apart."""

    def test_an_instance_with_no_counterpart_is_listed_under_no_edge(self):
        data = console.gather(self.cfg)
        self.assertIn("lonely", data["excluded"]["no_edge"])
        self.assertNotIn("analyst", data["excluded"]["no_edge"])
        self.assertNotIn("coder", data["excluded"]["no_edge"])

    def test_an_instance_this_router_has_never_polled_is_listed_as_such(self):
        """No first-sight marker means no poll has ever reached the root. It
        is a separate sense from "no edge": `b` here HAS an edge."""
        cfg = make_peer_config(
            self, {"a": {}, "b": {"peer_senders": ["a"]}}, seen=False)
        self.assertEqual(sorted(console.gather(cfg)["excluded"]["never_polled"]),
                         ["a", "b"])

    def test_a_polled_instance_is_not_listed_as_never_polled(self):
        """The control. Without it, a `gather` that listed every instance
        unconditionally would pass the test above."""
        cfg = make_peer_config(self, {"a": {}, "b": {"peer_senders": ["a"]}})
        self.assertEqual(console.gather(cfg)["excluded"]["never_polled"], [])

    def test_the_three_senses_name_three_different_remedies(self):
        """The point of separating them: a page that blends the senses sends
        an operator to re-render a config when the fix was to start the
        drainer."""
        html = self.page()
        self.assertIn("router --config C once", html)
        self.assertIn("peer_senders", html)
        self.assertIn("fleet policy", html)


class DisplayOnlyTests(_ConsoleTestCase):
    def test_rendering_writes_nothing_and_caches_nothing(self):
        """Display only, like `peers.py`: recomputed every call, with no
        cache anyone could later mistake for a ledger."""
        self.task()
        before = {p: p.stat().st_mtime_ns
                  for p in self.tmp.rglob("*") if p.is_file()}

        console.render_html(self.cfg)
        console.gather(self.cfg)

        after = {p: p.stat().st_mtime_ns
                 for p in self.tmp.rglob("*") if p.is_file()}
        self.assertEqual(before, after, "the console wrote or touched something")

    def test_an_unreadable_body_is_reported_not_raised(self):
        """A body that cannot be read is a body the page reports as
        unavailable; it is not an error that takes the console down."""
        self.task()
        spool = next((self.cfg.instances["coder"].peer_root / "messages").glob("*.json"))
        spool.unlink()

        msg = console.gather(self.cfg)["messages"][0]
        self.assertFalse(msg["body_available"])
        self.assertIn("body not available", self.page())

    def test_an_oversized_body_is_truncated_rather_than_withheld(self):
        self.task(body="x" * 5000)
        data = console.gather(self.cfg, body_cap=100)
        msg = data["messages"][0]
        self.assertTrue(msg["body_truncated"])
        self.assertEqual(len(msg["body_text"]), 100)


if __name__ == "__main__":
    unittest.main()


class SchemaTwoCapturedDocumentTests(_ConsoleTestCase):
    """Built from FOUR documents captured on the operator's host, not from a
    description of their shape.

    The adapter offered a description and this console asked for captures
    instead. The difference paid immediately: `reason` is documented as "free
    text, possibly multi-line", a sentence already read and not acted on, and
    only a real two-line value showed that rendering it into a plain `.note`
    collapses the newline and joins two speakers into one run-on sentence.

    HOST VALUES ARE NOT REPRODUCED HERE. The real capture's reason carried an
    absolute path including a username; the structural property under test is
    the NEWLINE, not the path, so these fixtures are synthetic. A test fixture
    is a tracked file, and a live host path in one is the same defect as a
    live workspace digest in one.
    """

    def _doc(self, **extra):
        doc = {"schema": 2, "generated_ts": _ts(0),
               "generated_by": "amap-sandy.py verify", "exit_status": 0,
               "exit_meaning": "ok", "phases": []}
        doc.update(extra)
        return self.host_facts(doc)

    def test_a_multi_line_reason_keeps_its_line_break(self):
        """Capture 3. The defect this class exists for."""
        reason = "run.sh: 4 mount(s) derived from <config>\nCannot connect to the daemon."
        path = self._doc(exit_meaning="failed", phases=[{
            "id": "router-container", "title": "the router's container",
            "checks": [{"claim": "the router container is running",
                        "result": "UNKNOWN",
                        "remedy": "fix the docker connection first",
                        "reason": reason}]}])
        html = self.page(host_facts_path=path)
        # The reason is rendered AT ALL...
        self.assertIn("Cannot connect to the daemon.", html)
        # ...and in a container that preserves the break. Asserting only the
        # text would pass with the newline collapsed, which is the whole bug.
        self.assertIn("class='reason'", html)
        self.assertIn("white-space:pre-wrap", html)
        self.assertIn("derived from &lt;config&gt;\nCannot connect", html)

    def test_an_all_unknown_document_is_failed_not_cannot_run(self):
        """Capture 3's boundary, agreed with the producer: `failed` means
        something is wrong and the checks say what — INCLUDING when every
        check is UNKNOWN, because "could not tell" is not a clean bill.
        `cannot_run` is reserved for a read that produced no verdict at all.
        """
        path = self._doc(exit_meaning="failed", phases=[{
            "id": "router-container", "title": "the router's container",
            "checks": [{"claim": "c", "result": "UNKNOWN", "reason": "r"}]}])
        html = self.page(host_facts_path=path)
        self.assertNotIn("could not run", html)
        self.assertIn("unknown", html.lower())

    def test_cannot_run_with_no_phases_never_reads_as_health(self):
        """Capture 4: `exit_status` 2, `phases: []`, and NO `not_enrolled`
        key at all, because the lookups never happened. This is the document
        that must not resemble a clean bill in any corner of the page."""
        path = self._doc(exit_meaning="cannot_run", exit_status=2)
        html = self.page(host_facts_path=path)
        self.assertIn("could not run", html)
        self.assertIn("neither a pass", html)
        self.assertIn("reported no phases", html)
        self.assertNotIn("container healthy", html)

    def test_empty_not_enrolled_is_none_excluded_absent_is_unanswered(self):
        """Captures 1-3 carry `not_enrolled: []` — the TRUE empty, a policy
        that excludes nobody. Capture 4 omits the key. Distinguished
        structurally (is it a list?), never by truthiness, because collapsing
        them is how a console manufactures a clean bill of health."""
        empty = self.page(host_facts_path=self._doc(not_enrolled=[]))
        self.assertIn("none", empty)
        self.assertNotIn("UNANSWERED", empty)

        absent = self.page(host_facts_path=self._doc())
        self.assertIn("UNANSWERED", absent)

    def test_a_phase_may_carry_any_number_of_checks(self):
        """Capture 3's health phase has ONE check where capture 1 has seven:
        the section stops at its first claim because everything after it
        needed a document docker could not fetch. A renderer assuming a fixed
        count, or diffing against the previous run's list, breaks here."""
        path = self._doc(exit_meaning="failed", phases=[
            {"id": "router-health", "title": "the router's health",
             "checks": [{"claim": "only one", "result": "FAIL", "remedy": "r"}]}])
        html = self.page(host_facts_path=path)
        self.assertIn("only one", html)
        self.assertIn("router-health", html)
