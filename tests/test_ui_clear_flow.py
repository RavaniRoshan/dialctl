import re
import unittest
from pathlib import Path

HTML = Path(__file__).resolve().parent.parent / "web" / "index.html"


class TestClearDataFlow(unittest.TestCase):
    """Static checks on the clear-data flow: it must close the DB before delete,
    treat `onblocked` as incomplete, and reopen storage afterwards."""

    def setUp(self):
        self.text = HTML.read_text(encoding="utf-8")

    def test_clear_closes_db_before_delete(self):
        # The clear handler must close the open connection before deleting.
        handler = self._function_body("clearLocalAuditData")
        self.assertIn("db.close()", handler)

    def test_onblocked_not_treated_as_success(self):
        handler = self._function_body("clearLocalAuditData")
        self.assertNotIn("req.onblocked = () => resolve()", handler)
        # onblocked must resolve to an explicit blocked state, not plain success
        self.assertIn("onblocked", handler)
        self.assertIn("blocked", handler)

    def test_clear_handler_reopens_storage(self):
        # After clearing, the handler must reopen the DB for subsequent use.
        self.assertIn("db = await openDb()", self.text)

    def _function_body(self, name):
        lines = self.text.splitlines()
        start = next(i for i, l in enumerate(lines) if l.strip().startswith(f"function {name}"))
        depth = 0
        for i in range(start, len(lines)):
            depth += lines[i].count("{") - lines[i].count("}")
            if depth == 0 and i > start:
                return "\n".join(lines[start : i + 1])
        raise AssertionError(f"function {name} not fully brace-matched")


if __name__ == "__main__":
    unittest.main()