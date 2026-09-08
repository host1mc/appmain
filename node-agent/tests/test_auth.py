import unittest

from node_agent import auth


class AgentAuthTests(unittest.TestCase):
    def test_bearer_token_is_compared_without_accepting_missing_or_wrong_tokens(self):
        self.assertTrue(hasattr(auth, "authorized"), "authorized is not implemented")

        self.assertTrue(auth.authorized("Bearer secret-token", "secret-token"))
        self.assertFalse(auth.authorized("Bearer wrong", "secret-token"))
        self.assertFalse(auth.authorized("", "secret-token"))
        self.assertFalse(auth.authorized("Bearer secret-token", ""))


if __name__ == "__main__":
    unittest.main()
