from __future__ import annotations

import unittest

from fasp_harness.platforms import local_model_profile, runtime_profile


class PlatformProfileTests(unittest.TestCase):
    def test_runtime_profile_is_non_identifying(self) -> None:
        profile = runtime_profile()
        self.assertIn(profile["os_family"], {"windows", "linux", "macos", "other"})
        self.assertIn("edge-safe", profile["profiles"])
        self.assertNotIn("serial", profile)
        self.assertNotIn("hostname", profile)

    def test_local_model_profile_is_policy_bound(self) -> None:
        self.assertTrue(local_model_profile()["requires_local_policy"])


if __name__ == "__main__":
    unittest.main()
