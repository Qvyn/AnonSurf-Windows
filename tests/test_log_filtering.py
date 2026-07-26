from unittest import TestCase
from unittest.mock import patch

from anonsurf_safe.http_socks_proxy import HTTPToSocksBridge
from anonsurf_safe.tor_controller import TorController


class LogFilteringTests(TestCase):
    def test_duplicate_code_four_is_limited_for_ten_minutes(self):
        messages: list[str] = []
        bridge = HTTPToSocksBridge(19051, 19050, logger=messages.append)
        error = "Tor could not reach the destination (destination unreachable, SOCKS code 4)"

        with patch(
            "anonsurf_safe.http_socks_proxy.time.monotonic",
            side_effect=[0, 599, 601],
        ):
            bridge._log_expected_error(error)
            bridge._log_expected_error(error)
            bridge._log_expected_error(error)

        self.assertEqual(len(messages), 2)
        self.assertTrue(
            all("No direct connection was attempted" in item for item in messages)
        )

    def test_duplicate_scrubbed_tor_notice_is_hidden(self):
        noisy = (
            "Jul 25 20:57:19.000 [notice] Have tried resolving or connecting "
            "to address '[scrubbed]' at 3 different places. Giving up."
        )
        self.assertFalse(TorController.should_display_log_line(noisy))
        self.assertTrue(
            TorController.should_display_log_line(
                "Jul 25 20:57:03.000 [notice] Bootstrapped 100% (done): Done"
            )
        )
