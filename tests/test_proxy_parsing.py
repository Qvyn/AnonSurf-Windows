import unittest

from anonsurf_safe.http_socks_proxy import (
    Target,
    TargetBlockedError,
    parse_absolute_http_target,
    parse_connect_target,
    validate_target,
)


class ProxyParsingTests(unittest.TestCase):
    def test_connect_host_and_port(self):
        self.assertEqual(parse_connect_target("example.com:443"), Target("example.com", 443))

    def test_connect_ipv6(self):
        self.assertEqual(parse_connect_target("[::1]:8443"), Target("::1", 8443))

    def test_absolute_http_uri(self):
        target, path = parse_absolute_http_target("http://example.com/a?b=1", None)
        self.assertEqual(target, Target("example.com", 80))
        self.assertEqual(path, "/a?b=1")

    def test_origin_form_uses_host(self):
        target, path = parse_absolute_http_target("/index.html", "example.com")
        self.assertEqual(target, Target("example.com", 80))
        self.assertEqual(path, "/index.html")

    def test_public_targets_are_allowed(self):
        validate_target(Target("example.com", 443))
        validate_target(Target("1.1.1.1", 443))

    def test_private_and_local_targets_are_blocked(self):
        blocked = ("localhost", "printer.local", "127.0.0.1", "192.168.18.1", "::1", "fe80::1")
        for host in blocked:
            with self.subTest(host=host), self.assertRaises(TargetBlockedError):
                validate_target(Target(host, 443))


if __name__ == "__main__":
    unittest.main()
