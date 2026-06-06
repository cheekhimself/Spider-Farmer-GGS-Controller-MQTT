import unittest

from verdant_integration.ble_stream import FragmentedJsonStreamParser


class FragmentedParserTests(unittest.TestCase):
    def test_reassembles_fragmented_json(self) -> None:
        parser = FragmentedJsonStreamParser()
        part1 = b"\x01\x02garbage{\"method\":\"getDevSta\",\"data\":{\"sensor\":"
        part2 = b"{\"temp\":23.3,\"humi\":37.7,\"vpd\":1.78},\"fan\":{\"level\":5,\"on\":1}}}"

        self.assertEqual(parser.feed(part1), [])
        parsed = parser.feed(part2)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0]["data"]["sensor"]["temp"], 23.3)
        self.assertEqual(parsed[0]["data"]["fan"]["level"], 5)

    def test_multiple_json_messages_in_single_chunk(self) -> None:
        parser = FragmentedJsonStreamParser()
        payload = '{"a":1}{"b":2}'
        parsed = parser.feed(payload)
        self.assertEqual(parsed, [{"a": 1}, {"b": 2}])

    def test_overflow_resets_but_keeps_latest_json_start(self) -> None:
        parser = FragmentedJsonStreamParser(max_buffer_chars=20)
        parser.feed("noise-noise-noise")
        parsed = parser.feed('{"ok":1}')
        self.assertEqual(parsed, [{"ok": 1}])


if __name__ == "__main__":
    unittest.main()
