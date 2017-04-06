import unittest

import datetime

from features import parse_log_line, FeatureExtractor, MostActiveIntervalExtractor, AccessViolationDetector, compile_regexp


class FeaturesTest(unittest.TestCase):
    def test_parse_line_base_case(self):
        host, timestamp, http_method, resource, reply_code, reply_bytes =\
            parse_log_line('210.238.40.43 - - [01/Jul/1995:00:00:09 -0400] "GET / HTTP/1.0" 200 7074', compile_regexp())

        self.assertEqual(host, '210.238.40.43')
        self.assertEqual(timestamp, datetime.datetime(year=1995, month=7, day=1, second=9))
        self.assertEqual(resource, '/')
        self.assertEqual(reply_code, 200)
        self.assertEqual(reply_bytes, 7074)

    def test_parse_line_handles_404(self):
        input_line = 'pm55.smartlink.net - - [03/Jul/1995:02:46:42 -0400] "GET /shuttle/missions/technology/sts-newsref/stsref-toc.html HTTP/1.0" 404 -'
        # check that bytes == 0
        host, timestamp, http_method, resource, reply_code, reply_bytes = \
            parse_log_line(input_line, compile_regexp())
        self.assertEqual(reply_bytes, 0)

    def test_parse_line_handles_multiple_quotes(self):
        input_line = 'frank.mtsu.edu - - [03/Jul/1995:02:41:15 -0400] "GET /images/" HTTP/1.0" 404 -'
        host, timestamp, http_method, resource, reply_code, reply_bytes = \
            parse_log_line(input_line, compile_regexp())
        self.assertEqual(resource, "/images/\"")

    def test_parse_line_handles_missing_http_method(self):
        input_line = 'www-b6.proxy.aol.com - - [04/Jul/1995:19:27:09 -0400] "/shuttle/countdown/count.gif HTTP/1.0" 200 40310'
        host, timestamp, http_method, resource, reply_code, reply_bytes = \
            parse_log_line(input_line, compile_regexp())
        self.assertEqual(resource, "/shuttle/countdown/count.gif")

    def test_parse_line_handles_all_http_version_names(self):
        input_line = '209.116.34.89 - - [28/Jul/1995:13:30:15 -0400] "GET /shuttle/missions/51-l/51-l-info.html HTTP/V1.0" 200 1387'
        host, timestamp, http_method, resource, reply_code, reply_bytes = \
            parse_log_line(input_line, compile_regexp())
        self.assertEqual(resource, "/shuttle/missions/51-l/51-l-info.html")

    def test_parse_line_handles_lines_without_http_method_and_version(self):
        input_line = '209.116.34.89 - - [28/Jul/1995:13:30:15 -0400] "/shuttle/missions/51-l/51-l-info.html" 200 1387'
        host, timestamp, http_method, resource, reply_code, reply_bytes = \
            parse_log_line(input_line, compile_regexp())
        self.assertEqual(resource, "/shuttle/missions/51-l/51-l-info.html")


class FeatureExtractorTest(unittest.TestCase):
    def test_extractor_correctly_returns_top_elements(self):
        extractor = FeatureExtractor(count_to_report=2)

        for i in range(0, 10):
            name = 'name{}'.format(i)
            for j in range(0, i):
                extractor.process(name, 1)
        self.assertEqual(extractor.top_elements_report(), [(9, 'name9'), (8, 'name8')])

    def test_extractor_uses_lexicographical_sort(self):
        extractor = FeatureExtractor(count_to_report=4)

        for i in range(9, 0, -1):
            name = 'name{}'.format(i)
            for j in range(0, 2*(i//2)):
                extractor.process(name, 1)
        self.assertEqual(extractor.top_elements_report(), [(8, 'name8'), (8, 'name9'), (6, 'name6'), (6, 'name7')])

    def test_extractor_correctly_handles_custom_increment(self):
        extractor = FeatureExtractor(count_to_report=3)

        for i in range(0, 10):
            name = 'name{}'.format(i)
            for j in range(0, i):
                extractor.process(name, i**2)
        self.assertEqual(extractor.top_elements_report(), [(729, 'name9'), (512, 'name8'), (343, 'name7')])


class MostActiveIntervalExtractorTest(unittest.TestCase):
    def test_extractor_finds_busiest_interval(self):
        extractor = MostActiveIntervalExtractor(count_to_report=2, interval=3600)
        timestamp_list = [datetime.datetime(1995, 7, 1, 0, 0, 1)]
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 6))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 9))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 11))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 12))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 13))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 14))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 14))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 15))
        timestamp_list.append(datetime.datetime(1995, 7, 1, 0, 0, 15))


        for timestamp in timestamp_list:
            extractor.process(timestamp)
        expected_list = [(10, datetime.datetime(1995, 7, 1, 0, 0, 1)),
                         (9, datetime.datetime(1995, 7, 1, 0, 0, 2))]

        x = extractor.most_active_intervals()
        print(x)
        self.assertEqual(x, expected_list)


class AccessViolationDetectorTest(unittest.TestCase):
    def test_no_logging_when_successful_login_after_two_failed(self):
        timestamp = datetime.datetime.now()
        logger = AccessViolationDetector(max_login_attempts=3, time_interval=20, access_block_interval=300)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 200))

    def test_successful_login_resets_failed_counter(self):
        timestamp = datetime.datetime.now()
        logger = AccessViolationDetector(max_login_attempts=3, time_interval=20, access_block_interval=300)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))

        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 200))

        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))

    def test_different_hosts_are_tracked_separately(self):
        timestamp = datetime.datetime.now()
        logger = AccessViolationDetector(max_login_attempts=3, time_interval=20, access_block_interval=300)
        self.assertTrue(logger.process('host1', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host1', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host2', timestamp, 401))
        self.assertTrue(logger.process('host2', timestamp, 401))

    def test_hosts_are_blocked_after_failed_attempts(self):
        timestamp = datetime.datetime.now()
        logger = AccessViolationDetector(max_login_attempts=3, time_interval=20, access_block_interval=300)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=299)
        self.assertFalse(logger.process('host', timestamp, 200))

    def test_only_one_host_is_blocked(self):
        timestamp = datetime.datetime.now()
        logger = AccessViolationDetector(max_login_attempts=3, time_interval=20, access_block_interval=300)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))
        self.assertTrue(logger.process('host2', timestamp, 200))
        timestamp += datetime.timedelta(seconds=299)
        self.assertFalse(logger.process('host', timestamp, 200))
        self.assertTrue(logger.process('host2', timestamp, 200))

    def test_access_restored_after_specified_interval(self):
        timestamp = datetime.datetime.now()
        logger = AccessViolationDetector(max_login_attempts=3, time_interval=20, access_block_interval=300)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=1)
        self.assertTrue(logger.process('host', timestamp, 401))
        timestamp += datetime.timedelta(seconds=299)
        self.assertFalse(logger.process('host', timestamp, 200))
        timestamp += datetime.timedelta(seconds=1, microseconds=1)
        self.assertTrue(logger.process('host', timestamp, 200))