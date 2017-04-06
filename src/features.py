from collections import defaultdict
from datetime import datetime, timedelta

import sys
import re
import heapq


DATE_FORMAT = '%d/%b/%Y:%H:%M:%S -0400'

def report_item_compare(left, right):
    '''Override compare method for pair (metrics, frequency)'''
    if left[0] > right[0]:
        return -1
    if left[0] < right[0]:
        return 1
    if right[1] > left[1]:
        return -1
    if right[1] < left[1]:
        return 1
    return 0


class FeatureExtractor:
    '''Produces reports of top N elements
    (used to produce reports for host/IP frequency, the most reached resources)'''
    def __init__(self, count_to_report):
        self.count_to_report = count_to_report
        self.table = defaultdict(int)

    def process(self, metrics, increment=1):
        '''process metrics'''
        self.table[metrics] += increment

    def top_elements_report(self):
        '''forms sorted list of top elements '''
        heap_arr = []
        if len(self.table) < self.count_to_report:
            return sorted([(value, key) for key, value in self.table.items()], reverse = True)

        for key, value in self.table.items()[:self.count_to_report]:
            heapq.heappush(heap_arr, (value, key))

        for key, value in self.table.items()[self.count_to_report:]:
            if value > heap_arr[0][0]:
                heapq.heapreplace(heap_arr, (value, key))

        return sorted(heap_arr, cmp=report_item_compare)

    def write_file(self, file, write_counts=False):
        '''write report file'''
        sorted_list = self.top_elements_report()
        with open(file, 'w') as fileobject:
            for key, value in sorted_list:
                line = value
                if write_counts:
                    line = line + ',' + str(key)
                fileobject.write(line + '\r\n')


class MostActiveIntervalExtractor:
    '''identify the busiest time period on the site'''
    def __init__(self, count_to_report, interval):
        self.count_to_report = count_to_report
        self.timestamp_heap = []
        self.interval = timedelta(seconds=interval)
        self.request_history = []
        self.start_time = None

    def process(self, timestamp):
        '''process incoming log timestamp'''
        if not self.start_time:
            self.start_time = timestamp
        #if the timestamp is out of limit, then process data in request history,
        # consider them as possible candidate to top busiest periods list
        while timestamp - self.start_time > self.interval:
            self.move_interval()
        self.request_history.append(timestamp)

    def move_interval(self):
        '''move the current time period to top busiest list if it satisfies
         and set the next current time period'''
        num = len(self.request_history)
        if len(self.timestamp_heap) < self.count_to_report:
            heapq.heappush(self.timestamp_heap, (num, self.start_time))
        elif self.timestamp_heap[0][0] < num:
            heapq.heapreplace(self.timestamp_heap, (num, self.start_time))
        self.start_time += timedelta(seconds=1)
        while self.request_history and self.request_history[0] < self.start_time:
            self.request_history.pop(0)

    def most_active_intervals(self):
        '''forms sorted list of the busiest periods'''
        for i in range(0, self.count_to_report):
            if not self.request_history:
                break
            self.move_interval()
        return sorted(self.timestamp_heap, cmp=report_item_compare)

    def write_file(self, file):
        '''write report file'''
        sorted_timestamps = self.most_active_intervals()
        with open(file, 'w') as fileobject:
            need_newline = False
            for freq, timestamp in sorted_timestamps:
                if need_newline:
                    fileobject.write('\r\n')
                line = timestamp.strftime(DATE_FORMAT) + ',' + str(freq)
                fileobject.write(line)
                need_newline = True

class AccessViolationDetector:
    '''Monitors potential security breaches by detecting patters of N failed login attempts
    from the same IP/host over K seconds.'''

    def __init__(self, max_login_attempts, time_interval, access_block_interval):
        self.max_login_attempts = max_login_attempts
        self.time_interval = timedelta(seconds=time_interval)
        self.access_block_interval = timedelta(seconds=access_block_interval)
        self.failed_login_counter = defaultdict(list)
        self.blocked_hosts = {}

    def process(self, host, timestamp, reply_code):
        '''identify if the host is already blocked'''
        if host in self.blocked_hosts:
            block_time = self.blocked_hosts[host]
            if timestamp - block_time > self.access_block_interval:
                # host is no longer blocked, then remove it from blocked list
                del self.blocked_hosts[host]
                return True
            return False
        #failed attempt
        if reply_code == 401:
            failed_attempts = self.failed_login_counter[host]
            failed_attempts.append(timestamp)

            #removing failed attempts that are no longer relevant
            while failed_attempts and (timestamp - failed_attempts[0]) > self.time_interval:
                failed_attempts.pop(0)

            if len(failed_attempts) >= self.max_login_attempts:
                self.blocked_hosts[host] = timestamp
        elif reply_code == 200:
            #reset failed login counter after a successful login. note that this code
            #   is not executed if a host is already blocked
            if host in self.failed_login_counter:
                self.failed_login_counter[host] = []
        return True


def compile_regexp():
    '''regular expression for line parsing'''
    regexp_pat = r'^(\S+) - - \[(\d{2}\/[a-zA-Z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} -\d{4})\] \"' \
                 r'(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH )?(.*)\" (\d+) (\d+|-)$'

    return re.compile(regexp_pat)


def parse_log_line(line, compiled_regexp):
    '''Decomposes a single line of server logs.
    Parameters:
       line: single line of server logs, expected format:
        host - - [timestamp] "(optional: request-method) request-uri (optional: http method)" reply-code reply-bytes
    Returns:
        tuple of host, timestamp, request method, request uri, http method, reply code, reply bytes '''

    result = compiled_regexp.match(line)
    if not result:
        raise RuntimeError('Incorrect format of input data: ' + line)

    host, timestamp, http_method, resource, reply_code, reply_bytes = result.groups()
    try:
        reply_bytes = int(reply_bytes)
    except ValueError:
        reply_bytes = 0

    timestamp = datetime.strptime(timestamp, DATE_FORMAT)

    parts = resource.split()
    resource = parts[0]

    return host, timestamp, http_method, resource, int(reply_code), reply_bytes


def main():
    #Default parameters
    log_file = 'log.txt'
    host_file = 'hosts.txt'
    resources_file = 'resources.txt'
    hours_file = 'hours.txt'
    blocked_file = 'blocked.txt'
    #Input parameters
    if len(sys.argv) == 6:
        log_file = sys.argv[1]
        host_file = sys.argv[2]
        hours_file = sys.argv[3]
        resources_file = sys.argv[4]
        blocked_file = sys.argv[5]
    #Init extractors for all features
    host_extractor = FeatureExtractor(count_to_report=10)
    resources_extractor = FeatureExtractor(count_to_report=10)
    active_intervals_extractor = MostActiveIntervalExtractor(count_to_report=10, interval=3600)
    access_violation_detector = AccessViolationDetector(max_login_attempts=3, time_interval=20, access_block_interval=300)

    regexp = compile_regexp()
    # Reading log file
    with open(log_file) as fileobject, open(blocked_file, 'w') as blocked_log_file:
        for line in fileobject:
            #Processing line
            try:
                host, timestamp, http_method, resource, reply_code, reply_bytes = parse_log_line(line, regexp)

                host_extractor.process(host)
                resources_extractor.process(resource, reply_bytes)
                active_intervals_extractor.process(timestamp)
                if not access_violation_detector.process(host, timestamp, reply_code):
                    blocked_log_file.write(line)
            except RuntimeError as e:
                sys.stderr.write('Malformed input: ' + line)
        #Writing report files
        host_extractor.write_file(file=host_file, write_counts=True)
        resources_extractor.write_file(file=resources_file)
        active_intervals_extractor.write_file(file=hours_file)


if __name__ == '__main__':
    main()
