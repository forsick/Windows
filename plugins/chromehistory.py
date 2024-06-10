import sys
import volatility3.framework.layers.scanners as scan
from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers
from volatility3.framework.exceptions import PagedInvalidAddressException
import volatility3.plugins.sqlite_help as sqlite_help

FORWARD = sqlite_help.FORWARD
BACKWARD = sqlite_help.BACKWARD

class ChromeScanner(scan.MultiStringScanner):
    def __init__(self, needles=None):
        if needles is None:
            needles = []
        self.needles = needles
        super().__init__(needles)

    def scan(self, context, layer_name):
        layer = context.layers[layer_name]
        for result in layer.scan(scanner=self, context=context):
            yield result

    def _generator(self):
        for needle in self.needles:
            yield scan.BytesScanner(needle)

class ChromeHistory(interfaces.plugins.PluginInterface):
    """ Scans for and parses potential Chrome url history"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.BooleanRequirement(name="nulltime", description="Don't print entries with null timestamps", default=True, optional=True),
            requirements.TranslationLayerRequirement(name="primary", description="Memory layer for the kernel", architectures=["Intel32", "Intel64"]),
        ]

    def __init__(self, context, config, *args, **kwargs):
        super().__init__(context, config, *args, **kwargs)

    def calculate(self):
        address_space = self.context.layers[self.config["primary"]]

        # URLs
        scanner = ChromeScanner(needles=[b'\x08http',
                                         b'\x08file',
                                         b'\x08ftp',
                                         b'\x08chrome',
                                         b'\x08data',
                                         b'\x08about',
                                         b'\x01\x01http',
                                         b'\x01\x01file',
                                         b'\x01\x01ftp',
                                         b'\x01\x01chrome',
                                         b'\x01\x01data',
                                         b'\x01\x01about',
                                         ])
        urls = {}
        for offset, _ in scanner.scan(self.context, self.config["primary"]):
            try:
                chrome_buff = address_space.read(offset - 15, 4500)
            except PagedInvalidAddressException as e:
                print(f"Unable to read page at offset {offset}: {e}")
                continue

            start = 15
            favicon_id = "N/A"
            favicon_id_length = 0

            # start before the needle match and work backwards, do sanity checks on some values before proceeding
            if chrome_buff[start - 1] not in (1, 6):
                continue
            start -= 1
            (last_visit_time_length, last_visit_time) = sqlite_help.varint_type_to_length(chrome_buff[start])

            if not (0 < chrome_buff[start - 1] < 10):
                continue
            start -= 1
            typed_count = None
            if chrome_buff[start] in (8, 9):
                (typed_count_length, typed_count) = sqlite_help.varint_type_to_length(chrome_buff[start])
            else:
                typed_count_length = chrome_buff[start]

            if not (0 < chrome_buff[start - 1] < 10):
                continue
            start -= 1
            visit_count = None
            if chrome_buff[start] in (8, 9):
                (visit_count_length, visit_count) = sqlite_help.varint_type_to_length(chrome_buff[start])
            else:
                visit_count_length = chrome_buff[start]

            start -= 1
            (title_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            title_length = int(sqlite_help.varint_to_text_length(int(title_length)))

            start -= varint_len
            (url_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            url_length = int(sqlite_help.varint_to_text_length(int(url_length)))

            start -= varint_len
            url_id_length = chrome_buff[start]

            start -= 1
            payload_header_length = chrome_buff[start]
            payload_header_end = start + payload_header_length

            start -= 1
            (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            # can't have a negative row_id (index)
            if row_id < 0:
                continue

            start -= varint_len
            if start < 0:
                continue
            (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

            # payload_length should be much longer than this, but this is a safe minimum
            if payload_length < 6:
                continue

            # jump back to the index of the needle match
            start = 15
            (hidden_length, hidden) = sqlite_help.varint_type_to_length(chrome_buff[start])
            start += 1
            if start != payload_header_end:
                (favicon_id_length, favicon_id) = sqlite_help.varint_type_to_length(chrome_buff[start])
                start += 1

            start += url_id_length
            url = chrome_buff[start:start + url_length]
            url = url.decode('utf-8', errors='ignore')

            start += url_length
            title = chrome_buff[start:start + title_length]
            title = title.decode('utf-8', errors='ignore')

            start += title_length
            if visit_count is None:
                visit_count = sqlite_help.sql_unpack(chrome_buff[start:start + visit_count_length])

            start += visit_count_length
            if typed_count is None:
                typed_count = sqlite_help.sql_unpack(chrome_buff[start:start + typed_count_length])

            # extract the time, unpack it to an integer, convert microseconds to string
            start += typed_count_length
            last_visit_time = chrome_buff[start:start + last_visit_time_length]
            last_visit_time = sqlite_help.sql_unpack(last_visit_time)
            if type(last_visit_time) is str:
                continue
            last_visit_time = sqlite_help.get_wintime_from_msec(last_visit_time)
            if last_visit_time.year == 1601 and self.config['nulltime'] == False:
                continue

            start += last_visit_time_length
            hidden = sqlite_help.sql_unpack(chrome_buff[start:start + hidden_length])

            start += hidden_length
            if favicon_id_length > 0:
                favicon_id = sqlite_help.sql_unpack(chrome_buff[start:start + favicon_id_length])

            urls[int(offset)] = (int(row_id),
                                str(url), str(title), int(visit_count), int(typed_count), last_visit_time)

        for url in urls.values():
            yield url

    def _generator(self):
        for item in self.calculate():
            yield item

    def run(self):
        data = list(self._generator())
        self.render_text(sys.stdout, data)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("Index", "6"), ("URL", "80"), ("Title", "80"), ("Visits", "6"), ("Typed", "5"), ("Last Visit Time", "26")])
        for index, url, title, visit_count, typed_count, last_visit_time in data:
            self.table_row(outfd, index, url, title, visit_count, typed_count, str(last_visit_time))

    def table_header(self, outfd, column_headers):
        outfd.write(" | ".join(header[0].ljust(int(header[1])) for header in column_headers) + "\n")
        outfd.write("-+-".join('-' * int(header[1]) for header in column_headers) + "\n")

    def table_row(self, outfd, *columns):
        outfd.write(" | ".join(str(col).ljust(len) for col, len in zip(columns, [6, 80, 80, 6, 5, 26])) + "\n")
