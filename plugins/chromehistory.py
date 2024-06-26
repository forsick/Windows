import datetime

import volatility3.framework.layers.scanners as scan
from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers
from volatility3.framework.exceptions import PagedInvalidAddressException

import volatility3.plugins.sqlite_help as sqlite_help

FORWARD = sqlite_help.FORWARD
BACKWARD = sqlite_help.BACKWARD

def map_transition(t):
    """Map the 32-bit integer transition t to the multiple transition types it represents"""
    transition = ""
    if (t & 0xFF) == 0:
        transition += "LINK;"
    if (t & 0xFF) == 1:
        transition += "TYPED;"
    if (t & 0xFF) == 2:
        transition += "BOOKMARK;"
    if (t & 0xFF) == 3:
        transition += "AUTO_SUBFRAME;"
    if (t & 0xFF) == 4:
        transition += "MANUAL_SUBFRAME;"
    if (t & 0xFF) == 5:
        transition += "GENERATED;"
    if (t & 0xFF) == 6:
        transition += "START_PAGE;"
    if (t & 0xFF) == 7:
        transition += "FORM_SUBMIT;"
    if (t & 0xFF) == 8:
        transition += "RELOAD-RESTORE-UNDO_CLOSE;"
    if (t & 0xFF) == 9:
        transition += "KEYWORD;"
    if (t & 0xFF) == 10:
        transition += "KEYWORD_GENERATED;"

    if (t & 0x03000000) == 0x03000000:
        transition += "FORWARD_BACK_FROM_ADDRESS_BAR;"
    elif (t & 0x03000000) == 0x01000000:
        transition += "FORWARD_BACK;"
    elif (t & 0x03000000) == 0x02000000:
        transition += "FROM_ADDRESS_BAR;"

    if (t & 0x04000000) == 0x04000000:
        transition += "HOME_PAGE;"

    if (t & 0x30000000) == 0x30000000:
        transition += "CHAIN_START_END;"
    elif (t & 0x30000000) == 0x10000000:
        transition += "CHAIN_START;"
    elif (t & 0x30000000) == 0x20000000:
        transition += "CHAIN_END;"

    if (t & 0xC0000000) == 0xC0000000:
        transition += "CLIENT_SERVER_REDIRECT;"
    elif (t & 0xC0000000) == 0x40000000:
        transition += "CLIENT_REDIRECT;"
    elif (t & 0xC0000000) == 0x80000000:
        transition += "SERVER_REDIRECT;"

    return transition

class ChromeHistory(interfaces.plugins.PluginInterface):
    """Scans for and parses potential Chrome url history"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Memory layer for the kernel", 
                architectures=["Intel32", "Intel64"]
            ),
            requirements.BooleanRequirement(
                name="nulltime", 
                description="Don't print entries with null timestamps", 
                default=False, 
                optional=True
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        physical_layer_name = self.context.layers[kernel.layer_name].config.get(
            "memory_layer", None
        )
        layer = self.context.layers[physical_layer_name]
        needles=[
                    b'\x08http', 
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
                ]
        urls = {}
        
        for offset, _value in layer.scan(
            context=self.context,
            scanner=scan.MultiStringScanner(patterns=needles),
        ):
            try:
                chrome_buff = layer.read(offset - 15, 4500)
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
            # We cannot have a negative row_id (index)
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

            urls[int(offset)] = (
                                int(row_id),
                                str(url), 
                                str(title), 
                                int(visit_count), 
                                int(typed_count), 
                                last_visit_time
                                )
            
        seen_tuples = set()
        for value in urls.values():
            if value not in seen_tuples:
                seen_tuples.add(value)
                yield 0, (value[0], value[1], value[2], value[3], value[4], value[5])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Index", int), 
                ("URL", str), 
                ("Title", str), 
                ("Visit Count", int),
                ("Typed Count", int), 
                ("Last Visit Time", datetime.datetime)
            ], 
            self._generator()
        )
    
class ChromeDownloads(interfaces.plugins.PluginInterface):
    """Scans for and parses potential Chrome download records"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Memory layer for the kernel", 
                architectures=["Intel32", "Intel64"]
            ),
            requirements.BooleanRequirement(
                name="nulltime", 
                description="Don't print entries with null timestamps", 
                default=False, 
                optional=True
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        physical_layer_name = self.context.layers[kernel.layer_name].config.get(
            "memory_layer", None
        )
        layer = self.context.layers[physical_layer_name]
        needles=[
                    b'\x01\x01\x01',
                ]
        downloads = {}
        
        for offset, _value in layer.scan(
            context=self.context,
            scanner=scan.MultiStringScanner(patterns=needles),
        ):
            try:
                chrome_buff = layer.read(offset - 16, 3000)
            except PagedInvalidAddressException as e:
                print(f"Unable to read page at offset {offset}: {e}")
                continue

            start = 16
            if chrome_buff[19] not in (1, 6) and chrome_buff[20] != 1:
                continue

            good = False

            # get all of the single byte lengths around the needle
            (start_time_length, start_time) = sqlite_help.varint_type_to_length(chrome_buff[start-3])
            (received_bytes_length, received_bytes) = sqlite_help.varint_type_to_length(chrome_buff[start-2])
            (total_bytes_length, total_bytes) = sqlite_help.varint_type_to_length(chrome_buff[start-1])
            (state_length, state) = sqlite_help.varint_type_to_length(chrome_buff[start])
            (danger_type_length, danger_type) = sqlite_help.varint_type_to_length(chrome_buff[start+1])
            (interrupt_reason_length, intterupt_reason) = sqlite_help.varint_type_to_length(chrome_buff[start+2])
            (end_time_length, end_time) = sqlite_help.varint_type_to_length(chrome_buff[start+3])
            (opened_length, opened) = sqlite_help.varint_type_to_length(chrome_buff[start+4])

            # go backwards from needle first
            start -= 4

            # times should be 8 bytes, might be 1 byte if time is empty, including 6 bytes just in case
            if start_time_length not in (1, 6, 8) or end_time_length not in (1, 6, 8):
                continue

            if received_bytes_length not in range (0,7) or total_bytes_length not in range (0, 7):
                continue

            (target_path_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            target_path_length = sqlite_help.varint_to_text_length(target_path_length)
            if target_path_length < 0 or target_path_length > 1024:
                continue
            start -= varint_len

            (current_path_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            current_path_length = sqlite_help.varint_to_text_length(current_path_length)
            if current_path_length < 0 or current_path_length > 1024:
                continue
            start -= varint_len

            (id_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            if id_length < 0 or id_length > 1024000:
                continue
            start -= varint_len

            (payload_header_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            if payload_header_length < 0 or payload_header_length > 1024000:
                continue
            start -= varint_len
            payload_header_start = start + 1

            (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            start -= varint_len

            (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            start -= varint_len

            # jump to after opened_length needle match and go forward
            start = 21

            (referrer_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
            referrer_length = sqlite_help.varint_to_text_length(referrer_length)
            start += varint_len

            # check that the full record length is still longer than the total of some of the longer fields
            if payload_length < payload_header_length + current_path_length + target_path_length + referrer_length:
                continue

            # For the next 6 fields:
            #   if the last fields in the record are null, the fields are sometimes not included at all
            #   so check if the current position (start) minus the start of the header is greater
            #   than the size specifed in payload_header_length
            if start - payload_header_start >= payload_header_length:
                by_ext_id_length = 0
            else:
                (by_ext_id_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                by_ext_id_length = sqlite_help.varint_to_text_length(by_ext_id_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                by_ext_name_length = 0
            else:
                (by_ext_name_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                by_ext_name_length = sqlite_help.varint_to_text_length(by_ext_name_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                etag_length = 0
            else:
                (etag_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                etag_length = sqlite_help.varint_to_text_length(etag_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                last_modified_length = 0
            else:
                (last_modified_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                last_modified_length = sqlite_help.varint_to_text_length(last_modified_length)
                start += varint_len

            # the mime_type related fields are new to chrome 37, but can be handled the same way
            if start - payload_header_start >= payload_header_length:
                mime_type_length = 0
            else:
                (mime_type_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                mime_type_length = sqlite_help.varint_to_text_length(mime_type_length)
                start += varint_len

            if start - payload_header_start >= payload_header_length:
                original_mime_type_length = 0
            else:
                (original_mime_type_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, FORWARD)
                original_mime_type_length = sqlite_help.varint_to_text_length(original_mime_type_length)
                start += varint_len

            # end of the payload header.  check that the length found matches the value in the length field
            payload_header_end = start
            if payload_header_length != payload_header_end - payload_header_start:
                continue

            # id field is 0 because it is actually stored in row_id above
            start += id_length

            current_path_length = int(current_path_length)
            target_path_length = int(target_path_length)
            referrer_length = int(referrer_length)
            etag_length = int(etag_length)
            last_modified_length = int(last_modified_length)
            by_ext_id_length = int(by_ext_id_length)
            by_ext_name_length = int(by_ext_name_length)

            current_path = chrome_buff[start:start+current_path_length]
            start += current_path_length
            current_path = current_path.decode('utf-8', errors='ignore')

            target_path = chrome_buff[start:start+target_path_length]
            start += target_path_length
            target_path = target_path.decode('utf-8', errors='ignore')

            # extract the time, unpack it to an integer, convert microseconds to string
            start_time = chrome_buff[start:start+start_time_length]
            start_time = sqlite_help.sql_unpack(start_time)
            if str(start_time) < str(11900000000000000) or str(start_time) > str(17000000000000000):
                continue
            start_time = sqlite_help.get_wintime_from_msec(start_time)
            start += start_time_length

            received_bytes = chrome_buff[start:start+received_bytes_length]
            received_bytes = sqlite_help.sql_unpack(received_bytes)
            start += received_bytes_length

            total_bytes = chrome_buff[start:start+total_bytes_length]
            total_bytes = sqlite_help.sql_unpack(total_bytes)
            start += total_bytes_length

            state =(chrome_buff[start:start+state_length])
            start += state_length
            state = state.decode('utf-8', errors='ignore')

            danger_type =(chrome_buff[start:start+danger_type_length])
            start += danger_type_length
            danger_type = danger_type.decode('utf-8', errors='ignore')

            interrupt_reason =(chrome_buff[start:start+interrupt_reason_length])
            start += interrupt_reason_length
            interrupt_reason = interrupt_reason.decode('utf-8', errors='ignore')

            # extract the time, unpack it to an integer, convert microseconds to string
            end_time = chrome_buff[start:start+end_time_length]
            end_time = sqlite_help.sql_unpack(end_time)
            end_time = sqlite_help.get_wintime_from_msec(end_time)
            start += end_time_length

            opened =(chrome_buff[start:start+opened_length])
            start += opened_length
            opened = opened.decode('utf-8', errors='ignore')

            referrer = chrome_buff[start:start+referrer_length]
            start += referrer_length
            referrer = referrer.decode('utf-8', errors='ignore')

            by_ext_id = ""
            if by_ext_id_length:
                by_ext_id =(chrome_buff[start:start+by_ext_id_length])
            start += by_ext_id_length
            if type(by_ext_id) is bytes:
                by_ext_id = by_ext_id.decode('utf-8', errors='ignore')

            by_ext_name = ""
            if by_ext_name_length:
                by_ext_name = chrome_buff[start:start+by_ext_name_length]
            start += by_ext_name_length
            if type(by_ext_name) is bytes:
                by_ext_name = by_ext_name.decode('utf-8', errors='ignore')

            etag = ""
            start = int(start)
            if etag_length:
                etag = chrome_buff[start:start+etag_length]
            start += etag_length
            if type(etag) is bytes:
                etag = etag.decode('utf-8', errors='ignore')

            last_modified = ""
            if last_modified_length:
                last_modified = chrome_buff[start:start+last_modified_length]
            start += last_modified_length
            if type(last_modified) is bytes:
                last_modified = last_modified.decode('utf-8', errors='ignore')

            mime_type = ""
            if mime_type_length:
                mime_type = chrome_buff[start:start+mime_type_length]
            start += mime_type_length

            original_mime_type = ""
            if original_mime_type_length:
                original_mime_type = chrome_buff[start:start+original_mime_type_length]
            start += original_mime_type_length

            downloads[int(offset)] = (
                                    row_id,
                                    current_path, 
                                    target_path, 
                                    start_time, 
                                    received_bytes, 
                                    total_bytes, state, 
                                    danger_type, 
                                    interrupt_reason, 
                                    end_time, 
                                    opened, 
                                    referrer, 
                                    by_ext_id, 
                                    by_ext_name, 
                                    etag, 
                                    last_modified, 
                                    mime_type, 
                                    original_mime_type
                                    )

        seen_tuples = set()
        for value in downloads.values():
            if value not in seen_tuples:
                seen_tuples.add(value)
                yield 0, (value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15], value[16], value[17])

    def run(self):
        return renderers.TreeGrid(
            [
                ("row_id", int), 
                ("current_path", str), 
                ("target_path", str), 
                ("start_time", datetime.datetime),
                ("received_bytes", int), 
                ("total_bytes", int),
                ("state", str),
                ("danger_type", str),
                ("interrupt_reason", str),
                ("end_time", datetime.datetime),
                ("opened", str),
                ("referrer", str),
                ("by_ext_id", str),
                ("by_ext_name", str),
                ("etag", str),
                ("last_modified", str),
                ("mime_type", str),
                ("original_mime_type", str)
            ], 
            self._generator()
        )
    
class ChromeVisits(interfaces.plugins.PluginInterface):
    """Scans for and parses potential Chrome download records"""
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", 
                description="Memory layer for the kernel", 
                architectures=["Intel32", "Intel64"]
            ),
            requirements.BooleanRequirement(
                name="nulltime", 
                description="Don't print entries with null timestamps", 
                default=False, 
                optional=True
            ),
        ]

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        physical_layer_name = self.context.layers[kernel.layer_name].config.get(
            "memory_layer", None
        )
        layer = self.context.layers[physical_layer_name]
        needles=[
                    b'\x08\x00\x01\x06',
                    b'\x08\x00\x02\x06',
                    b'\x08\x00\x03\x06',
                    b'\x08\x00\x08\x06',
                    b'\x08\x00\x09\x06',
                    b'\x09\x00\x01\x06',
                    b'\x09\x00\x02\x06',
                    b'\x09\x00\x03\x06',
                    b'\x09\x00\x08\x06',
                    b'\x09\x00\x09\x06',
                ]
        visits = {}
        
        for offset, _value in layer.scan(
            context=self.context,
            scanner=scan.MultiStringScanner(patterns=needles),
        ):
            try:
                chrome_buff = layer.read(offset - 13, 150)
            except PagedInvalidAddressException as e:
                print(f"Unable to read page at offset {offset}: {e}")
                continue

             # sanity checks on a few other values
            if chrome_buff[17] not in (1, 2, 3, 8, 9):
                continue
            if chrome_buff[18] not in (4, 5):
                continue
            if chrome_buff[19] not in (1, 2, 3, 8, 9):
                continue

            # get the bytes around the needles, then work backwards
            payload_header_length = (chrome_buff[13])
            (visit_id_length, visit_id) = sqlite_help.varint_type_to_length(chrome_buff[14])
            (url_length, url) = sqlite_help.varint_type_to_length(chrome_buff[15])

            # row_id is before the payload_header_length
            start = 12
            (row_id, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)
            # can't have a negative row_id (index)
            if row_id < 0:
                continue

            # payload_length is length of sqlite record and the first item
            start -= varint_len
            if start < 0:
                continue
            (payload_length, varint_len) = sqlite_help.find_varint(chrome_buff, start, BACKWARD)

            # payload_length should be much longer than this, but this is a safe minimum
            if payload_length < 6:
                continue

            # get the remaining needle match and the next few single byte values
            (visit_time_length, visit_time) = sqlite_help.varint_type_to_length(chrome_buff[16])
            (from_visit_length, from_visit) = sqlite_help.varint_type_to_length(chrome_buff[17])
            (transition_length, transition) = sqlite_help.varint_type_to_length(chrome_buff[18])
            (segment_id_length, segment_id) = sqlite_help.varint_type_to_length(chrome_buff[19])

            # older versions of chrome don't have the is_indexed field
            if payload_header_length == 9:
                (is_indexed_length, is_indexed) = sqlite_help.varint_type_to_length(chrome_buff[20])
                (visit_duration_length, visit_duration) = sqlite_help.varint_type_to_length(chrome_buff[21])
                start = 22
            elif payload_header_length == 8:
                (visit_duration_length, visit_duration) = sqlite_help.varint_type_to_length(chrome_buff[20])
                start = 21
            else:
                continue

            # visit_id INTEGER
            visit_id = sqlite_help.sql_unpack(chrome_buff[start:start+visit_id_length])

            # url INTEGER (an id into the urls table)
            start += visit_id_length
            url = sqlite_help.sql_unpack(chrome_buff[start:start+url_length])

            # visit_time INTEGER
            start += url_length
            visit_time = sqlite_help.sql_unpack(chrome_buff[start:start+visit_time_length])
            visit_time = sqlite_help.get_wintime_from_msec(visit_time)
            if visit_time.year == 1601:
                continue

            # from_visit INTEGER
            start += visit_time_length
            from_visit = sqlite_help.sql_unpack(chrome_buff[start:start+from_visit_length])

            # transition INTEGER
            start += from_visit_length
            transition = sqlite_help.sql_unpack(chrome_buff[start:start+transition_length])

            # segment_id INTEGER
            start += transition_length
            segment_id = sqlite_help.sql_unpack(chrome_buff[start:start+segment_id_length])

            # is_index INTEGER
            start += segment_id_length
            if payload_header_length == 9:
                is_indexed = sqlite_help.sql_unpack(chrome_buff[start:start+is_indexed_length])

                # visit_duration INTEGER
                start += is_indexed_length
            if visit_duration_length:
                visit_duration = sqlite_help.sql_unpack(chrome_buff[start:start+visit_duration_length])

            # store all the fields as a tuple to eliminate printing duplicates
            if payload_header_length == 9:
                visits[int(offset)] = (row_id, url, visit_time, from_visit, map_transition(transition), segment_id, is_indexed, visit_duration)
            else:
                visits[int(offset)] = (row_id, url, visit_time, from_visit, map_transition(transition), segment_id, "n/a", visit_duration)

        seen_tuples = set()
        for value in visits.values():
            if value not in seen_tuples:
                seen_tuples.add(value)
                yield 0, (value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7])

    def run(self):
        return renderers.TreeGrid(
            [
                ("Visit ID", int), 
                ("URL ID", int), 
                ("Visit Time", datetime.datetime),
                ("From Visit", int), 
                ("Transition", str),
                ("Segment ID", int),
                ("Is Indexed", str),
                ("Visit Duration", int),
            ], 
            self._generator()
        )