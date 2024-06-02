from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.windows import pslist

import re


class UrlPlugin(interfaces.plugins.PluginInterface):
    """URL Plugin"""

    _required_framework_version = (2, 0, 0)

    _strings_regex = re.compile(b'[\x20-\x7E]+')
    _url_regex = re.compile(b'https?\:\/\/[a-zA-Z0-9\.\/\?\:@\-_=#]+\.[a-zA-Z]{2,6}[a-zA-Z0-9\.\&\/\?\:@\-_=#]*')

    @classmethod
    def get_requirements(self):
        return [
            requirements.TranslationLayerRequirement(
                name='primary',
                description='Memory layer for the kernel',
                architectures=['Intel32', 'Intel64']
            ),
            requirements.SymbolTableRequirement(
                name='nt_symbols',
                description='Windows kernel symbols'
            ),
            requirements.PluginRequirement(
                name='pslist',
                plugin=pslist.PsList,
                version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name='pid',
                description='Process ID to include (all other processes are excluded)',
                optional=True
            ),
            requirements.StringRequirement(
                name='pname',
                description='Process name to include (all other processes are excluded)',
                optional=True
            )
        ]

    def _generator(self, procs, pname):
        num = 0

        for proc in procs:
            proc_name = proc.ImageFileName.cast('string',
                                                max_length=proc.ImageFileName.vol.count,
                                                errors='replace')
            # if (proc_name == 'chrome.exe'):
            if pname and not pname.lower().startswith(proc_name.lower()):
                continue

            for vad in proc.get_vad_root().traverse():
                try:
                    proc_layer_name = proc.add_process_layer()
                    proc_layer = self.context.layers[proc_layer_name]

                    data_size = vad.get_end() - vad.get_start()
                    data = proc_layer.read(vad.get_start(), data_size, pad=True)

                    for string in self._strings_regex.findall(data):
                        for url in self._url_regex.findall(string):
                            yield (
                                0,  # level
                                (
                                    num,  # no
                                    proc.UniqueProcessId,  # pid
                                    proc_name,  # pname
                                    url.decode()  # url
                                )
                            )
                            num += 1
                except MemoryError:
                    comment = """
                                yield (
                                    0,
                                    (
                                        -1,
                                        proc.UniqueProcessId, 
                                        proc_name,
                                        '<Too large memory (pid: {}, size: 0x{:x} bytes)>'.format(proc.UniqueProcessId, data_size)
                                    )
                                )
                                """
                    pass

    def run(self):
        return renderers.TreeGrid(
            [
                # colums name and type
                ('no', int),
                ('pid', int),
                ('pname', str),
                ('url', str)
            ],
            self._generator(
                pslist.PsList.list_processes(
                    self.context,
                    self.config['primary'],
                    self.config['nt_symbols'],
                    filter_func=pslist.PsList.create_pid_filter(
                        [self.config.get('pid', None)]
                    )
                ),
                self.config.get('pname', None)
            )
        )