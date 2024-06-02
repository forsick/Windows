import logging
from typing import List

from volatility3.framework import renderers, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import intel

vollog = logging.getLogger(__name__)

class AbstractWindowsCommand(plugins.PluginInterface):
    @staticmethod
    def is_valid_profile(profile):
        return profile.metadata.get('os', 'unknown') == 'windows'

class AbstractScanCommand(AbstractWindowsCommand):
    """A command built to provide the common options that should be available to Volatility's various scanning plugins."""

    # This is a list of scanners to use
    scanners = []

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"]
            ),
            requirements.SymbolTableRequirement(
                name='nt_symbols',
                description='Windows kernel symbols'
            ),
            requirements.BooleanRequirement(
                name="virtual",
                description="Scan virtual space instead of physical",
                default=False,
                optional=True
            ),
            requirements.BooleanRequirement(
                name="show_unallocated",
                description="Show unallocated objects",
                default=False,
                optional=True
            ),
            requirements.IntRequirement(
                name="start",
                description="The starting address to begin scanning",
                optional=True
            ),
            requirements.IntRequirement(
                name="length",
                description="Length (in bytes) to scan from the starting address",
                optional=True
            )
        ]

    def __init__(self, context: interfaces.context.ContextInterface, config: interfaces.configuration.HierarchicalDict, progress_callback = None, file_handler = None):
        super().__init__(context, config, progress_callback, file_handler)

    def calculate(self):
        addr_space = self.context.layers[self.config["primary"]]
        if not self.is_valid_profile(addr_space.profile):
            vollog.error("This command does not support the selected profile.")
        return self.scan_results(addr_space)

    def offset_column(self):
        return "Offset(V)" if self.config.get("virtual", False) else "Offset(P)"

    def scan_results(self, addr_space):
        use_top_down = (addr_space.profile.metadata.get("major", 0) == 6 and addr_space.profile.metadata.get("minor", 0) >= 2)

        multiscan = intel.Intel(context=self.context, config=self.config, progress_callback=self._progress_callback)
        return multiscan.scan()

def pool_align(vm, object_name, align):
    """Returns the size of the object accounting for pool alignment."""
    size_of_obj = vm.profile.get_obj_size(object_name)

    # Size is rounded to pool alignment
    extra = size_of_obj % align
    if extra:
        size_of_obj += align - extra

    return size_of_obj
