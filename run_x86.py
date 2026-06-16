from slothy import Slothy

import slothy.targets.x86_64.x86_64 as x86_64
import slothy.targets.x86_64.intel_atom as intel_atom

arch = x86_64
target = intel_atom

slothy = Slothy(arch, target)

# example
slothy.load_source_from_file("tests/naive/x86_64/x86_64_add.s")
slothy.config.variable_size=True
slothy.config.constraints.stalls_first_attempt=32
slothy.config._allow_useless_instructions = True

slothy.optimize()
slothy.write_source_to_file("opt/x86_64_add.s")