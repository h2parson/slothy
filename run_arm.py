from slothy import Slothy

import slothy.targets.aarch64.aarch64_neon as arm
import slothy.targets.aarch64.cortex_a55 as a55

arch = arm
target = a55

slothy = Slothy(arch, target)

# example
slothy.load_source_from_file("tests/naive/aarch64/aarch64_add.s")
slothy.config.variable_size=True
slothy.config.constraints.stalls_first_attempt=32
slothy.config._allow_useless_instructions = True

slothy.optimize()
slothy.write_source_to_file("opt/aarch64_add.s")