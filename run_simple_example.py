from slothy import Slothy

import slothy.targets.aarch64.aarch64_neon as AArch64_Neon
import slothy.targets.aarch64.cortex_a55 as Target_CortexA55

arch = AArch64_Neon
target = Target_CortexA55

slothy = Slothy(arch, target)

# example
slothy.load_source_from_file("tests/naive/aarch64/aarch64_stack.s")
slothy.config.variable_size=True
slothy.config.constraints.stalls_first_attempt=32
slothy.config._allow_useless_instructions = True
slothy.config._outputs.add("STACK0")
slothy.config.selfcheck=False
slothy.config.selftest=False

slothy.optimize()
slothy.write_source_to_file("opt/aarch64_stack.s")