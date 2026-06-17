from enum import Enum
from slothy.helper import lookup_multidict
from slothy.targets.x86_64.x86_64 import (
    find_class,
    add_hi,
    add_si,
    add_di,
    add_qi,
    add_hh,
    add_ss,
    add_dd,
    add_qq,
)

issue_rate = 2
llvm_mca_target = "intel-atom"

class ExecutionUnit(Enum):
    """Enumeration of execution units in intel Atom model"""

    ALU0 = 1
    ALU1 = 2
    MUL  = 3
    DIV  = 4
    MEM  = 5
    FP0  = 6
    FP1  = 7

    def __repr__(self):
        return self.name

    @classmethod
    def SCALAR(cls):
        """All scalar execution units"""
        return [ExecutionUnit.ALU0, ExecutionUnit.ALU1]

    @classmethod
    def SCALAR_MUL(cls):
        """All multiply-capable scalar execution units"""
        return [ExecutionUnit.MUL]


# Opaque function called by SLOTHY to add further microarchitecture-
# specific constraints which are not encapsulated by the general framework.
def add_further_constraints(slothy):
    if slothy.config.constraints.functional_only:
        return
    return

def has_min_max_objective(config):
    _ = config
    return False


def get_min_max_objective(slothy):
    _ = slothy
    return

execution_units = {
    (
        add_hi,
        add_si,
        add_di,
        add_qi,
        add_hh,
        add_ss,
        add_dd,
        add_qq,
    ): [
        ExecutionUnit.ALU0,
        ExecutionUnit.ALU1,
    ],
}

# TODO: Agner Fog says 1/2 for this. Make sure 1 is right
inverse_throughput = {
    (
        add_hi,
        add_si,
        add_di,
        add_qi,
        add_hh,
        add_ss,
        add_dd,
        add_qq,
    ): 1,
}

default_latencies = {
    (
        add_hi,
        add_si,
        add_di,
        add_qi,
        add_hh,
        add_ss,
        add_dd,
        add_qq,
    ): 1,
}


def get_latency(src, out_idx, dst):
    _ = out_idx
    _ = dst

    instclass_src = find_class(src)

    latency = lookup_multidict(default_latencies, src, instclass_src)

    return latency


def get_units(src):
    instclass_src = find_class(src)
    units = lookup_multidict(execution_units, src, instclass_src)
    if isinstance(units, list):
        return units
    return [units]


def get_inverse_throughput(src):
    instclass_src = find_class(src)
    return lookup_multidict(inverse_throughput, src, instclass_src)
