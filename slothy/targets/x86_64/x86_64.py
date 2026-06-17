import logging
import re
import math
from enum import Enum
from functools import cache
from sympy import simplify

from slothy.targets.exceptions import (
    FatalParsingException,
    UnknownInstruction,
    ParsingException,
)
from slothy.helper import Loop, SourceLine

# TODO: what is this for and can I make it work for x86
unicorn_arch = None
unicorn_mode = None

class RegisterType(Enum):
    GPR_H = 1
    GPR_S = 2
    GPR_D = 3
    GPR_Q = 4
    FLAGS = 2

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    @staticmethod
    @cache
    def spillable(reg_type):
        return reg_type in [RegisterType.GPR]  # For now, only GPRs

    @staticmethod
    def callee_saved_registers():
        return [f"x{i}" for i in range(18, 31)] + [f"v{i}" for i in range(8, 16)]
    
    @staticmethod
    @cache
    def list_byte_gprs():
        letter_labels = ['A','B','C','D']
        return [f"{p}L" for p in letter_labels] + \
                ['DIL','SIL'] + \
                [f"R{n}L" for n in range(8,16)]
    
    @staticmethod
    @cache
    def list_word_gprs():
        letter_labels = ['A','B','C','D']
        return [f"{p}X" for p in letter_labels] + \
                ['DI','SI'] + \
                [f"R{n}W" for n in range(8,16)]
    
    @staticmethod
    @cache
    def list_dblword_gprs():
        letter_labels = ['A','B','C','D']
        return [f"E{p}X" for p in letter_labels] + \
                ['EDI','ESI'] + \
                [f"R{n}D" for n in range(8,16)]
    
    @staticmethod
    @cache
    def list_qdword_gprs():
        letter_labels = ['A','B','C','D']
        return [f"R{p}X" for p in letter_labels] + \
                ['RDI','RSI'] + \
                [f"R{n}" for n in range(8,16)]

    @staticmethod
    @cache
    def list_registers(
        reg_type, only_extra=False, only_normal=False, with_variants=False
    ):
        """Return the list of all registers of a given type"""

        # TODO: add flags
        flags = []

        return {
            RegisterType.GPR_H: RegisterType.list_byte_gprs(),
            RegisterType.GPR_S: RegisterType.list_word_gprs(),
            RegisterType.GPR_D: RegisterType.list_dblword_gprs(),
            RegisterType.GPR_Q: RegisterType.list_qdword_gprs(),
            RegisterType.FLAGS: flags,
        }[reg_type]

    @staticmethod
    def find_type(r):
        """Find type of architectural register"""

        for ty in RegisterType:
            if r in RegisterType.list_registers(ty):
                return ty

        return None

    @staticmethod
    def is_renamed(ty):
        """Indicate if register type should be subject to renaming"""
        # if ty == RegisterType.HINT:
        #     return False
        return True

    @staticmethod
    def from_string(string):
        """Find register type from string"""
        string = string.lower()
        return {
            "gpr_h": RegisterType.GPR_H,
            "gpr_s": RegisterType.GPR_S,
            "gpr_d": RegisterType.GPR_D,
            "gpr_q": RegisterType.GPR_Q,
            "flags": RegisterType.FLAGS
        }.get(string, None)
    
    # TODO: fill this in
    @staticmethod
    def default_reserved():
        """Return the list of registers that should be reserved by default"""
        return set()
    
    @staticmethod
    def default_aliases():
        "Register aliases used by the architecture"
        return {}

class Instruction:
    def __init__(
        self, *, mnemonic, arg_types_in=None, arg_types_in_out=None, arg_types_out=None
    ):

        if arg_types_in is None:
            arg_types_in = []
        if arg_types_out is None:
            arg_types_out = []
        if arg_types_in_out is None:
            arg_types_in_out = []

        self.mnemonic = mnemonic

        self.args_out_combinations = None
        self.args_in_combinations = None
        self.args_in_out_combinations = None
        self.args_in_out_different = None
        self.args_in_inout_different = None

        self.arg_types_in = arg_types_in
        self.arg_types_out = arg_types_out
        self.arg_types_in_out = arg_types_in_out
        self.num_in = len(arg_types_in)
        self.num_out = len(arg_types_out)
        self.num_in_out = len(arg_types_in_out)

        self.args_out_restrictions = [None for _ in range(self.num_out)]
        self.args_in_restrictions = [None for _ in range(self.num_in)]
        self.args_in_out_restrictions = [None for _ in range(self.num_in_out)]

        self.args_in = []
        self.args_out = []
        self.args_in_out = []

        self.addr = None
        self.increment = None
        self.pre_index = None
        self.offset_adjustable = True

        self.immediate = None
        self.datatype = None
        self.index = None
        self.flag = None
        self.barrel = None

    def extract_read_writes(self):
        """Extracts 'reads'/'writes' clauses from the source line of the instruction"""

        src_line = self.source_line

        def hint_register_name(tag):
            return f"hint_{tag}"

        # Check if the source line is tagged as reading/writing from memory
        def add_memory_write(tag):
            self.num_out += 1
            self.args_out_restrictions.append(None)
            self.args_out.append(hint_register_name(tag))
            self.arg_types_out.append(RegisterType.HINT)

        def add_memory_read(tag):
            self.num_in += 1
            self.args_in_restrictions.append(None)
            self.args_in.append(hint_register_name(tag))
            self.arg_types_in.append(RegisterType.HINT)

        write_tags = src_line.tags.get("writes", [])
        read_tags = src_line.tags.get("reads", [])

        if not isinstance(write_tags, list):
            write_tags = [write_tags]

        if not isinstance(read_tags, list):
            read_tags = [read_tags]

        for w in write_tags:
            add_memory_write(w)

        for r in read_tags:
            add_memory_read(r)

        return self

    def global_parsing_cb(self, a, log=None):
        """Parsing callback triggered after DataFlowGraph parsing which allows
        modification of the instruction in the context of the overall computation.

        This is primarily used to remodel input-outputs as outputs in jointly destructive
        instruction patterns (See Section 4.4, https://eprint.iacr.org/2022/1303.pdf).
        """
        _ = log  # log is not used
        return False

    def global_fusion_cb(self, a, log=None):
        """Fusion callback triggered after DataFlowGraph parsing which allows fusing
        of the instruction in the context of the overall computation.

        This can be used e.g. to detect eor-eor pairs and replace them by eor3."""
        _ = log  # log is not used
        return False

    def write(self):
        """Write the instruction"""
        args = self.args_out + self.args_in_out + self.args_in
        return self.mnemonic + " " + ", ".join(args)

    def _is_instance_of(self, inst_list):
        for inst in inst_list:
            if isinstance(self, inst):
                return True
        return False

    # scalar or vector
    def is_load(self):
        """Indicates if an instruction is a load instruction"""
        return False

    def is_store(self):
        """Indicates if an instruction is a store instruction"""
        return False

    def is_load_store_instruction(self):
        """Indicates if an instruction is a scalar or Neon load or store instruction"""
        return self.is_load() or self.is_store()

    @classmethod
    def make(cls, src):
        """Abstract factory method parsing a string into an instruction instance."""

    @staticmethod
    def build(  # noqa: DOC103
        c: any, src: str, mnemonic: str, **kwargs: list
    ) -> "Instruction":
        """Attempt to parse a string as an instance of an instruction.

        :param c: The target instruction the string should be attempted to be parsed as.
        :type c: any
        :param src: The string to parse.
        :type src: str
        :param mnemonic: The mnemonic of instruction c
        :type mnemonic: str
        :param ``**kwargs``: Additional arguments to pass to the constructor of c.
        :type ``**kwargs``: list

        :return: Upon success, the result of parsing src as an instance of c.
        :rtype: Instruction

        :raises ParsingException: The str argument cannot be parsed as an
                instance of c.
        :raises FatalParsingException: A fatal error during parsing happened
                that's likely a bug in the model.
        """

        if src.split(" ")[0] != mnemonic:
            raise ParsingException("Mnemonic does not match")

        obj = c(mnemonic=mnemonic, **kwargs)

        expected_args = obj.num_in + obj.num_out + obj.num_in_out
        regexp_txt = rf"^\s*{mnemonic}"
        if expected_args > 0:
            regexp_txt += r"\s+"
        regexp_txt += ",".join([r"\s*(\w+)\s*" for _ in range(expected_args)])
        regexp = re.compile(regexp_txt)

        p = regexp.match(src)
        if p is None:
            raise ParsingException(
                f"Doesn't match basic instruction template {regexp_txt}"
            )

        operands = list(p.groups())

        if obj.num_out > 0:
            obj.args_out = operands[: obj.num_out]
            idx_args_in = obj.num_out
        elif obj.num_in_out > 0:
            obj.args_in_out = operands[: obj.num_in_out]
            idx_args_in = obj.num_in_out
        else:
            idx_args_in = 0

        obj.args_in = operands[idx_args_in:]

        if not len(obj.args_in) == obj.num_in:
            raise FatalParsingException(
                f"Something wrong parsing {src}: Expect {obj.num_in} input,"
                f" but got {len(obj.args_in)} ({obj.args_in})"
            )

        return obj

    @staticmethod
    def parser(src_line):
        """Global factory method parsing an assembly line into an instance
        of a subclass of Instruction."""
        insts = []
        exceptions = {}
        instnames = []

        src = src_line.text.strip()

        # Iterate through all derived classes and call their parser
        # until one of them hopefully succeeds
        for inst_class in Instruction.all_subclass_leaves:
            try:
                inst = inst_class.make(src)
                instnames = [inst_class.__name__]
                insts = [inst]
                break
            except ParsingException as e:
                exceptions[inst_class.__name__] = e

        for i in insts:
            i.source_line = src_line
            i.extract_read_writes()

        if len(insts) == 0:
            logging.error("Failed to parse instruction %s", src)
            logging.error("A list of attempted parsers and their exceptions follows.")
            for i, e in exceptions.items():
                msg = f"* {i + ':':20s} {e}"
                logging.error(msg)
            raise ParsingException(
                f"Couldn't parse {src}\nYou may need to add support "
                "for a new instruction (variant)?"
            )

        logging.debug("Parsing result for '%s': %s", src, instnames)
        return insts

    def __repr__(self):
        return self.write()


class x86_64Instruction(Instruction):
    """Abstract class representing x86_64 instructions"""

    PARSERS = {}

    @staticmethod
    def _replace_duplicate_datatypes(src, mnemonic_key):
        pattern = re.compile(rf"<{re.escape(mnemonic_key)}\d*>")

        matches = list(pattern.finditer(src))

        if len(matches) > 1:
            for i, match in enumerate(reversed(matches)):
                start, end = match.span()
                src = src[:start] + f"<{mnemonic_key}{len(matches)-1-i}>" + src[end:]

        return src

    @staticmethod
    def _unfold_pattern(src):

        # Those replacements may look pointless, but they replace
        # actual whitespaces before/after '.,[]' in the instruction
        # pattern by regular expressions allowing flexible whitespacing.
        flexible_spacing = [
            (r"\s*,\s*", r"\\s*,\\s*"),
            (r"\s*<imm>\s*", r"\\s*<imm>\\s*"),
            (r"\s*<literal>\s*", r"\\s*<literal>\\s*"),
            (r"\s*\[\s*", r"\\s*\\[\\s*"),
            (r"\s*\]\s*", r"\\s*\\]\\s*"),
            (r"\s*\{\s*", r"\\s*\\{\\s*"),
            (r"\s*\}\s*", r"\\s*\\}\\s*"),
            (r"\s*\.\s*", r"\\s*\\.\\s*"),
            (r"\s+", r"\\s+"),
            (r"\\s\*\\s\\+", r"\\s+"),
            (r"\\s\+\\s\\*", r"\\s+"),
            (r"(\\s\*)+", r"\\s*"),
        ]
        for c, cp in flexible_spacing:
            src = re.sub(c, cp, src)

        def idx_pattern_transform(g):
            return (
                f"(\\w?)(?P<{g.group(1)}>([0-9]+|.(i|I)|.(?=(x|X))|.(?=(l|L))))(\\w?)"
            )
        
        def sz_pattern_transform(g):
            return (
                f"(?P<{g.group(1)}>([eErR]?([a-dA-D][lLxX]|[sSdD][iI][lL]?)|[rR](8|9|1[0-5])))"
            )

        idx_re = re.sub(r"<(\wW\w)>", idx_pattern_transform, src)
        sz_re = re.sub(r"<(\w)(W\w)>", sz_pattern_transform, src)

        # Replace <key> or <key0>, <key1>, ... with pattern
        def replace_placeholders(src, mnemonic_key, regexp, group_name):
            prefix = f"<{mnemonic_key}"
            pattern = f"<{mnemonic_key}>"

            def pattern_i(i):
                return f"<{mnemonic_key}{i}>"

            cnt = src.count(prefix)
            if cnt > 1:
                for i in range(cnt):
                    src = re.sub(pattern_i(i), f"(?P<{group_name}{i}>{regexp})", src)
            else:
                src = re.sub(pattern, f"(?P<{group_name}>{regexp})", src)

            return src
        
        imm_pattern = (
            "([0-9]*)"
        )

        idx_re = replace_placeholders(idx_re, "imm", imm_pattern, "imm")
        sz_re = replace_placeholders(sz_re, "imm", imm_pattern, "imm")
        for sz_sym in ['H','S','D','Q']:
            sz_re = x86_64Instruction._replace_duplicate_datatypes(sz_re, sz_sym)

        idx_re = r"\s*" + idx_re + r"\s*(//.*)?\Z"
        sz_re = r"\s*" + sz_re + r"\s*(//.*)?\Z"
        return idx_re, sz_re

    @staticmethod
    def check_reg_sizes(sz_re_match):
        sz_dict = sz_re_match.groupdict()
        for sz_sym, reg in sz_dict.items():
            reg = reg.upper()
            if 'H' in sz_sym:
                if reg in RegisterType.list_byte_gprs():
                    return True
            elif 'S' in sz_sym:
                if reg in RegisterType.list_word_gprs():
                    return True
            elif 'D' in sz_sym:
                if reg in RegisterType.list_dblword_gprs():
                    return True
            elif 'Q' in sz_sym:
                if reg in RegisterType.list_qdword_gprs():
                    return True
            return False

    @staticmethod
    def _build_parser(src):
        idx_regexp_txt, sz_regexp_txt = x86_64Instruction._unfold_pattern(src)
        idx_regexp = re.compile(idx_regexp_txt)
        sz_regexp = re.compile(sz_regexp_txt)

        def _parse(line):
            idx_regexp_result = idx_regexp.match(line)
            sz_regexp_result = sz_regexp.match(line)
            if idx_regexp_result is None or sz_regexp_result is None or not x86_64Instruction.check_reg_sizes(sz_regexp_result):
                raise ParsingException(
                    f"Does not match instruction pattern {src}" f"[indexing regex: {idx_regexp_txt}]" f"[size regex: {sz_regexp_txt}]" 
                )
            res = idx_regexp.match(line).groupdict()
            return res

        return _parse

    @staticmethod
    def get_parser(pattern):
        """Build parser for given x86_64 instruction pattern"""
        if pattern in x86_64Instruction.PARSERS:
            return x86_64Instruction.PARSERS[pattern]
        parser = x86_64Instruction._build_parser(pattern)
        x86_64Instruction.PARSERS[pattern] = parser
        return parser

    @staticmethod
    @cache
    def _infer_register_type(ptrn):
        if ptrn[0:2].upper() == 'HW':
            return RegisterType.GPR_H
        if ptrn[0:2].upper() == 'SW':
            return RegisterType.GPR_S
        if ptrn[0:2].upper() == 'DW':
            return RegisterType.GPR_D
        if ptrn[0:2].upper() == 'QW':
            return RegisterType.GPR_Q
        if ptrn[0].upper() in []:
            return RegisterType.FLAGS
        raise FatalParsingException(f"Unknown pattern: {ptrn}")

    def __init__(
        self,
        pattern,
        *,
        inputs=None,
        outputs=None,
        in_outs=None,
        modifiesFlags=False,
        dependsOnFlags=False,
    ):

        self.mnemonic = pattern.split(" ")[0]

        if inputs is None:
            inputs = []
        if outputs is None:
            outputs = []
        if in_outs is None:
            in_outs = []
        arg_types_in = [x86_64Instruction._infer_register_type(r) for r in inputs]
        arg_types_out = [x86_64Instruction._infer_register_type(r) for r in outputs]
        arg_types_in_out = [x86_64Instruction._infer_register_type(r) for r in in_outs]

        if modifiesFlags:
            arg_types_out += [RegisterType.FLAGS]
            outputs += ["flags"]

        if dependsOnFlags:
            arg_types_in += [RegisterType.FLAGS]
            inputs += ["flags"]

        super().__init__(
            mnemonic=pattern,
            arg_types_in=arg_types_in,
            arg_types_out=arg_types_out,
            arg_types_in_out=arg_types_in_out,
        )

        self.inputs = inputs
        self.outputs = outputs
        self.in_outs = in_outs

        self.pattern = pattern
        assert len(inputs) == len(arg_types_in)
        self.pattern_inputs = list(zip(inputs, arg_types_in))
        assert len(outputs) == len(arg_types_out)
        self.pattern_outputs = list(zip(outputs, arg_types_out))
        assert len(in_outs) == len(arg_types_in_out)
        self.pattern_in_outs = list(zip(in_outs, arg_types_in_out))

    @staticmethod
    def _to_reg(ty, s):
        if ty == RegisterType.GPR_H:
                s = s.lower()
                if s.isnumeric():
                    return f"r{s}l"
                if s[-1] in ['A','B','C','D']:
                    pass
                return f"{s}l"
        if ty == RegisterType.GPR_S:
                s = s.lower()
                if s.isnumeric():
                    return f"r{s}w"
                if s[-1] in ['A','B','C','D']:
                    return f"{s}x"
                return s
        if ty == RegisterType.GPR_D:
                s = s.lower()
                if s.isnumeric():
                    return f"r{s}d"
                if s[-1] in ['A','B','C','D']:
                    s = f"{s}x"
                return f"e{s}"
        if ty == RegisterType.GPR_Q:
                s = s.lower()
                if s.isnumeric():
                    return f"r{s}"
                if s[-1] in ['A','B','C','D']:
                    s = f"{s}x"
                return f"r{s}"
        return s

    @staticmethod
    def _build_pattern_replacement(s, ty, arg):
        _ = s
        _ = ty
        return arg
        # if ty == RegisterType.GPR:
        #     if arg[0] not in ['e','E']:
        #         return f"{s[0].upper()}<{arg}>"
        #     return s[0] + arg[1:]
        # raise FatalParsingException(f"Unknown register type ({s}, {ty}, {arg})")

    @staticmethod
    def _instantiate_pattern(s, ty, arg, out):
        if ty == RegisterType.FLAGS:
            return out
        rep = x86_64Instruction._build_pattern_replacement(s, ty, arg)
        res = out.replace(f"<{s}>", rep)
        if res == out:
            raise FatalParsingException(f"Failed to replace <{s}> by {rep} in {out}!")
        return res

    @staticmethod
    def build_core(obj, res):

        def group_to_attribute(group_name, attr_name, f=None):
            def f_default(x):
                return x

            def group_name_i(i):
                return f"{group_name}{i}"

            if f is None:
                f = f_default
            if group_name in res.keys():
                setattr(obj, attr_name, f(res[group_name]))
            else:
                idxs = [i for i in range(4) if group_name_i(i) in res.keys()]
                if len(idxs) == 0:
                    return
                assert idxs == list(range(len(idxs)))
                setattr(
                    obj, attr_name, list(map(lambda i: f(res[group_name_i(i)]), idxs))
                )

        group_to_attribute("datatype", "datatype", lambda x: x.lower())
        group_to_attribute(
            "imm", "immediate", lambda x: x.replace("#", "")
        )  # Strip '#'
        group_to_attribute(
            "literal", "immediate", lambda x: x.replace("#", "")
        )  # Strip '#'
        group_to_attribute("index", "index", int)
        group_to_attribute("flag", "flag")
        group_to_attribute("barrel", "barrel")

        for s, ty in obj.pattern_inputs:
            if ty == RegisterType.FLAGS:
                obj.args_in.append("flags")
            else:
                obj.args_in.append(obj._to_reg(ty, res[s]))
        for s, ty in obj.pattern_outputs:
            if ty == RegisterType.FLAGS:
                obj.args_out.append("flags")
            else:
                obj.args_out.append(obj._to_reg(ty, res[s]))

        for s, ty in obj.pattern_in_outs:
            obj.args_in_out.append(obj._to_reg(ty, res[s]))

    @staticmethod
    def build(c, src):
        pattern = getattr(c, "pattern")
        inputs = getattr(c, "inputs", []).copy()
        outputs = getattr(c, "outputs", []).copy()
        in_outs = getattr(c, "in_outs", []).copy()
        modifies_flags = getattr(c, "modifiesFlags", False)
        depends_on_flags = getattr(c, "dependsOnFlags", False)

        if isinstance(src, str):
            if src.split(" ")[0] != pattern.split(" ")[0]:
                raise ParsingException("Mnemonic does not match")
            res = x86_64Instruction.get_parser(pattern)(src)
        else:
            assert isinstance(src, dict)
            res = src

        obj = c(
            pattern,
            inputs=inputs,
            outputs=outputs,
            in_outs=in_outs,
            modifiesFlags=modifies_flags,
            dependsOnFlags=depends_on_flags,
        )

        x86_64Instruction.build_core(obj, res)
        return obj

    @classmethod
    def make(cls, src):
        return x86_64Instruction.build(cls, src)

    def write(self):
        out = self.pattern
        ll = (
            list(zip(self.args_in, self.pattern_inputs))
            + list(zip(self.args_out, self.pattern_outputs))
            + list(zip(self.args_in_out, self.pattern_in_outs))
        )
        for arg, (s, ty) in ll:
            out = x86_64Instruction._instantiate_pattern(s, ty, arg, out)

        def replace_pattern(txt, attr_name, mnemonic_key, t=None):
            def t_default(x):
                return x

            if t is None:
                t = t_default

            a = getattr(self, attr_name)
            if a is None:
                return txt
            if not isinstance(a, list):
                txt = txt.replace(f"<{mnemonic_key}>", t(a))
                return txt
            for i, v in enumerate(a):
                txt = txt.replace(f"<{mnemonic_key}{i}>", t(v))
            return txt

        out = replace_pattern(out, "immediate", "imm", lambda x: f"{x}")
        # out = replace_pattern(out, "immediate", "literal", lambda x: f"{x}")
        # out = replace_pattern(out, "datatype", "dt", lambda x: x.upper())
        # out = replace_pattern(out, "flag", "flag")
        # out = replace_pattern(out, "index", "index", str)
        # out = replace_pattern(out, "barrel", "barrel", lambda x: x.lower())

        out = out.replace("\\[", "[")
        out = out.replace("\\]", "]")
        return out 

# ADD immediate to register
# Byte register
class add_hi(x86_64Instruction):
    pattern = "add <HWd>, <imm>"
    in_outs = ["HWd"]

# ADD immediate to register
# Word register
class add_si(x86_64Instruction):
    pattern = "add <SWd>, <imm>"
    in_outs = ["SWd"]

# ADD immediate to register
# Doubleword register
class add_di(x86_64Instruction):
    pattern = "add <DWd>, <imm>"
    in_outs = ["DWd"]

# ADD immediate to register
# Quadword register
class add_qi(x86_64Instruction):
    pattern = "add <QWd>, <imm>"
    in_outs = ["QWd"]

# ADD byte register to byte register
class add_hh(x86_64Instruction):
    pattern = "add <HWd>, <HWs>"
    inputs = ["HWs"]
    in_outs = ["HWd"]

# ADD word register to word register
class add_ss(x86_64Instruction):
    pattern = "add <SWd>, <SWs>"
    inputs = ["SWs"]
    in_outs = ["SWd"]

# ADD doubleword register to doubleword register
class add_dd(x86_64Instruction):
    pattern = "add <DWd>, <DWs>"
    inputs = ["DWs"]
    in_outs = ["DWd"]

# ADD quadword register to quadword register
class add_qq(x86_64Instruction):
    pattern = "add <QWd>, <QWs>"
    inputs = ["QWs"]
    in_outs = ["QWd"]

def iter_x86_64_instructions():
    yield from all_subclass_leaves(Instruction)


def find_class(src):
    for inst_class in iter_x86_64_instructions():
        if isinstance(src, inst_class):
            return inst_class
    raise UnknownInstruction(
        f"Couldn't find instruction class for {src} (type {type(src)})"
    )

# Returns the list of all subclasses of a class which don't have
# subclasses themselves
def all_subclass_leaves(c):

    def has_subclasses(cl):
        return len(cl.__subclasses__()) > 0

    def is_leaf(c):
        return not has_subclasses(c)

    def all_subclass_leaves_core(leaf_lst, todo_lst):
        leaf_lst += filter(is_leaf, todo_lst)
        todo_lst = [
            csub
            for c in filter(has_subclasses, todo_lst)
            for csub in c.__subclasses__()
        ]
        if len(todo_lst) == 0:
            return leaf_lst
        return all_subclass_leaves_core(leaf_lst, todo_lst)

    return all_subclass_leaves_core([], [c])


Instruction.all_subclass_leaves = all_subclass_leaves(Instruction)
