"""
SkookumScript Decompiler for The Eternal Cylinder
Reads Classes.sk-bin and Classes.sk-sym files and produces .sk source files.

Binary format based on open-source SkookumScript for UE 4.24 (version 61).
"""

import struct
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any


def format_real(val: float) -> str:
    for precision in range(1, 20):
        s = f"{val:.{precision}f}"
        if struct.pack('<f', float(s)) == struct.pack('<f', val):
            if '.' not in s:
                s += '.0'
            return s
    return repr(val)


class BinaryReader:
    __slots__ = ('data', 'pos', 'size')

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.size = len(data)

    def u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        v = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return v

    def i16(self) -> int:
        v = struct.unpack_from('<h', self.data, self.pos)[0]
        self.pos += 2
        return v

    def u32(self) -> int:
        v = struct.unpack_from('<I', self.data, self.pos)[0]
        self.pos += 4
        return v

    def i32(self) -> int:
        v = struct.unpack_from('<i', self.data, self.pos)[0]
        self.pos += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from('<Q', self.data, self.pos)[0]
        self.pos += 8
        return v

    def f32(self) -> float:
        v = struct.unpack_from('<f', self.data, self.pos)[0]
        self.pos += 4
        return v

    def raw(self, n: int) -> bytes:
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v

    def remaining(self) -> int:
        return self.size - self.pos


class SymbolTable:

    def __init__(self):
        self.id_to_name: Dict[int, str] = {}
        self.name_to_id: Dict[str, int] = {}

    def load(self, filepath: str):
        with open(filepath, 'rb') as f:
            data = f.read()

        r = BinaryReader(data)
        count = r.u32()

        for _ in range(count):
            sym_id = r.u32()
            str_len = r.u8()
            name = r.raw(str_len).decode('ascii', errors='replace')
            self.id_to_name[sym_id] = name
            self.name_to_id[name] = sym_id

        assert r.remaining() == 0, f"Symbol table has {r.remaining()} trailing bytes"

    def resolve(self, sym_id: int) -> str:
        if sym_id == 0 or sym_id == 0xFFFFFFFF:
            return ""
        return self.id_to_name.get(sym_id, f"<sym_0x{sym_id:08X}>")

    def __len__(self):
        return len(self.id_to_name)


EXPR_DEFAULT = 0
EXPR_IDENT_LOCAL = 1
EXPR_IDENT_MEMBER = 2
EXPR_IDENT_RAW_MEMBER = 3
EXPR_IDENT_CLASS_MEMBER = 4
EXPR_RAW_MEMBER_ASSIGN = 5
EXPR_RAW_MEMBER_INVOKE = 6
EXPR_OBJECT_ID = 7
EXPR_LITERAL = 8
EXPR_LITERAL_LIST = 9
EXPR_CLOSURE_METHOD = 10
EXPR_CLOSURE_COROUTINE = 11
EXPR_BIND = 12
EXPR_CAST = 13
EXPR_CONVERSION = 14
EXPR_CODE = 15
EXPR_CONDITIONAL = 16
EXPR_CASE = 17
EXPR_WHEN = 18
EXPR_UNLESS = 19
EXPR_LOOP = 20
EXPR_LOOP_EXIT = 21
EXPR_INVOKE = 22
EXPR_INVOKE_SYNC = 23
EXPR_INVOKE_RACE = 24
EXPR_INVOKE_CASCADE = 25
EXPR_INVOKE_CLOSURE_METHOD = 26
EXPR_INVOKE_CLOSURE_COROUTINE = 27
EXPR_INSTANTIATE = 28
EXPR_COPY_INVOKE = 29
EXPR_CONCURRENT_SYNC = 30
EXPR_CONCURRENT_RACE = 31
EXPR_CONCURRENT_BRANCH = 32
EXPR_CHANGE = 33
EXPR_NIL_COALESCING = 34

LIT_BOOLEAN = 0
LIT_INTEGER = 1
LIT_REAL = 2
LIT_STRING = 3
LIT_SYMBOL = 4
LIT_CLASS = 5
LIT_NIL = 6
LIT_THIS = 7
LIT_THIS_CLASS = 8
LIT_THIS_CODE = 9
LIT_THIS_MIND = 10

INVOKE_INVALID = 0
INVOKE_COROUTINE = 1
INVOKE_METHOD_ON_INSTANCE = 2
INVOKE_METHOD_ON_CLASS = 3
INVOKE_METHOD_ON_INSTANCE_CLASS = 4
INVOKE_METHOD_ON_CLASS_INSTANCE = 5
INVOKE_METHOD_BOOL_AND = 6
INVOKE_METHOD_BOOL_OR = 7
INVOKE_METHOD_BOOL_NAND = 8
INVOKE_METHOD_BOOL_NOR = 9
INVOKE_METHOD_ASSERT = 10
INVOKE_METHOD_ASSERT_NO_LEAK = 11

CLASS_TYPE_CLASS = 0
CLASS_TYPE_METACLASS = 1
CLASS_TYPE_TYPED_CLASS = 2
CLASS_TYPE_INVOKABLE_CLASS = 3
CLASS_TYPE_CLASS_UNION = 4

INVOKABLE_METHOD = 0
INVOKABLE_METHOD_FUNC = 1
INVOKABLE_METHOD_MTHD = 2
INVOKABLE_COROUTINE = 3
INVOKABLE_COROUTINE_FUNC = 4
INVOKABLE_COROUTINE_MTHD = 5

PARAM_UNARY = 0
PARAM_UNARY_DEFAULT = 1
PARAM_GROUP = 3

INVOKE_TIME_IMMEDIATE = 1
INVOKE_TIME_DURATIONAL = 2
INVOKE_TIME_ANY = 3

OBJID_FLAG_POSSIBLE = 1
OBJID_FLAG_IDENTIFIER = 2


@dataclass
class SkClass:
    name: str
    name_id: int = 0
    flags: int = 0
    annotation_flags: int = 0
    bind_name: str = ""
    superclass: Optional['SkClass'] = None
    subclasses: List['SkClass'] = field(default_factory=list)
    data_members: list = field(default_factory=list)
    raw_data_members: list = field(default_factory=list)
    class_data_members: list = field(default_factory=list)
    instance_methods: list = field(default_factory=list)
    class_methods: list = field(default_factory=list)
    coroutines: list = field(default_factory=list)

@dataclass
class SkRoutine:
    name: str
    invokable_type: int
    name_id: int = 0
    params: Optional[Any] = None
    expression: Optional[Any] = None
    annotation_flags: int = 0
    invoked_data_array_size: int = 0

@dataclass
class SkParams:
    params: list = field(default_factory=list)
    return_params: list = field(default_factory=list)
    result_type: str = "None"

@dataclass
class ClassRef:
    ctype: int
    raw_id: int
    display: str

    def __str__(self):
        return self.display

@dataclass
class SkParam:
    kind: int
    name: str = ""
    name_id: int = 0
    class_type: Any = None
    default_expr: Optional[Any] = None
    default_debug_pos: int = 0
    default_expr_type: int = 0
    type_info: int = 0
    group_classes: list = field(default_factory=list)


class SkDecompiler:

    def __init__(self, sym_path: str, bin_path: str):
        self.symbols = SymbolTable()
        self.symbols.load(sym_path)
        print(f"Loaded {len(self.symbols)} symbols from {sym_path}")

        with open(bin_path, 'rb') as f:
            data = f.read()
        self.r = BinaryReader(data)
        print(f"Loaded {len(data)} bytes from {bin_path}")

        self.classes: Dict[str, SkClass] = {}
        self.class_list: List[SkClass] = []
        self.typed_classes: List[Any] = []
        self.invokable_classes: List[Any] = []
        self.class_unions: List[Any] = []
        self.indent_size = 2

    def sym(self, sym_id: int) -> str:
        return self.symbols.resolve(sym_id)

    def read_symbol(self) -> Tuple[int, str]:
        sid = self.r.u32()
        return sid, self.sym(sid)

    def read_bind_name(self) -> str:
        length = self.r.u16()
        name = self.r.raw(length).decode('ascii', errors='replace')
        self.r.u8()
        return name

    def read_string(self) -> str:
        length = self.r.u32()
        return self.r.raw(length).decode('utf-8', errors='replace')

    def read_class_ref(self) -> Tuple[int, str]:
        sid, name = self.read_symbol()
        return sid, name

    def read_class_ref_typed(self) -> 'ClassRef':
        ctype = self.r.u8()
        if ctype == CLASS_TYPE_CLASS:
            sid, name = self.read_class_ref()
            return ClassRef(ctype, sid, name)
        elif ctype == CLASS_TYPE_METACLASS:
            sid, name = self.read_class_ref()
            return ClassRef(ctype, sid, f"<{name}>")
        elif ctype == CLASS_TYPE_TYPED_CLASS:
            idx = self.r.u32()
            tc = self.typed_classes[idx] if idx < len(self.typed_classes) else None
            display = tc['display'] if tc else f"<typed_class_{idx}>"
            return ClassRef(ctype, idx, display)
        elif ctype == CLASS_TYPE_INVOKABLE_CLASS:
            idx = self.r.u32()
            ic = self.invokable_classes[idx] if idx < len(self.invokable_classes) else None
            display = ic['display'] if ic else f"<invokable_class_{idx}>"
            return ClassRef(ctype, idx, display)
        elif ctype == CLASS_TYPE_CLASS_UNION:
            idx = self.r.u32()
            cu = self.class_unions[idx] if idx < len(self.class_unions) else None
            display = cu['display'] if cu else f"<class_union_{idx}>"
            return ClassRef(ctype, idx, display)
        else:
            return ClassRef(ctype, 0, f"<unknown_class_type_{ctype}>")


    def read_header(self):
        self.code_id = self.r.u32()
        version = self.code_id >> 24
        magic = self.code_id & 0x00FFFFFF
        assert magic == 0xDEC0CB, f"Invalid magic: 0x{magic:06X}"
        print(f"Binary version: {version}")

        self.checksum_folders = self.r.u32()
        self.checksum_files = self.r.u32()
        self.session_guid = self.r.u64()
        self.revision = self.r.u32()

        self.project_name = self.read_string()
        self.project_path = self.read_string()
        self.default_project_path = self.read_string()

        print(f"Project: {self.project_name}")
        print(f"Revision: {self.revision}")

        self.alloc_bytes = self.r.u32()
        self.debug_bytes = self.r.u32()

        self.class_count = self.r.u32()
        print(f"Class count: {self.class_count}")


    def read_class_hierarchy(self, superclass: Optional[SkClass] = None):
        name_id, name = self.read_symbol()
        flags = self.r.u32()
        annotation_flags = self.r.u32()
        bind_name = self.read_bind_name()

        cls = SkClass(
            name=name,
            name_id=name_id,
            flags=flags,
            annotation_flags=annotation_flags,
            bind_name=bind_name,
            superclass=superclass,
        )

        self.classes[name] = cls
        self.class_list.append(cls)

        if superclass:
            superclass.subclasses.append(cls)

        subclass_count = self.r.u16()
        for _ in range(subclass_count):
            self.read_class_hierarchy(cls)


    def read_typed_class_full(self) -> dict:
        class_id, class_name = self.read_class_ref()
        item_type = self.read_class_ref_typed()
        display = f"{class_name}{{{item_type.display}}}"
        return {'class_id': class_id, 'item_type': item_type, 'display': display}

    def read_invokable_class_full(self) -> dict:
        class_id, class_name = self.read_class_ref()
        params = self.read_parameters()
        invoke_time = self.r.u8()

        params_str = self.format_params_signature(params)
        if invoke_time == INVOKE_TIME_IMMEDIATE:
            display = f"({params_str})"
        elif invoke_time == INVOKE_TIME_DURATIONAL:
            display = f"_({params_str})"
        else:
            display = f"+({params_str})"
        return {'class_id': class_id, 'params': params, 'invoke_time': invoke_time, 'display': display}

    def read_class_union_full(self) -> dict:
        common_class = self.read_class_ref_typed()
        member_count = self.r.u8()
        members = []
        for _ in range(member_count):
            members.append(self.read_class_ref_typed())
        display = "<" + "|".join(m.display for m in members) + ">"
        return {'common_class': common_class, 'members': members, 'display': display}

    def read_compound_types(self):
        self.startup_class_id, startup_name = self.read_symbol()
        print(f"Startup class: {startup_name}")

        typed_count = self.r.u32()
        self.typed_classes = [None] * typed_count

        invokable_count = self.r.u32()
        self.invokable_classes = [None] * invokable_count

        union_count = self.r.u32()
        self.class_unions = [None] * union_count

        print(f"Typed classes: {typed_count}, Invokable classes: {invokable_count}, Class unions: {union_count}")

        for i in range(union_count):
            self.class_unions[i] = self.read_class_union_full()

        for i in range(typed_count):
            self.typed_classes[i] = self.read_typed_class_full()

        for i in range(invokable_count):
            self.invokable_classes[i] = self.read_invokable_class_full()


    def read_parameters(self) -> SkParams:
        params = SkParams()

        param_count = self.r.u8()
        for _ in range(param_count):
            params.params.append(self.read_parameter())

        ret_count = self.r.u8()
        for _ in range(ret_count):
            name_id = self.r.u32()
            name = self.sym(name_id)
            ctype = self.read_class_ref_typed()
            params.return_params.append((name, name_id, ctype))

        params.result_type = self.read_class_ref_typed()

        return params

    def read_parameter(self) -> SkParam:
        header = self.r.u8()
        kind = header & 0x03
        type_info = header >> 2

        param = SkParam(kind=kind)
        param.type_info = type_info

        if kind == PARAM_GROUP:
            param.name_id = self.r.u32()
            param.name = self.sym(param.name_id)
            class_count = type_info
            for _ in range(class_count):
                param.group_classes.append(self.read_class_ref_typed())
        else:
            param.name_id = self.r.u32()
            param.name = self.sym(param.name_id)
            param.class_type = self.read_class_ref_typed()
            if kind == PARAM_UNARY_DEFAULT:
                param.default_expr_type = type_info
                param.default_debug_pos = self.r.u16()
                param.default_expr = self.read_expression(type_info)

        return param


    def read_typed_expression(self) -> Optional[dict]:
        expr_type = self.r.u8()
        if expr_type == EXPR_DEFAULT:
            return None
        debug_pos = self.r.u16()
        expr = self.read_expression(expr_type)
        return {'type': expr_type, 'debug_pos': debug_pos, 'expr': expr}

    def read_expression(self, expr_type: int) -> Any:
        readers = {
            EXPR_IDENT_LOCAL: self.read_ident_local,
            EXPR_IDENT_MEMBER: self.read_ident_member,
            EXPR_IDENT_RAW_MEMBER: self.read_ident_raw_member,
            EXPR_IDENT_CLASS_MEMBER: self.read_ident_class_member,
            EXPR_RAW_MEMBER_ASSIGN: self.read_raw_member_assign,
            EXPR_RAW_MEMBER_INVOKE: self.read_raw_member_invoke,
            EXPR_OBJECT_ID: self.read_object_id,
            EXPR_LITERAL: self.read_literal,
            EXPR_LITERAL_LIST: self.read_literal_list,
            EXPR_CLOSURE_METHOD: lambda: self.read_closure(True),
            EXPR_CLOSURE_COROUTINE: lambda: self.read_closure(False),
            EXPR_BIND: self.read_bind,
            EXPR_CAST: self.read_cast,
            EXPR_CONVERSION: self.read_conversion,
            EXPR_CODE: self.read_code,
            EXPR_CONDITIONAL: self.read_conditional,
            EXPR_CASE: self.read_case,
            EXPR_WHEN: self.read_when,
            EXPR_UNLESS: self.read_unless,
            EXPR_LOOP: self.read_loop,
            EXPR_LOOP_EXIT: self.read_loop_exit,
            EXPR_INVOKE: self.read_invoke,
            EXPR_INVOKE_SYNC: self.read_invoke_sync,
            EXPR_INVOKE_RACE: self.read_invoke_race,
            EXPR_INVOKE_CASCADE: self.read_invoke_cascade,
            EXPR_INVOKE_CLOSURE_METHOD: self.read_invoke_closure_method,
            EXPR_INVOKE_CLOSURE_COROUTINE: self.read_invoke_closure_coroutine,
            EXPR_INSTANTIATE: self.read_instantiate,
            EXPR_COPY_INVOKE: self.read_copy_invoke,
            EXPR_CONCURRENT_SYNC: self.read_concurrent_sync,
            EXPR_CONCURRENT_RACE: self.read_concurrent_race,
            EXPR_CONCURRENT_BRANCH: self.read_concurrent_branch,
            EXPR_CHANGE: self.read_change,
            EXPR_NIL_COALESCING: self.read_nil_coalescing,
        }

        if expr_type == EXPR_DEFAULT:
            return None

        reader = readers.get(expr_type)
        if reader is None:
            raise ValueError(f"Unknown expression type {expr_type} at offset 0x{self.r.pos:X}")
        return reader()


    def read_ident_local(self):
        name_id = self.r.u32()
        name = self.sym(name_id)
        data_idx = self.r.u16()
        return ('ident_local', name, name_id, data_idx)

    def read_ident_member(self):
        name_id = self.r.u32()
        name = self.sym(name_id)
        data_idx = self.r.u16()
        owner = self.read_typed_expression()
        return ('ident_member', name, name_id, data_idx, owner)

    def read_ident_raw_member(self):
        name_id = self.r.u32()
        name = self.sym(name_id)
        data_idx = self.r.u16()
        owner = self.read_typed_expression()
        owner_class_id, owner_class = self.read_class_ref()
        return ('ident_raw_member', name, name_id, data_idx, owner, owner_class_id, owner_class)

    def read_ident_class_member(self):
        name_id = self.r.u32()
        name = self.sym(name_id)
        data_idx = self.r.u16()
        owner_class_id, owner_class = self.read_class_ref()
        return ('ident_class_member', name, name_id, data_idx, owner_class_id, owner_class)


    def read_raw_member_base(self):
        owner = self.read_typed_expression()
        mc_id, member_class = self.read_class_ref()
        member_idx = self.r.u16()
        cascade_count = self.r.u8()
        cascade = []
        for _ in range(cascade_count):
            cc_id, cc = self.read_class_ref()
            ci = self.r.u16()
            cascade.append((cc_id, cc, ci))
        return owner, mc_id, member_class, member_idx, cascade

    def read_raw_member_assign(self):
        owner, mc_id, mc, mi, cascade = self.read_raw_member_base()
        value = self.read_typed_expression()
        return ('raw_member_assign', owner, mc_id, mc, mi, cascade, value)

    def read_raw_member_invoke(self):
        owner, mc_id, mc, mi, cascade = self.read_raw_member_base()
        call = self.read_invoke_typed()
        return ('raw_member_invoke', owner, mc_id, mc, mi, cascade, call)


    def read_object_id(self):
        name_len = self.r.u16()
        name = self.r.raw(name_len).decode('ascii', errors='replace')
        self.r.u8()
        obj_class_id, obj_class = self.read_class_ref()
        flags = self.r.u8()
        return ('object_id', name, obj_class_id, obj_class, flags)


    def read_literal(self):
        kind = self.r.u8()
        if kind == LIT_BOOLEAN:
            val = self.r.u32()
            return ('literal', 'Boolean', val)
        elif kind == LIT_INTEGER:
            val = self.r.i32()
            return ('literal', 'Integer', val)
        elif kind == LIT_REAL:
            val = self.r.f32()
            return ('literal', 'Real', val)
        elif kind == LIT_STRING:
            length = self.r.u32()
            val = self.r.raw(length).decode('utf-8', errors='replace')
            return ('literal', 'String', val)
        elif kind == LIT_SYMBOL:
            sid, name = self.read_symbol()
            return ('literal', 'Symbol', name, sid)
        elif kind == LIT_CLASS:
            class_id, name = self.read_class_ref()
            return ('literal', 'Class', name, class_id)
        elif kind == LIT_NIL:
            return ('literal', 'nil', None)
        elif kind == LIT_THIS:
            return ('literal', 'this', None)
        elif kind == LIT_THIS_CLASS:
            return ('literal', 'this_class', None)
        elif kind == LIT_THIS_CODE:
            return ('literal', 'this_code', None)
        elif kind == LIT_THIS_MIND:
            return ('literal', 'this_mind', None)
        else:
            raise ValueError(f"Unknown literal kind {kind}")

    def read_literal_list(self):
        list_class_id, list_class = self.read_class_ref()
        call_type = self.r.u8()
        call = None
        if call_type != INVOKE_INVALID:
            call = self.read_invoke_base()
        item_count = self.r.u16()
        items = []
        for _ in range(item_count):
            items.append(self.read_typed_expression())
        return ('literal_list', list_class_id, list_class, call_type, call, items)


    def read_closure(self, is_method: bool):
        receiver = self.read_typed_expression()
        capture_count = self.r.u32()
        captured = []
        for _ in range(capture_count):
            cname_id = self.r.u32()
            cname = self.sym(cname_id)
            cidx = self.r.u16()
            captured.append((cname, cname_id, cidx))
        params = self.read_parameters()
        inv_data_size = self.r.u16()
        ann_flags = self.r.u32()
        expr = self.read_typed_expression()
        return ('closure', is_method, receiver, captured, params, inv_data_size, ann_flags, expr)


    def read_bind(self):
        ident = self.read_typed_expression()
        expr = self.read_typed_expression()
        return ('bind', ident, expr)

    def read_cast(self):
        cast_type = self.read_class_ref_typed()
        expr = self.read_typed_expression()
        return ('cast', cast_type, expr)

    def read_conversion(self):
        conv_class_id, conv_class = self.read_class_ref()
        vtable_idx = self.r.u16()
        expr = self.read_typed_expression()
        return ('conversion', conv_class_id, conv_class, vtable_idx, expr)


    def read_code(self):
        start_idx = self.r.u16()
        temp_count = self.r.u16()
        temp_vars = []
        for _ in range(temp_count):
            tv_id = self.r.u32()
            tv_name = self.sym(tv_id)
            temp_vars.append((tv_name, tv_id))

        stmt_count = self.r.u32()
        statements = []
        for _ in range(stmt_count):
            stmt = self.read_typed_expression()
            if stmt is not None:
                statements.append(stmt)
        return ('code', start_idx, temp_vars, statements)


    def read_conditional(self):
        clause_count = self.r.u32()
        clauses = []
        for _ in range(clause_count):
            test = self.read_typed_expression()
            body = self.read_typed_expression()
            clauses.append((test, body))
        return ('conditional', clauses)

    def read_case(self):
        compare = self.read_typed_expression()
        clause_count = self.r.u32()
        clauses = []
        for _ in range(clause_count):
            test = self.read_typed_expression()
            body = self.read_typed_expression()
            clauses.append((test, body))
        return ('case', compare, clauses)

    def read_when(self):
        clause = self.read_typed_expression()
        test = self.read_typed_expression()
        return ('when', clause, test)

    def read_unless(self):
        clause = self.read_typed_expression()
        test = self.read_typed_expression()
        return ('unless', clause, test)

    def read_loop(self):
        loop_name_id = self.r.u32()
        expr = self.read_typed_expression()
        return ('loop', loop_name_id, expr)

    def read_loop_exit(self):
        loop_name_id = self.r.u32()
        return ('loop_exit', loop_name_id)

    def read_nil_coalescing(self):
        trial = self.read_typed_expression()
        alternate = self.read_typed_expression()
        return ('nil_coalescing', trial, alternate)


    def read_invoke_base(self) -> dict:
        name_id = self.r.u32()
        call_name = self.sym(name_id)
        vtable_idx = self.r.u16()
        scope_id = self.r.u32()
        scope_name = self.sym(scope_id)

        arg_count = self.r.u8()
        args = []
        for _ in range(arg_count):
            args.append(self.read_typed_expression())

        ret_count = self.r.u8()
        ret_args = []
        for _ in range(ret_count):
            ret_args.append(self.read_typed_expression())

        return {
            'name': call_name,
            'name_id': name_id,
            'vtable_idx': vtable_idx,
            'scope': scope_name if scope_name else None,
            'scope_id': scope_id,
            'args': args,
            'ret_args': ret_args,
        }

    def read_invoke_typed(self) -> Optional[dict]:
        invoke_type = self.r.u8()
        if invoke_type == INVOKE_INVALID:
            return None
        call = self.read_invoke_base()
        call['invoke_type'] = invoke_type
        return call

    def read_invoke(self):
        receiver = self.read_typed_expression()
        call = self.read_invoke_typed()
        return ('invoke', receiver, call)

    def read_invoke_sync(self):
        receiver = self.read_typed_expression()
        call = self.read_invoke_typed()
        return ('invoke_sync', receiver, call)

    def read_invoke_race(self):
        receiver = self.read_typed_expression()
        call = self.read_invoke_typed()
        return ('invoke_race', receiver, call)

    def read_invoke_cascade(self):
        receiver = self.read_typed_expression()
        call_count = self.r.u8()
        calls = []
        for _ in range(call_count):
            calls.append(self.read_invoke_typed())
        return ('invoke_cascade', receiver, calls)

    def read_invoke_closure_method(self):
        return self._read_invoke_closure()

    def read_invoke_closure_coroutine(self):
        return self._read_invoke_closure()

    def _read_invoke_closure(self):
        params = self.read_parameters()
        arg_count = self.r.u8()
        args = []
        for _ in range(arg_count):
            args.append(self.read_typed_expression())
        ret_count = self.r.u8()
        ret_args = []
        for _ in range(ret_count):
            ret_args.append(self.read_typed_expression())
        receiver = self.read_typed_expression()
        return ('invoke_closure', receiver, params, args, ret_args)


    def read_instantiate(self):
        inst_class_id, inst_class = self.read_class_ref()
        ctor_call = self.read_invoke_base()
        return ('instantiate', inst_class_id, inst_class, ctor_call)

    def read_copy_invoke(self):
        copy_class_id, copy_class = self.read_class_ref()
        ctor_call = self.read_invoke_base()
        method_call = self.read_invoke_base()
        return ('copy_invoke', copy_class_id, copy_class, ctor_call, method_call)


    def read_concurrent_sync(self):
        count = self.r.u8()
        exprs = []
        for _ in range(count):
            exprs.append(self.read_typed_expression())
        return ('concurrent_sync', exprs)

    def read_concurrent_race(self):
        count = self.r.u8()
        exprs = []
        for _ in range(count):
            exprs.append(self.read_typed_expression())
        return ('concurrent_race', exprs)

    def read_concurrent_branch(self):
        capture_count = self.r.u32()
        captured = []
        for _ in range(capture_count):
            cname_id = self.r.u32()
            cname = self.sym(cname_id)
            cidx = self.r.u16()
            captured.append((cname, cname_id, cidx))
        params = self.read_parameters()
        inv_data_size = self.r.u16()
        ann_flags = self.r.u32()
        expr = self.read_typed_expression()
        return ('concurrent_branch', captured, params, inv_data_size, ann_flags, expr)

    def read_change(self):
        mind = self.read_typed_expression()
        expr = self.read_typed_expression()
        return ('change', mind, expr)


    def read_class_members(self):
        class_count = self.r.u32()
        print(f"Reading members for {class_count} classes...")

        for i in range(class_count):
            pos_before = self.r.pos
            class_name_id, class_name = self.read_class_ref()
            cls = self.classes.get(class_name)
            if cls is None:
                print(f"  WARNING: Class '{class_name}' not found in hierarchy!")
                cls = SkClass(name=class_name, name_id=class_name_id)
                self.classes[class_name] = cls
            try:
                self.read_class_body(cls)
            except Exception as e:
                print(f"  ERROR at class #{i} '{class_name}' (started at 0x{pos_before:X}, now at 0x{self.r.pos:X}): {e}")

                raise

            if (i + 1) % 500 == 0 or i >= class_count - 10:
                print(f"  {i+1}/{class_count} classes read... (class='{class_name}', pos=0x{self.r.pos:X})")

        print(f"  Done reading all {class_count} classes")

    def read_class_body(self, cls: SkClass):
        dm_count = self.r.u16()
        for _ in range(dm_count):
            name_id = self.r.u32()
            name = self.sym(name_id)
            ctype = self.read_class_ref_typed()
            cls.data_members.append((name, name_id, ctype))

        rdm_count = self.r.u16()
        for _ in range(rdm_count):
            name_id = self.r.u32()
            name = self.sym(name_id)
            ctype = self.read_class_ref_typed()
            bname = self.read_bind_name()
            cls.raw_data_members.append((name, name_id, ctype, bname))

        cdm_count = self.r.u16()
        for _ in range(cdm_count):
            name_id = self.r.u32()
            name = self.sym(name_id)
            ctype = self.read_class_ref_typed()
            cls.class_data_members.append((name, name_id, ctype))

        im_count = self.r.u32()
        for mi in range(im_count):
            cls.instance_methods.append(self.read_routine())

        cm_count = self.r.u32()
        for _ in range(cm_count):
            cls.class_methods.append(self.read_routine())

        co_count = self.r.u32()
        for _ in range(co_count):
            cls.coroutines.append(self.read_routine())

    def read_routine(self) -> SkRoutine:
        pos_start = self.r.pos
        inv_type = self.r.u8()
        name_id = self.r.u32()
        name = self.sym(name_id)

        routine = SkRoutine(name=name, name_id=name_id, invokable_type=inv_type)

        try:
            routine.params = self.read_parameters()
            routine.invoked_data_array_size = self.r.u16()
            routine.annotation_flags = self.r.u32()

            if inv_type in (INVOKABLE_METHOD, INVOKABLE_COROUTINE):
                routine.expression = self.read_typed_expression()
        except Exception as e:
            print(f"    ERROR in routine '{name}' (type={inv_type}, started at 0x{pos_start:X}): {e}")
            raise

        return routine


    def expr_to_code(self, expr, indent: int = 0) -> str:
        if expr is None:
            return ""

        if isinstance(expr, dict):
            return self.expr_to_code(expr['expr'], indent)

        tag = expr[0]

        if tag == 'ident_local':
            return expr[1]

        elif tag == 'ident_member':
            _, name, name_id, data_idx, owner = expr
            prefix = f"{self.expr_to_code(owner)}." if owner else ""
            return f"{prefix}@{name}"

        elif tag == 'ident_raw_member':
            _, name, name_id, data_idx, owner, owner_class_id, owner_class = expr
            prefix = f"{self.expr_to_code(owner)}." if owner else ""
            return f"{prefix}@{name}"

        elif tag == 'ident_class_member':
            _, name, name_id, data_idx, owner_class_id, owner_class = expr
            return f"@@{name}"

        elif tag == 'raw_member_assign':
            _, owner, mc_id, mc, mi, cascade, value = expr
            member_str = self._raw_member_str(owner, mc, mi, cascade)
            return f"{member_str} := {self.expr_to_code(value)}"

        elif tag == 'raw_member_invoke':
            _, owner, mc_id, mc, mi, cascade, call = expr
            member_str = self._raw_member_str(owner, mc, mi, cascade)
            call_str = self._invoke_call_str(call)
            return f"{member_str}.{call_str}"

        elif tag == 'object_id':
            _, name, obj_class_id, obj_class, flags = expr
            if flags & OBJID_FLAG_POSSIBLE:
                return f"{obj_class}@?'{name}'"
            elif flags & OBJID_FLAG_IDENTIFIER:
                return f"{obj_class}@#'{name}'"

            return f"{obj_class}@'{name}'"

        elif tag == 'literal':
            lit_type = expr[1]
            val = expr[2]
            if lit_type == 'Boolean':
                return "true" if val != 0 else "false"
            elif lit_type == 'Integer':
                return str(val)
            elif lit_type == 'Real':
                return format_real(val)
            elif lit_type == 'String':
                escaped = val.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                return f'"{escaped}"'
            elif lit_type == 'Symbol':
                return f"'{val}'"
            elif lit_type == 'Class':
                return val
            elif lit_type in ('nil', 'this', 'this_class', 'this_code', 'this_mind'):
                return lit_type

        elif tag == 'literal_list':
            _, list_class_id, list_class, call_type, call, items = expr
            items_str = ", ".join(self.expr_to_code(i) for i in items if i is not None)
            return "{" + items_str + "}"

        elif tag == 'closure':
            _, is_method, receiver, captured, params, inv_data_size, ann_flags, body = expr
            params_str = self.format_params_signature(params)
            body_str = self.expr_to_code(body, indent)
            if params_str:
                return f"^({params_str}) {body_str}"
            return f"^{body_str}"

        elif tag == 'bind':
            _, ident, value = expr
            ident_str = self.expr_to_code(ident)
            value_str = self.expr_to_code(value, indent)
            return f"!{ident_str} : {value_str}"

        elif tag == 'cast':
            _, cast_type, value = expr
            return f"{self.expr_to_code(value)}<>{cast_type}"

        elif tag == 'conversion':
            _, conv_class_id, conv_class, vtable_idx, value = expr
            return f"{self.expr_to_code(value)}>>{conv_class}"

        elif tag == 'code':
            _, start_idx, temp_vars, stmts = expr
            pad = " " * indent
            inner_pad = " " * (indent + self.indent_size)
            lines = []
            for stmt in stmts:
                lines.append(inner_pad + self.expr_to_code(stmt, indent + self.indent_size))
            if not lines:
                return "[]"
            return "[\n" + "\n".join(lines) + "\n" + pad + "]"

        elif tag == 'conditional':
            _, clauses = expr
            pad = " " * indent
            parts = []
            for i, (test, body) in enumerate(clauses):
                if test is None:
                    parts.append(f"else\n{pad}  {self.expr_to_code(body, indent + self.indent_size)}")
                elif i == 0:
                    parts.append(f"if {self.expr_to_code(test)}\n{pad}  {self.expr_to_code(body, indent + self.indent_size)}")
                else:
                    parts.append(f"elseif {self.expr_to_code(test)}\n{pad}  {self.expr_to_code(body, indent + self.indent_size)}")
            return ("\n" + pad).join(parts)

        elif tag == 'case':
            _, compare, clauses = expr
            pad = " " * indent
            parts = [f"case {self.expr_to_code(compare)}"]
            for test, body in clauses:
                if test is None:
                    parts.append(f"  else {self.expr_to_code(body, indent + self.indent_size)}")
                else:
                    parts.append(f"  {self.expr_to_code(test)} [{self.expr_to_code(body, indent + self.indent_size)}]")
            return ("\n" + pad).join(parts)

        elif tag == 'when':
            _, clause, test = expr
            return f"{self.expr_to_code(clause, indent)} when {self.expr_to_code(test)}"

        elif tag == 'unless':
            _, clause, test = expr
            return f"{self.expr_to_code(clause, indent)} unless {self.expr_to_code(test)}"

        elif tag == 'loop':
            _, loop_name_id, body = expr
            return f"loop {self.expr_to_code(body, indent)}"

        elif tag == 'loop_exit':
            return "exit"

        elif tag == 'nil_coalescing':
            _, trial, alt = expr
            return f"{self.expr_to_code(trial)}??{self.expr_to_code(alt)}"

        elif tag == 'invoke':
            _, receiver, call = expr
            recv_str = self.expr_to_code(receiver) if receiver else ""
            call_str = self._invoke_call_str(call)
            if recv_str:
                return f"{recv_str}.{call_str}"
            return call_str

        elif tag == 'invoke_sync':
            _, receiver, call = expr
            recv_str = self.expr_to_code(receiver) if receiver else ""
            call_str = self._invoke_call_str(call)
            if recv_str:
                return f"{recv_str}%{call_str}"
            return f"%{call_str}"

        elif tag == 'invoke_race':
            _, receiver, call = expr
            recv_str = self.expr_to_code(receiver) if receiver else ""
            call_str = self._invoke_call_str(call)
            if recv_str:
                return f"{recv_str}%>{call_str}"
            return f"%>{call_str}"

        elif tag == 'invoke_cascade':
            _, receiver, calls = expr
            recv_str = self.expr_to_code(receiver) if receiver else "this"
            pad = " " * indent
            call_strs = [self._invoke_call_str(c) for c in calls]
            return recv_str + "." + ("\n" + pad + "  :").join(call_strs)

        elif tag == 'invoke_closure':
            _, receiver, params, args, ret_args = expr
            recv_str = self.expr_to_code(receiver) if receiver else ""
            args_str = ", ".join(self.expr_to_code(a) for a in args if a is not None)
            if recv_str:
                return f"{recv_str}({args_str})"
            return f"({args_str})"

        elif tag == 'instantiate':
            _, inst_class_id, inst_class, ctor = expr
            args_str = self._invoke_args_str(ctor)
            ctor_name = ctor.get('name', '!')
            if ctor_name == '!':
                return f"{inst_class}!({args_str})"
            return f"{inst_class}!{ctor_name}({args_str})"

        elif tag == 'copy_invoke':
            _, copy_class_id, copy_class, ctor, method = expr
            ctor_args = self._invoke_args_str(ctor)
            method_name = method.get('name', '')
            method_args = self._invoke_args_str(method)
            return f"{copy_class}!copy({ctor_args}).{method_name}({method_args})"

        elif tag == 'concurrent_sync':
            _, exprs = expr
            pad = " " * indent
            inner = "\n".join(f"{pad}  {self.expr_to_code(e, indent + self.indent_size)}" for e in exprs if e)
            return f"sync\n{inner}"

        elif tag == 'concurrent_race':
            _, exprs = expr
            pad = " " * indent
            inner = "\n".join(f"{pad}  {self.expr_to_code(e, indent + self.indent_size)}" for e in exprs if e)
            return f"race\n{inner}"

        elif tag == 'concurrent_branch':
            _, captured, params, inv_data_size, ann_flags, body = expr
            return f"branch {self.expr_to_code(body, indent)}"

        elif tag == 'change':
            _, mind, body = expr
            return f"change {self.expr_to_code(mind)} {self.expr_to_code(body, indent)}"

        return f"<unknown:{tag}>"

    def _raw_member_str(self, owner, mc, mi, cascade) -> str:
        parts = []
        if owner:
            parts.append(self.expr_to_code(owner))
        cls = self.classes.get(mc)
        if cls and mi < len(cls.raw_data_members):
            member_name = cls.raw_data_members[mi][0]
        else:
            member_name = f"@raw_{mi}"
        parts.append(f"@{member_name}")

        for cc_id, cc, ci in cascade:
            ccls = self.classes.get(cc)
            if ccls and ci < len(ccls.raw_data_members):
                parts.append(f"@{ccls.raw_data_members[ci][0]}")
            else:
                parts.append(f"@raw_{ci}")

        return ".".join(parts) if parts else f"@{member_name}"

    def _invoke_call_str(self, call: Optional[dict]) -> str:
        if call is None:
            return "()"
        name = call.get('name', '')
        scope = call.get('scope')
        args_str = self._invoke_args_str(call)
        scope_prefix = f"{scope}@" if scope else ""
        return f"{scope_prefix}{name}({args_str})"

    def _invoke_args_str(self, call: dict) -> str:
        args = call.get('args', [])
        ret_args = call.get('ret_args', [])
        parts = []
        for a in args:
            if a is not None:
                parts.append(self.expr_to_code(a))

        if ret_args:
            ret_parts = []
            for ra in ret_args:
                if ra is not None:
                    ret_parts.append(self.expr_to_code(ra))
            if ret_parts:
                return ", ".join(parts) + "; " + ", ".join(ret_parts)

        return ", ".join(parts)

    def format_params_signature(self, params: SkParams) -> str:
        parts = []
        for p in params.params:
            if p.kind == PARAM_GROUP:
                class_str = ", ".join(str(c) for c in p.group_classes) if p.group_classes else ""
                parts.append(f"{{{class_str}}} {p.name}")
            elif p.kind == PARAM_UNARY_DEFAULT:
                default_str = f" : {self.expr_to_code(p.default_expr)}" if p.default_expr else ""
                parts.append(f"{p.class_type} {p.name}{default_str}")
            else:
                parts.append(f"{p.class_type} {p.name}")

        result = ", ".join(parts)

        if params.return_params:
            ret_parts = [f"{ctype} {name}" for name, name_id, ctype in params.return_params]
            result += "; " + ", ".join(ret_parts)

        return result

    def format_routine_signature(self, routine: SkRoutine) -> str:
        if routine.params is None:
            return f"({routine.name})"

        params_str = self.format_params_signature(routine.params)
        result_type = routine.params.result_type

        sig = f"({params_str})"
        if result_type:
            rt_str = str(result_type)
            if rt_str not in ('None', 'InferredClass', ''):
                sig += f" {rt_str}"
        return sig


    def _is_atomic(self, routine: 'SkRoutine') -> bool:
        return routine.invokable_type in (INVOKABLE_METHOD_FUNC, INVOKABLE_METHOD_MTHD,
                                          INVOKABLE_COROUTINE_FUNC, INVOKABLE_COROUTINE_MTHD)

    def write_output(self, output_dir: str):
        cpp_dir = os.path.join(output_dir, "cpp-bound")
        script_dir = os.path.join(output_dir, "script")
        os.makedirs(cpp_dir, exist_ok=True)
        os.makedirs(script_dir, exist_ok=True)

        total_methods = 0
        total_coroutines = 0
        total_classes = 0
        cpp_count = 0
        script_count = 0

        for cls_name, cls in self.classes.items():
            has_content = (cls.instance_methods or cls.class_methods or
                          cls.coroutines or cls.data_members or
                          cls.raw_data_members or cls.class_data_members)

            if not has_content:
                continue

            total_classes += 1

            class_path = self._class_path(cls)

            cpp_routines = []
            script_routines = []

            all_routines = []
            for method in cls.instance_methods:
                all_routines.append((method, False, False))
            for method in cls.class_methods:
                all_routines.append((method, False, True))
            for coro in cls.coroutines:
                all_routines.append((coro, True, False))

            for routine, is_coro, is_class in all_routines:
                if self._is_atomic(routine):
                    cpp_routines.append((routine, is_coro, is_class))
                else:
                    script_routines.append((routine, is_coro, is_class))

            if cpp_routines:
                cdir = os.path.join(cpp_dir, *class_path)
                os.makedirs(cdir, exist_ok=True)
                if cls.data_members or cls.raw_data_members or cls.class_data_members:
                    self._write_data_file(cdir, cls)
                for routine, is_coro, is_class in cpp_routines:
                    if is_coro:
                        total_coroutines += 1
                    else:
                        total_methods += 1
                    cpp_count += 1
                    self._write_routine_file(cdir, routine, is_coroutine=is_coro, is_class=is_class)

            if script_routines:
                sdir = os.path.join(script_dir, *class_path)
                os.makedirs(sdir, exist_ok=True)
                if cls.data_members or cls.raw_data_members or cls.class_data_members:
                    self._write_data_file(sdir, cls)
                for routine, is_coro, is_class in script_routines:
                    if is_coro:
                        total_coroutines += 1
                    else:
                        total_methods += 1
                    script_count += 1
                    self._write_routine_file(sdir, routine, is_coroutine=is_coro, is_class=is_class)

        print(f"\nOutput: {total_classes} classes, {total_methods} methods, {total_coroutines} coroutines")
        print(f"  cpp-bound: {cpp_count} files")
        print(f"  script:    {script_count} files")

    def _class_path(self, cls: SkClass) -> list:
        parts = []
        c = cls
        while c:
            parts.append(c.name)
            c = c.superclass
        parts.reverse()
        return parts

    def _write_data_file(self, class_dir: str, cls: SkClass):
        lines = []
        for name, name_id, ctype in cls.data_members:
            lines.append(f"&{ctype} @{name}")
        for name, name_id, ctype in cls.class_data_members:
            lines.append(f"&{ctype} @@{name}")
        for name, name_id, ctype, bname in cls.raw_data_members:
            lines.append(f"&raw {ctype} @{name}  // bind: {bname}")

        if lines:
            filepath = os.path.join(class_dir, "!Data.sk")
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("\n".join(lines) + "\n")

    def _write_routine_file(self, class_dir: str, routine: SkRoutine,
                            is_coroutine: bool, is_class: bool):
        name = routine.name

        safe_name = name.replace('?', '-Q').replace('!', '-E').replace('*', '-S')
        safe_name = safe_name.replace('<', '-L').replace('>', '-G').replace('|', '-P')
        safe_name = safe_name.replace(':', '-C').replace('"', '-D').replace('/', '-F')
        safe_name = safe_name.replace('\\', '-B')

        if is_coroutine:
            filename = f"_{safe_name}.sk"
        elif is_class:
            filename = f"!{safe_name}C.sk"
        else:
            filename = f"{safe_name}.sk"

        filepath = os.path.join(class_dir, filename)

        lines = []

        sig = self.format_routine_signature(routine)
        lines.append(f"// {name}")
        lines.append(sig)

        if routine.invokable_type in (INVOKABLE_METHOD_FUNC, INVOKABLE_METHOD_MTHD,
                                       INVOKABLE_COROUTINE_FUNC, INVOKABLE_COROUTINE_MTHD):
            subtype = 'func' if routine.invokable_type in (INVOKABLE_METHOD_FUNC, INVOKABLE_COROUTINE_FUNC) else 'mthd'
            lines.append(f"  // [Atomic({subtype})]")
        elif routine.expression:
            body = self.expr_to_code(routine.expression, 2)
            lines.append(f"  {body}")

        lines.append("")

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))


    def decompile(self, output_dir: str):
        t0 = time.time()

        print("\n=== Phase 1: Header ===")
        self.read_header()

        print("\n=== Phase 2: Class Hierarchy ===")
        self.read_class_hierarchy()
        print(f"  {len(self.classes)} classes in hierarchy")

        print("\n=== Phase 3: Compound Types ===")
        self.read_compound_types()

        print("\n=== Phase 4: Class Members ===")
        self.read_class_members()

        remaining = self.r.remaining()
        print(f"\nBytes remaining after parse: {remaining}")
        if remaining > 0:
            print(f"  (This may indicate trailing data or a parse drift)")

        t1 = time.time()
        print(f"\nParsing completed in {t1-t0:.2f}s")

        print(f"\n=== Phase 5: Writing Output to {output_dir} ===")
        self.write_output(output_dir)

        t2 = time.time()
        print(f"Output written in {t2-t1:.2f}s")
        print(f"Total time: {t2-t0:.2f}s")


def main():
    if len(sys.argv) < 3:
        print("Usage: python sk_decompiler.py <Classes.sk-bin> <Classes.sk-sym> [output_dir]")
        print()
        print("Example:")
        print("  python sk_decompiler.py Classes.sk-bin Classes.sk-sym ./decompiled")
        sys.exit(1)

    bin_path = sys.argv[1]
    sym_path = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else "./decompiled"

    decompiler = SkDecompiler(sym_path, bin_path)
    decompiler.decompile(output_dir)


if __name__ == '__main__':
    main()
