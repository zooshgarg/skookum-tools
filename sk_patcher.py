
import struct
import os
import sys
import time
import zlib
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

from sk_decompiler import (
    SkDecompiler, SymbolTable, BinaryReader,
    SkClass, SkRoutine, SkParams, SkParam, ClassRef,
    EXPR_DEFAULT, EXPR_IDENT_LOCAL, EXPR_IDENT_MEMBER, EXPR_IDENT_RAW_MEMBER,
    EXPR_IDENT_CLASS_MEMBER, EXPR_RAW_MEMBER_ASSIGN, EXPR_RAW_MEMBER_INVOKE,
    EXPR_OBJECT_ID, EXPR_LITERAL, EXPR_LITERAL_LIST,
    EXPR_CLOSURE_METHOD, EXPR_CLOSURE_COROUTINE,
    EXPR_BIND, EXPR_CAST, EXPR_CONVERSION, EXPR_CODE,
    EXPR_CONDITIONAL, EXPR_CASE, EXPR_WHEN, EXPR_UNLESS,
    EXPR_LOOP, EXPR_LOOP_EXIT,
    EXPR_INVOKE, EXPR_INVOKE_SYNC, EXPR_INVOKE_RACE, EXPR_INVOKE_CASCADE,
    EXPR_INVOKE_CLOSURE_METHOD, EXPR_INVOKE_CLOSURE_COROUTINE,
    EXPR_INSTANTIATE, EXPR_COPY_INVOKE,
    EXPR_CONCURRENT_SYNC, EXPR_CONCURRENT_RACE, EXPR_CONCURRENT_BRANCH,
    EXPR_CHANGE, EXPR_NIL_COALESCING,
    LIT_BOOLEAN, LIT_INTEGER, LIT_REAL, LIT_STRING, LIT_SYMBOL, LIT_CLASS,
    LIT_NIL, LIT_THIS, LIT_THIS_CLASS, LIT_THIS_CODE, LIT_THIS_MIND,
    INVOKE_INVALID, INVOKE_COROUTINE,
    INVOKE_METHOD_ON_INSTANCE, INVOKE_METHOD_ON_CLASS,
    INVOKE_METHOD_ON_INSTANCE_CLASS, INVOKE_METHOD_ON_CLASS_INSTANCE,
    INVOKE_METHOD_BOOL_AND, INVOKE_METHOD_BOOL_OR,
    INVOKE_METHOD_BOOL_NAND, INVOKE_METHOD_BOOL_NOR,
    INVOKE_METHOD_ASSERT, INVOKE_METHOD_ASSERT_NO_LEAK,
    CLASS_TYPE_CLASS, CLASS_TYPE_METACLASS, CLASS_TYPE_TYPED_CLASS,
    CLASS_TYPE_INVOKABLE_CLASS, CLASS_TYPE_CLASS_UNION,
    INVOKABLE_METHOD, INVOKABLE_METHOD_FUNC, INVOKABLE_METHOD_MTHD,
    INVOKABLE_COROUTINE, INVOKABLE_COROUTINE_FUNC, INVOKABLE_COROUTINE_MTHD,
    PARAM_UNARY, PARAM_UNARY_DEFAULT, PARAM_GROUP,
    INVOKE_TIME_IMMEDIATE, INVOKE_TIME_DURATIONAL, INVOKE_TIME_ANY,
    OBJID_FLAG_POSSIBLE, OBJID_FLAG_IDENTIFIER,
)

class BinaryWriter:
    __slots__ = ('buf',)

    def __init__(self):
        self.buf = bytearray()

    def u8(self, v: int):
        self.buf.append(v & 0xFF)

    def u16(self, v: int):
        self.buf.extend(struct.pack('<H', v & 0xFFFF))

    def i16(self, v: int):
        self.buf.extend(struct.pack('<h', v))

    def u32(self, v: int):
        self.buf.extend(struct.pack('<I', v & 0xFFFFFFFF))

    def i32(self, v: int):
        self.buf.extend(struct.pack('<i', v))

    def u64(self, v: int):
        self.buf.extend(struct.pack('<Q', v))

    def f32(self, v: float):
        self.buf.extend(struct.pack('<f', v))

    def raw(self, data: bytes):
        self.buf.extend(data)

    @property
    def pos(self) -> int:
        return len(self.buf)

    def getvalue(self) -> bytes:
        return bytes(self.buf)


class SkRecompiler:

    def __init__(self, decompiler: SkDecompiler):
        self.d = decompiler
        self.w = BinaryWriter()

    def write_symbol(self, sym_id: int):
        self.w.u32(sym_id)

    def write_bind_name(self, name: str):
        encoded = name.encode('ascii')
        self.w.u16(len(encoded))
        self.w.raw(encoded)
        self.w.u8(0)

    def write_string(self, s: str):
        encoded = s.encode('utf-8')
        self.w.u32(len(encoded))
        self.w.raw(encoded)

    def write_class_ref(self, class_id: int):
        self.w.u32(class_id)

    def write_class_ref_typed(self, cref: ClassRef):
        self.w.u8(cref.ctype)
        self.w.u32(cref.raw_id)

    def write_header(self):
        self.w.u32(self.d.code_id)
        self.w.u32(self.d.checksum_folders)
        self.w.u32(self.d.checksum_files)
        self.w.u64(self.d.session_guid)
        self.w.u32(self.d.revision)
        self.write_string(self.d.project_name)
        self.write_string(self.d.project_path)
        self.write_string(self.d.default_project_path)
        self.w.u32(self.d.alloc_bytes)
        self.w.u32(self.d.debug_bytes)
        self.w.u32(self.d.class_count)

    def write_class_hierarchy(self, cls: SkClass):
        self.write_symbol(cls.name_id)
        self.w.u32(cls.flags)
        self.w.u32(cls.annotation_flags)
        self.write_bind_name(cls.bind_name)
        self.w.u16(len(cls.subclasses))
        for sub in cls.subclasses:
            self.write_class_hierarchy(sub)

    def write_typed_class_full(self, tc: dict):
        self.write_class_ref(tc['class_id'])
        self.write_class_ref_typed(tc['item_type'])

    def write_invokable_class_full(self, ic: dict):
        self.write_class_ref(ic['class_id'])
        self.write_parameters(ic['params'])
        self.w.u8(ic['invoke_time'])

    def write_class_union_full(self, cu: dict):
        self.write_class_ref_typed(cu['common_class'])
        self.w.u8(len(cu['members']))
        for m in cu['members']:
            self.write_class_ref_typed(m)

    def write_compound_types(self):
        self.write_symbol(self.d.startup_class_id)
        self.w.u32(len(self.d.typed_classes))
        self.w.u32(len(self.d.invokable_classes))
        self.w.u32(len(self.d.class_unions))
        for cu in self.d.class_unions:
            self.write_class_union_full(cu)
        for tc in self.d.typed_classes:
            self.write_typed_class_full(tc)
        for ic in self.d.invokable_classes:
            self.write_invokable_class_full(ic)

    def write_parameters(self, params: SkParams):
        self.w.u8(len(params.params))
        for p in params.params:
            self.write_parameter(p)
        self.w.u8(len(params.return_params))
        for name, name_id, ctype in params.return_params:
            self.w.u32(name_id)
            self.write_class_ref_typed(ctype)
        self.write_class_ref_typed(params.result_type)

    def write_parameter(self, param: SkParam):
        if param.kind == PARAM_GROUP:
            header = (len(param.group_classes) << 2) | PARAM_GROUP
            self.w.u8(header)
            self.w.u32(param.name_id)
            for gc in param.group_classes:
                self.write_class_ref_typed(gc)
        elif param.kind == PARAM_UNARY_DEFAULT:
            header = (param.default_expr_type << 2) | PARAM_UNARY_DEFAULT
            self.w.u8(header)
            self.w.u32(param.name_id)
            self.write_class_ref_typed(param.class_type)
            self.w.u16(param.default_debug_pos)
            self.write_expression_data(param.default_expr_type, param.default_expr)
        else:
            header = (param.type_info << 2) | PARAM_UNARY
            self.w.u8(header)
            self.w.u32(param.name_id)
            self.write_class_ref_typed(param.class_type)

    def write_typed_expression(self, texpr):
        if texpr is None:
            self.w.u8(EXPR_DEFAULT)
            return
        self.w.u8(texpr['type'])
        self.w.u16(texpr['debug_pos'])
        self.write_expression_data(texpr['type'], texpr['expr'])

    def write_expression_data(self, expr_type: int, expr):
        if expr is None or expr_type == EXPR_DEFAULT:
            return
        tag = expr[0]
        writers = {
            'ident_local': self._write_ident_local,
            'ident_member': self._write_ident_member,
            'ident_raw_member': self._write_ident_raw_member,
            'ident_class_member': self._write_ident_class_member,
            'raw_member_assign': self._write_raw_member_assign,
            'raw_member_invoke': self._write_raw_member_invoke,
            'object_id': self._write_object_id,
            'literal': self._write_literal,
            'literal_list': self._write_literal_list,
            'closure': self._write_closure,
            'bind': self._write_bind,
            'cast': self._write_cast,
            'conversion': self._write_conversion,
            'code': self._write_code,
            'conditional': self._write_conditional,
            'case': self._write_case,
            'when': self._write_when,
            'unless': self._write_unless,
            'loop': self._write_loop,
            'loop_exit': self._write_loop_exit,
            'nil_coalescing': self._write_nil_coalescing,
            'invoke': self._write_invoke,
            'invoke_sync': self._write_invoke_sync,
            'invoke_race': self._write_invoke_race,
            'invoke_cascade': self._write_invoke_cascade,
            'invoke_closure': self._write_invoke_closure,
            'instantiate': self._write_instantiate,
            'copy_invoke': self._write_copy_invoke,
            'concurrent_sync': self._write_concurrent_sync,
            'concurrent_race': self._write_concurrent_race,
            'concurrent_branch': self._write_concurrent_branch,
            'change': self._write_change,
        }
        writer = writers.get(tag)
        if writer is None:
            raise ValueError(f"Unknown expression tag '{tag}'")
        writer(expr)

    def _write_ident_local(self, expr):
        _, name, name_id, data_idx = expr
        self.w.u32(name_id)
        self.w.u16(data_idx)

    def _write_ident_member(self, expr):
        _, name, name_id, data_idx, owner = expr
        self.w.u32(name_id)
        self.w.u16(data_idx)
        self.write_typed_expression(owner)

    def _write_ident_raw_member(self, expr):
        _, name, name_id, data_idx, owner, owner_class_id, owner_class = expr
        self.w.u32(name_id)
        self.w.u16(data_idx)
        self.write_typed_expression(owner)
        self.write_class_ref(owner_class_id)

    def _write_ident_class_member(self, expr):
        _, name, name_id, data_idx, owner_class_id, owner_class = expr
        self.w.u32(name_id)
        self.w.u16(data_idx)
        self.write_class_ref(owner_class_id)

    def _write_raw_member_base(self, owner, mc_id, mc, mi, cascade):
        self.write_typed_expression(owner)
        self.write_class_ref(mc_id)
        self.w.u16(mi)
        self.w.u8(len(cascade))
        if cascade and mc_id == 0xa475f943:
            import sys
            offset = len(self.w.buf)
            print(f'  WRITE_BYTES at {hex(offset)}: mc_id={mc_id:#x}, mi={mi}, cascade_count={len(cascade)}', file=sys.stderr)
        for cc_id, cc, ci in cascade:
            self.write_class_ref(cc_id)
            self.w.u16(ci)

    def _write_raw_member_assign(self, expr):
        _, owner, mc_id, mc, mi, cascade, value = expr
        self._write_raw_member_base(owner, mc_id, mc, mi, cascade)
        self.write_typed_expression(value)

    def _write_raw_member_invoke(self, expr):
        _, owner, mc_id, mc, mi, cascade, call = expr
        self._write_raw_member_base(owner, mc_id, mc, mi, cascade)
        self._write_invoke_typed(call)

    def _write_object_id(self, expr):
        _, name, obj_class_id, obj_class, flags = expr
        encoded = name.encode('ascii')
        self.w.u16(len(encoded))
        self.w.raw(encoded)
        self.w.u8(0)
        self.write_class_ref(obj_class_id)
        self.w.u8(flags)

    def _write_literal(self, expr):
        lit_type = expr[1]
        val = expr[2]
        LIT_KINDS = {
            'Boolean': LIT_BOOLEAN, 'Integer': LIT_INTEGER, 'Real': LIT_REAL,
            'String': LIT_STRING, 'Symbol': LIT_SYMBOL, 'Class': LIT_CLASS,
            'nil': LIT_NIL, 'this': LIT_THIS, 'this_class': LIT_THIS_CLASS,
            'this_code': LIT_THIS_CODE, 'this_mind': LIT_THIS_MIND,
        }
        kind = LIT_KINDS[lit_type]
        self.w.u8(kind)
        if lit_type == 'Boolean':
            self.w.u32(val)
        elif lit_type == 'Integer':
            self.w.i32(val)
        elif lit_type == 'Real':
            self.w.f32(val)
        elif lit_type == 'String':
            encoded = val.encode('utf-8')
            self.w.u32(len(encoded))
            self.w.raw(encoded)
        elif lit_type == 'Symbol':
            self.w.u32(expr[3])
        elif lit_type == 'Class':
            self.w.u32(expr[3])

    def _write_literal_list(self, expr):
        _, list_class_id, list_class, call_type, call, items = expr
        self.write_class_ref(list_class_id)
        self.w.u8(call_type)
        if call_type != INVOKE_INVALID:
            self._write_invoke_base(call)
        self.w.u16(len(items))
        for item in items:
            self.write_typed_expression(item)

    def _write_closure(self, expr):
        _, is_method, receiver, captured, params, inv_data_size, ann_flags, body = expr
        self.write_typed_expression(receiver)
        self.w.u32(len(captured))
        for cname, cname_id, cidx in captured:
            self.w.u32(cname_id)
            self.w.u16(cidx)
        self.write_parameters(params)
        self.w.u16(inv_data_size)
        self.w.u32(ann_flags)
        self.write_typed_expression(body)

    def _write_bind(self, expr):
        _, ident, value = expr
        self.write_typed_expression(ident)
        self.write_typed_expression(value)

    def _write_cast(self, expr):
        _, cast_type, value = expr
        self.write_class_ref_typed(cast_type)
        self.write_typed_expression(value)

    def _write_conversion(self, expr):
        _, conv_class_id, conv_class, vtable_idx, value = expr
        self.write_class_ref(conv_class_id)
        self.w.u16(vtable_idx)
        self.write_typed_expression(value)

    def _write_code(self, expr):
        _, start_idx, temp_vars, stmts = expr
        self.w.u16(start_idx)
        self.w.u16(len(temp_vars))
        for tv_name, tv_id in temp_vars:
            self.w.u32(tv_id)
        self.w.u32(len(stmts))
        for stmt in stmts:
            self.write_typed_expression(stmt)

    def _write_conditional(self, expr):
        _, clauses = expr
        self.w.u32(len(clauses))
        for test, body in clauses:
            self.write_typed_expression(test)
            self.write_typed_expression(body)

    def _write_case(self, expr):
        _, compare, clauses = expr
        self.write_typed_expression(compare)
        self.w.u32(len(clauses))
        for test, body in clauses:
            self.write_typed_expression(test)
            self.write_typed_expression(body)

    def _write_when(self, expr):
        _, clause, test = expr
        self.write_typed_expression(clause)
        self.write_typed_expression(test)

    def _write_unless(self, expr):
        _, clause, test = expr
        self.write_typed_expression(clause)
        self.write_typed_expression(test)

    def _write_loop(self, expr):
        _, loop_name_id, body = expr
        self.w.u32(loop_name_id)
        self.write_typed_expression(body)

    def _write_loop_exit(self, expr):
        _, loop_name_id = expr
        self.w.u32(loop_name_id)

    def _write_nil_coalescing(self, expr):
        _, trial, alternate = expr
        self.write_typed_expression(trial)
        self.write_typed_expression(alternate)

    def _write_invoke_base(self, call: dict):
        self.w.u32(call['name_id'])
        self.w.u16(call['vtable_idx'])
        self.w.u32(call['scope_id'])
        args = call.get('args', [])
        self.w.u8(len(args))
        for a in args:
            self.write_typed_expression(a)
        ret_args = call.get('ret_args', [])
        self.w.u8(len(ret_args))
        for ra in ret_args:
            self.write_typed_expression(ra)

    def _write_invoke_typed(self, call):
        if call is None:
            self.w.u8(INVOKE_INVALID)
            return
        self.w.u8(call['invoke_type'])
        self._write_invoke_base(call)

    def _write_invoke(self, expr):
        _, receiver, call = expr
        self.write_typed_expression(receiver)
        self._write_invoke_typed(call)

    def _write_invoke_sync(self, expr):
        _, receiver, call = expr
        self.write_typed_expression(receiver)
        self._write_invoke_typed(call)

    def _write_invoke_race(self, expr):
        _, receiver, call = expr
        self.write_typed_expression(receiver)
        self._write_invoke_typed(call)

    def _write_invoke_cascade(self, expr):
        _, receiver, calls = expr
        self.write_typed_expression(receiver)
        self.w.u8(len(calls))
        for c in calls:
            self._write_invoke_typed(c)

    def _write_invoke_closure(self, expr):
        _, receiver, params, args, ret_args = expr
        self.write_parameters(params)
        self.w.u8(len(args))
        for a in args:
            self.write_typed_expression(a)
        self.w.u8(len(ret_args))
        for ra in ret_args:
            self.write_typed_expression(ra)
        self.write_typed_expression(receiver)

    def _write_instantiate(self, expr):
        _, inst_class_id, inst_class, ctor = expr
        self.write_class_ref(inst_class_id)
        self._write_invoke_base(ctor)

    def _write_copy_invoke(self, expr):
        _, copy_class_id, copy_class, ctor, method = expr
        self.write_class_ref(copy_class_id)
        self._write_invoke_base(ctor)
        self._write_invoke_base(method)

    def _write_concurrent_sync(self, expr):
        _, exprs = expr
        self.w.u8(len(exprs))
        for e in exprs:
            self.write_typed_expression(e)

    def _write_concurrent_race(self, expr):
        _, exprs = expr
        self.w.u8(len(exprs))
        for e in exprs:
            self.write_typed_expression(e)

    def _write_concurrent_branch(self, expr):
        _, captured, params, inv_data_size, ann_flags, body = expr
        self.w.u32(len(captured))
        for cname, cname_id, cidx in captured:
            self.w.u32(cname_id)
            self.w.u16(cidx)
        self.write_parameters(params)
        self.w.u16(inv_data_size)
        self.w.u32(ann_flags)
        self.write_typed_expression(body)

    def _write_change(self, expr):
        _, mind, body = expr
        self.write_typed_expression(mind)
        self.write_typed_expression(body)

    def write_class_members(self):
        self.w.u32(len(self.d.class_list))
        for cls in self.d.class_list:
            self.write_class_ref(cls.name_id)
            self.write_class_body(cls)

    def write_class_body(self, cls: SkClass):
        self.w.u16(len(cls.data_members))
        for name, name_id, ctype in cls.data_members:
            self.w.u32(name_id)
            self.write_class_ref_typed(ctype)
        self.w.u16(len(cls.raw_data_members))
        for name, name_id, ctype, bname in cls.raw_data_members:
            self.w.u32(name_id)
            self.write_class_ref_typed(ctype)
            self.write_bind_name(bname)
        self.w.u16(len(cls.class_data_members))
        for name, name_id, ctype in cls.class_data_members:
            self.w.u32(name_id)
            self.write_class_ref_typed(ctype)
        self.w.u32(len(cls.instance_methods))
        for routine in cls.instance_methods:
            self.write_routine(routine)
        self.w.u32(len(cls.class_methods))
        for routine in cls.class_methods:
            self.write_routine(routine)
        self.w.u32(len(cls.coroutines))
        for routine in cls.coroutines:
            self.write_routine(routine)

    def write_routine(self, routine: SkRoutine):
        self.w.u8(routine.invokable_type)
        self.w.u32(routine.name_id)
        self.write_parameters(routine.params)
        self.w.u16(routine.invoked_data_array_size)
        self.w.u32(routine.annotation_flags)
        if routine.invokable_type in (INVOKABLE_METHOD, INVOKABLE_COROUTINE):
            self.write_typed_expression(routine.expression)

    def compile(self) -> bytes:
        self.write_header()
        root = self.d.class_list[0]
        self.write_class_hierarchy(root)
        self.write_compound_types()
        self.write_class_members()
        return self.w.getvalue()


def write_sk_sym(symbols: SymbolTable, output_path: str):
    w = BinaryWriter()
    w.u32(len(symbols.id_to_name))
    for sym_id, name in symbols.id_to_name.items():
        w.u32(sym_id)
        encoded = name.encode('ascii')
        w.u8(len(encoded))
        w.raw(encoded)
    with open(output_path, 'wb') as f:
        f.write(w.getvalue())
    print(f"Wrote {len(symbols.id_to_name)} symbols to {output_path}")


def sk_symbol_id(name: str) -> int:
    return zlib.crc32(name.encode('ascii')) & 0xFFFFFFFF


class ParseError(Exception):
    def __init__(self, msg, source="", pos=0):
        self.pos = pos
        line = source[:pos].count('\n') + 1
        col = pos - source[:pos].rfind('\n')
        super().__init__(f"Line {line}, col {col}: {msg}")


class SkParser:

    def __init__(self, symbols: SymbolTable, decomp: SkDecompiler):
        self.symbols = symbols
        self.decomp = decomp
        self.source = ""
        self.pos = 0
        self.current_class: Optional[SkClass] = None

        self.local_vars: Dict[str, int] = {}
        self.next_data_idx = 0
        self.temp_vars: List[Tuple[str, int]] = []
        self._local_var_types: Dict[str, str] = {}
        self._local_var_class_refs: Dict[str, 'ClassRef'] = {}
        self._outer_locals: Dict[str, int] = {}
        self._outer_local_types: Dict[str, str] = {}
        self._outer_local_class_refs: Dict[str, 'ClassRef'] = {}
        self._closure_captures: List[Tuple[str, int, int]] = []
        self._in_class_method: bool = False

        self._method_db: Dict[Tuple[str, str], Tuple[int, Optional[ClassRef]]] = {}
        self._vtable_i: Dict[str, Dict[str, int]] = {}
        self._vtable_c: Dict[str, Dict[str, int]] = {}
        self._build_vtables()

    def _build_vtables(self):
        for cls in self.decomp.class_list:
            for routine_list in (cls.instance_methods, cls.class_methods, cls.coroutines):
                for routine in routine_list:
                    result_type = routine.params.result_type if routine.params else None
                    key = (cls.name, routine.name)
                    self._method_db[key] = (0, result_type)

        root = self.decomp.classes.get('Object')
        if root:
            self._build_vtables_recurse(root)

    def _build_vtables_recurse(self, cls):
        if cls.superclass:
            super_vt_i = dict(self._vtable_i.get(cls.superclass.name, {}))
            super_vt_c = dict(self._vtable_c.get(cls.superclass.name, {}))
        else:
            super_vt_i = {}
            super_vt_c = {}

        vt_i = dict(super_vt_i)
        vt_c = dict(super_vt_c)

        next_i = max(vt_i.values(), default=-1) + 1
        next_c = max(vt_c.values(), default=-1) + 1

        for method in cls.instance_methods:
            if method.name not in vt_i:
                vt_i[method.name] = next_i
                next_i += 1
        for coroutine in cls.coroutines:
            if coroutine.name not in vt_i:
                vt_i[coroutine.name] = next_i
                next_i += 1
        for method in cls.class_methods:
            if method.name not in vt_c:
                vt_c[method.name] = next_c
                next_c += 1

        self._vtable_i[cls.name] = vt_i
        self._vtable_c[cls.name] = vt_c

        for sub in cls.subclasses:
            self._build_vtables_recurse(sub)

    def _infer_ast_type(self, node, ctx_class: str) -> Optional[str]:
        if node is None:
            return ctx_class
        if isinstance(node, dict) and 'expr' in node:
            node = node['expr']
        if not isinstance(node, tuple) or len(node) == 0:
            return None
        tag = node[0]
        if tag == 'literal' and len(node) > 1:
            lit_type = node[1]
            if lit_type == 'this':
                return ctx_class
            return {'Boolean': 'Boolean', 'Integer': 'Integer', 'Real': 'Real',
                    'String': 'String', 'Symbol': 'Symbol'}.get(lit_type)
        if tag == 'instantiate' and len(node) > 2:
            return node[2]
        if tag == 'ident_raw_member' and len(node) > 6:
            member_name = node[1]
            owner_class_name = node[6]
            owner_cls = self.decomp.classes.get(owner_class_name)
            while owner_cls:
                for dm_name, dm_id, dm_type, bname in owner_cls.raw_data_members:
                    if dm_name == member_name:
                        return dm_type
                owner_cls = owner_cls.superclass
            return node[6]
        if tag in ('invoke', 'invoke_sync', 'invoke_race') and len(node) >= 3:
            call = node[2]
            if isinstance(call, dict):
                recv = self._infer_ast_type(node[1], ctx_class)
                if recv:
                    return self._infer_return_type(recv, call.get('name', ''))
        if tag == 'cast' and len(node) > 1:
            ct = node[1]
            return ct.display if isinstance(ct, ClassRef) else None
        if tag == 'conversion' and len(node) > 2:
            return node[2]
        return None

    def _lookup_vtable(self, scope: str, name: str, receiver_class: str = None) -> int:
        if receiver_class and not isinstance(receiver_class, str):
            receiver_class = getattr(receiver_class, 'display', str(receiver_class))
        if scope and not isinstance(scope, str):
            scope = getattr(scope, 'display', str(scope))
        if receiver_class in ('ThisClass_', 'ItemClass_'):
            receiver_class = self.current_class.name if self.current_class else receiver_class
        if receiver_class and receiver_class.startswith('<') and receiver_class.endswith('>'):
            receiver_class = receiver_class[1:-1]
        if receiver_class and '|' in receiver_class:
            parts = receiver_class.split('|')
            receiver_class = parts[0].strip()
        if receiver_class and '{' in receiver_class:
            receiver_class = receiver_class[:receiver_class.index('{')]
        lookup_class = receiver_class or scope
        if lookup_class:
            vt_i = self._vtable_i.get(lookup_class)
            if vt_i and name in vt_i:
                return vt_i[name]
            vt_c = self._vtable_c.get(lookup_class)
            if vt_c and name in vt_c:
                return vt_c[name]
        if receiver_class:
            cls = self.decomp.classes.get(receiver_class)
            while cls:
                vt_i = self._vtable_i.get(cls.name)
                if vt_i and name in vt_i:
                    return vt_i[name]
                vt_c = self._vtable_c.get(cls.name)
                if vt_c and name in vt_c:
                    return vt_c[name]
                cls = cls.superclass
        return 0xFFFF

    def _infer_return_type(self, receiver_class: str, method_name: str) -> Optional[str]:
        rc = receiver_class
        if rc in ('ThisClass_', 'ItemClass_'):
            rc = self.current_class.name if self.current_class else rc
        if rc and rc.startswith('<') and rc.endswith('>'):
            rc = rc[1:-1]
        if rc and '{' in rc:
            rc = rc[:rc.index('{')]
        cls = self.decomp.classes.get(rc)
        while cls:
            entry = self._method_db.get((cls.name, method_name))
            if entry and entry[1] is not None:
                rt = entry[1]
                rt_str = rt.display if isinstance(rt, ClassRef) else str(rt)
                if rt_str in ('ThisClass_', 'ItemClass_') and receiver_class:
                    base_rc = receiver_class
                    if base_rc.startswith('<') and base_rc.endswith('>'):
                        base_rc = base_rc[1:-1]
                    if '{' in base_rc:
                        base_rc = base_rc[:base_rc.index('{')]
                    return base_rc
                return rt_str
            cls = cls.superclass
        return None

    def _infer_expr_type(self, expr) -> Optional[str]:
        if expr is None:
            return self.current_class.name if self.current_class else None
        if isinstance(expr, dict) and 'expr' in expr:
            expr = expr['expr']
        if not isinstance(expr, tuple) or len(expr) == 0:
            return None
        result = self._infer_expr_type_inner(expr)
        if result is not None and not isinstance(result, str):
            result = getattr(result, 'display', str(result))
        return result

    def _infer_expr_type_inner(self, expr) -> Optional[str]:
        tag = expr[0]
        if tag == 'ident_local' and len(expr) > 1:
            return self._local_var_types.get(expr[1])
        if tag == 'literal' and len(expr) > 1:
            lit_type = expr[1]
            if lit_type == 'this':
                return self.current_class.name if self.current_class else None
            if lit_type == 'Class' and len(expr) > 2:
                return expr[2]
            return {'Boolean': 'Boolean', 'Integer': 'Integer', 'Real': 'Real',
                    'String': 'String', 'Symbol': 'Symbol', 'nil': 'None'}.get(lit_type)
        if tag == 'literal_list':
            return 'List'
        if tag == 'instantiate' and len(expr) > 2:
            return expr[2]
        if tag in ('invoke', 'invoke_sync', 'invoke_race') and len(expr) >= 3:
            call = expr[2]
            if isinstance(call, dict):
                recv_type = self._infer_expr_type(expr[1])
                if recv_type:
                    return self._infer_return_type(recv_type, call.get('name', ''))
        if tag in ('invoke_closure',) and len(expr) >= 3:
            params = expr[2]
            if isinstance(params, SkParams) and params.result_type:
                rt = params.result_type
                return rt.display if isinstance(rt, ClassRef) else str(rt)
        if tag == 'conditional' and len(expr) > 1:
            clauses = expr[1]
            for test, body in clauses:
                if body:
                    return self._infer_expr_type(body)
        if tag == 'code' and len(expr) >= 4:
            stmts = expr[3]
            if stmts:
                return self._infer_expr_type(stmts[-1])
        if tag == 'cast' and len(expr) > 1:
            ct = expr[1]
            return ct.display if isinstance(ct, ClassRef) else None
        if tag == 'conversion' and len(expr) > 2:
            return expr[2]
        if tag == 'ident_raw_member' and len(expr) > 6:
            member_name = expr[1]
            owner_class_name = expr[6]
            owner_cls = self.decomp.classes.get(owner_class_name)
            while owner_cls:
                for dm_name, dm_id, dm_type, bname in owner_cls.raw_data_members:
                    if dm_name == member_name:
                        return dm_type
                owner_cls = owner_cls.superclass
            return expr[6]
        if tag == 'ident_class_member' and len(expr) > 5:
            member_name = expr[1]
            owner_class_name = expr[5]
            owner_cls = self.decomp.classes.get(owner_class_name)
            prefixed_name = f"@@{member_name}"
            while owner_cls:
                for dm_name, dm_id, dm_type in owner_cls.class_data_members:
                    if dm_name == member_name or dm_name == prefixed_name:
                        return dm_type.display if isinstance(dm_type, ClassRef) else str(dm_type)
                owner_cls = owner_cls.superclass
        if tag == 'ident_member' and len(expr) > 4:
            member_name = expr[1]
            prefixed_name = f"@{member_name}"
            cls = self.current_class
            while cls:
                for dm_name, dm_id, dm_type in cls.data_members:
                    if dm_name == member_name or dm_name == prefixed_name:
                        return dm_type.display if isinstance(dm_type, ClassRef) else str(dm_type)
                cls = cls.superclass
        if tag == 'raw_member_invoke' and len(expr) > 5:
            owner_class = expr[3] if len(expr) > 3 else None
            member_idx = expr[4] if len(expr) > 4 else None
            call = expr[6] if len(expr) > 6 else (expr[5] if len(expr) > 5 else None)
            if isinstance(call, dict) and isinstance(owner_class, str):
                owner_cls = self.decomp.classes.get(owner_class)
                raw_type = None
                if owner_cls and isinstance(member_idx, int) and member_idx < len(owner_cls.raw_data_members):
                    _, _, raw_type_ref, _ = owner_cls.raw_data_members[member_idx]
                    raw_type = raw_type_ref.display if isinstance(raw_type_ref, ClassRef) else str(raw_type_ref)
                if raw_type:
                    rt = self._infer_return_type(raw_type, call.get('name', ''))
                    if rt:
                        return rt
                    return raw_type
        if tag == 'raw_member_assignment':
            return None
        if tag == 'code' and len(expr) > 3:
            stmts = expr[3]
            if stmts:
                return self._infer_expr_type(stmts[-1])
        return None

    def _find_raw_member(self, raw_name: str, search_class: SkClass = None, global_fallback: bool = False) -> Optional[Tuple[int, str, int]]:
        if search_class:
            cls = search_class
            while cls:
                for i, (dm_name, dm_id, dm_type, bname) in enumerate(cls.raw_data_members):
                    if dm_name == raw_name:
                        return (i, cls.name, self.sym_id(cls.name))
                cls = cls.superclass
            if not global_fallback:
                return None

        for cls in self.decomp.class_list:
            for i, (dm_name, dm_id, dm_type, bname) in enumerate(cls.raw_data_members):
                if dm_name == raw_name:
                    return (i, cls.name, self.sym_id(cls.name))

        return None


    def sym_id(self, name: str) -> int:
        if not name:
            return 0
        if name in self.symbols.name_to_id:
            return self.symbols.name_to_id[name]
        sid = sk_symbol_id(name)
        self.symbols.id_to_name[sid] = name
        self.symbols.name_to_id[name] = sid
        return sid

    def class_ref_for_name(self, name: str) -> ClassRef:
        sid = self.sym_id(name)
        return ClassRef(CLASS_TYPE_CLASS, sid, name)

    def resolve_class_ref_typed(self, type_str: str) -> ClassRef:
        type_str = type_str.strip()

        if type_str.startswith('<') and type_str.endswith('>') and '|' not in type_str:
            inner = type_str[1:-1]
            sid = self.sym_id(inner)
            return ClassRef(CLASS_TYPE_METACLASS, sid, type_str)

        if type_str.startswith('<') and '|' in type_str:
            for i, cu in enumerate(self.decomp.class_unions):
                if cu and cu['display'] == type_str:
                    return ClassRef(CLASS_TYPE_CLASS_UNION, i, type_str)
            raise ParseError(f"Unknown class union: {type_str}", self.source, self.pos)

        if '{' in type_str and type_str.endswith('}'):
            for i, tc in enumerate(self.decomp.typed_classes):
                if tc and tc['display'] == type_str:
                    return ClassRef(CLASS_TYPE_TYPED_CLASS, i, type_str)
            raise ParseError(f"Unknown typed class: {type_str}", self.source, self.pos)

        if type_str.startswith('(') or type_str.startswith('_(') or type_str.startswith('+('):
            for i, ic in enumerate(self.decomp.invokable_classes):
                if ic and ic['display'] == type_str:
                    return ClassRef(CLASS_TYPE_INVOKABLE_CLASS, i, type_str)
            raise ParseError(f"Unknown invokable class: {type_str}", self.source, self.pos)

        return self.class_ref_for_name(type_str)


    def error(self, msg):
        raise ParseError(msg, self.source, self.pos)

    def at_end(self) -> bool:
        return self.pos >= len(self.source)

    def peek(self, offset=0) -> str:
        p = self.pos + offset
        if p >= len(self.source):
            return '\0'
        return self.source[p]

    def advance(self) -> str:
        ch = self.source[self.pos]
        self.pos += 1
        return ch

    def match(self, ch: str) -> bool:
        if not self.at_end() and self.source[self.pos] == ch:
            self.pos += 1
            return True
        return False

    def expect(self, ch: str):
        if self.at_end() or self.source[self.pos] != ch:
            self.error(f"Expected '{ch}', got '{self.peek()}'")
        self.pos += 1

    def skip_ws(self):
        while self.pos < len(self.source):
            ch = self.source[self.pos]
            if ch in ' \t\r\n':
                self.pos += 1
            elif ch == '/' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '/':
                while self.pos < len(self.source) and self.source[self.pos] != '\n':
                    self.pos += 1
            else:
                break

    def skip_ws_inline(self):
        while self.pos < len(self.source) and self.source[self.pos] in ' \t':
            self.pos += 1

    def check_keyword(self, kw: str) -> bool:
        end = self.pos + len(kw)
        if self.source[self.pos:end] == kw:
            if end >= len(self.source) or not (self.source[end].isalnum() or self.source[end] == '_'):
                return True
        return False

    def match_keyword(self, kw: str) -> bool:
        if self.check_keyword(kw):
            self.pos += len(kw)
            return True
        return False


    def parse_name(self) -> str:
        start = self.pos
        if self.at_end() or not (self.peek().isalnum() or self.peek() == '_'):
            self.error("Expected identifier")
        while not self.at_end() and (self.peek().isalnum() or self.peek() == '_'):
            self.pos += 1
        if not self.at_end() and self.peek() == '?':
            self.pos += 1
        return self.source[start:self.pos]

    def parse_number(self):
        start = self.pos
        negative = False
        if self.peek() == '-':
            negative = True
            self.pos += 1

        radix_start = self.pos
        while not self.at_end() and self.peek().isdigit():
            self.pos += 1
        if not self.at_end() and self.peek() == 'r':
            radix = int(self.source[radix_start:self.pos])
            self.pos += 1
            val_start = self.pos
            while not self.at_end() and (self.peek().isalnum()):
                self.pos += 1
            val = int(self.source[val_start:self.pos], radix)
            if negative:
                val = -val
            return self._make_expr(EXPR_LITERAL, ('literal', 'Integer', val))

        self.pos = radix_start

        is_real = False
        if self.peek() == '.':
            is_real = True
            self.pos += 1
            while not self.at_end() and self.peek().isdigit():
                self.pos += 1
        else:
            if self.peek() == '0' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] in 'xX':
                self.pos += 2
                while not self.at_end() and (self.peek().isdigit() or self.peek() in 'abcdefABCDEF'):
                    self.pos += 1
                val = int(self.source[start:self.pos], 0) if not negative else -int(self.source[start+1:self.pos], 0)
                return self._make_expr(EXPR_LITERAL, ('literal', 'Integer', val))

            while not self.at_end() and self.peek().isdigit():
                self.pos += 1

            if not self.at_end() and self.peek() == '.' and self.pos + 1 < len(self.source) and self.source[self.pos + 1].isdigit():
                is_real = True
                self.pos += 1
                while not self.at_end() and self.peek().isdigit():
                    self.pos += 1

        text = self.source[start:self.pos]
        if negative and not text.startswith('-'):
            text = '-' + text

        if is_real:
            val = struct.unpack('<f', struct.pack('<f', float(text)))[0]
            return self._make_expr(EXPR_LITERAL, ('literal', 'Real', val))
        else:
            val = int(text)
            return self._make_expr(EXPR_LITERAL, ('literal', 'Integer', val))

    def parse_string_literal(self) -> str:
        self.expect('"')
        result = []
        while not self.at_end() and self.peek() != '"':
            ch = self.advance()
            if ch == '\\':
                esc = self.advance()
                if esc == 'n':
                    result.append('\n')
                elif esc == 'r':
                    result.append('\r')
                elif esc == 't':
                    result.append('\t')
                elif esc == '\\':
                    result.append('\\')
                elif esc == '"':
                    result.append('"')
                else:
                    result.append('\\')
                    result.append(esc)
            else:
                result.append(ch)
        self.expect('"')
        return ''.join(result)

    def parse_symbol_literal(self) -> Tuple[str, int]:
        self.expect("'")
        start = self.pos
        while not self.at_end() and (self.peek().isalnum() or self.peek() in '_?'):
            self.pos += 1
        name = self.source[start:self.pos]
        if not name and self.peek() == "'":
            self.error("Empty symbol")
        return name, self.sym_id(name)


    def parse_class_name(self, allow_invokable: bool = False) -> str:
        if self.peek() == '<':
            return self._parse_angle_type()

        if allow_invokable:
            if self.peek() == '(':
                return self._parse_invokable_class_type('')
            if self.peek() in ('_', '+') and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '(':
                prefix = self.advance()
                return self._parse_invokable_class_type(prefix)

        name = self.parse_name()

        if not self.at_end() and self.peek() == '{':
            self.pos += 1
            item = self.parse_class_name()
            self.expect('}')
            return f"{name}{{{item}}}"

        return name

    def _parse_invokable_class_type(self, prefix: str) -> str:
        self.expect('(')
        depth = 1
        start = self.pos
        while not self.at_end() and depth > 0:
            ch = self.source[self.pos]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
            self.pos += 1
        content = self.source[start:self.pos - 1]
        return f"{prefix}({content})"

    def _parse_angle_type(self) -> str:
        self.expect('<')
        types = [self.parse_class_name()]
        while not self.at_end() and self.peek() == '|':
            self.pos += 1
            types.append(self.parse_class_name())
        self.expect('>')
        if len(types) == 1:
            return f"<{types[0]}>"
        return "<" + "|".join(types) + ">"

    def parse_class_ref_typed(self, allow_invokable: bool = False) -> ClassRef:
        type_str = self.parse_class_name(allow_invokable=allow_invokable)
        return self.resolve_class_ref_typed(type_str)


    def _make_expr(self, expr_type: int, expr_tuple) -> dict:
        pos = getattr(self, '_expr_start_pos', self.pos)
        return {'type': expr_type, 'debug_pos': pos & 0xFFFF, 'expr': expr_tuple}


    def parse_expression(self) -> Optional[dict]:
        expr = self._parse_primary()
        if expr is None:
            return None
        return self._parse_postfix(expr)

    def _parse_primary(self) -> Optional[dict]:
        self.skip_ws()
        if self.at_end():
            return None

        self._expr_start_pos = self.pos
        ch = self.peek()

        if ch == '[':
            return self.parse_code_block()

        if ch == '{':
            return self.parse_literal_list()

        if ch == '"':
            val = self.parse_string_literal()
            return self._make_expr(EXPR_LITERAL, ('literal', 'String', val))

        if ch == "'" and (self.pos + 1 < len(self.source) and self.source[self.pos + 1].isalpha()):
            name, sid = self.parse_symbol_literal()
            return self._make_expr(EXPR_LITERAL, ('literal', 'Symbol', name, sid))

        if ch == '^':
            return self.parse_closure()

        if ch == '!' and self.pos + 1 < len(self.source) and (self.source[self.pos + 1].isalpha() or self.source[self.pos + 1] == '_' or self.source[self.pos + 1] == '@'):
            return self.parse_bind()

        if ch == '@':
            return self._parse_member_ident(owner=None)

        if ch.isdigit():
            return self.parse_number()
        if ch == '-' and self.pos + 1 < len(self.source) and (self.source[self.pos + 1].isdigit() or self.source[self.pos + 1] == '.'):
            return self.parse_number()
        if ch == '.' and self.pos + 1 < len(self.source) and self.source[self.pos + 1].isdigit():
            return self.parse_number()

        if ch.isalpha() or ch == '_':
            return self._parse_name_or_keyword()

        return None

    def _parse_name_or_keyword(self) -> Optional[dict]:
        if self.check_keyword('true'):
            self.pos += 4
            return self._make_expr(EXPR_LITERAL, ('literal', 'Boolean', 1))

        if self.check_keyword('false'):
            self.pos += 5
            return self._make_expr(EXPR_LITERAL, ('literal', 'Boolean', 0))

        if self.check_keyword('nil'):
            self.pos += 3
            return self._make_expr(EXPR_LITERAL, ('literal', 'nil', None))

        if self.check_keyword('this_class'):
            self.pos += 10
            return self._make_expr(EXPR_LITERAL, ('literal', 'this_class', None))

        if self.check_keyword('this_code'):
            self.pos += 9
            return self._make_expr(EXPR_LITERAL, ('literal', 'this_code', None))

        if self.check_keyword('this_mind'):
            self.pos += 9
            return self._make_expr(EXPR_LITERAL, ('literal', 'this_mind', None))

        if self.check_keyword('this'):
            self.pos += 4
            return self._make_expr(EXPR_LITERAL, ('literal', 'this', None))

        if self.check_keyword('if'):
            return self.parse_conditional()

        if self.check_keyword('case'):
            return self.parse_case()

        if self.check_keyword('loop'):
            return self.parse_loop()

        if self.check_keyword('exit'):
            return self.parse_exit()

        if self.check_keyword('sync'):
            return self.parse_sync()

        if self.check_keyword('race') and not self.check_keyword('race_invoke'):
            return self.parse_race()

        if self.check_keyword('branch'):
            return self.parse_branch()

        if self.check_keyword('divert'):
            return self.parse_divert()

        if self.check_keyword('change'):
            return self.parse_change()

        name = self.parse_name()
        return self._resolve_name(name)

    def _resolve_name(self, name: str) -> dict:
        if not self.at_end() and self.peek() == '!' and self._is_class_name(name):
            return self._parse_instantiate(name)

        if not self.at_end() and self.peek() == '@' and self._is_class_name(name):
            next_after_at = self.source[self.pos + 1] if self.pos + 1 < len(self.source) else '\0'
            if next_after_at in ("'", '?', '#'):

                return self._parse_object_id(name)
            if next_after_at.isalpha() or next_after_at == '_' or next_after_at == '!':
                return self._parse_scoped_invoke(name)

        if name in self.local_vars:
            data_idx = self.local_vars[name]
            name_id = self.sym_id(name)
            return self._make_expr(EXPR_IDENT_LOCAL, ('ident_local', name, name_id, data_idx))

        if self._outer_locals and name in self._outer_locals:
            name_id = self.sym_id(name)
            outer_idx = self._outer_locals[name]
            existing = None
            for i, (cn, cid, cidx) in enumerate(self._closure_captures):
                if cn == name:
                    existing = i
                    break
            if existing is None:
                self._closure_captures.append((name, name_id, outer_idx))
                data_idx = 0xDEAD
                self.local_vars[name] = data_idx
                if name in self._outer_local_types:
                    self._local_var_types[name] = self._outer_local_types[name]
                if name in self._outer_local_class_refs:
                    self._local_var_class_refs[name] = self._outer_local_class_refs[name]
            else:
                data_idx = self.local_vars[name]
            return self._make_expr(EXPR_IDENT_LOCAL, ('ident_local', name, name_id, data_idx))

        if name in self.decomp.classes and not self._could_be_method_call(name):
            class_id = self.sym_id(name)
            return self._make_expr(EXPR_LITERAL, ('literal', 'Class', name, class_id))

        if not self.at_end() and self.peek() == '(':
            return self._parse_invoke_on_implicit(name, scope=None)

        if name[0].isupper() and name in self.decomp.classes:
            class_id = self.sym_id(name)
            return self._make_expr(EXPR_LITERAL, ('literal', 'Class', name, class_id))

        name_id = self.sym_id(name)
        if name not in self.local_vars:
            self.local_vars[name] = self.next_data_idx
            self.next_data_idx += 1
        data_idx = self.local_vars[name]
        return self._make_expr(EXPR_IDENT_LOCAL, ('ident_local', name, name_id, data_idx))

    def _is_class_name(self, name: str) -> bool:
        return name in self.decomp.classes

    def _could_be_method_call(self, name: str) -> bool:
        if self.at_end():
            return False
        ch = self.peek()
        return ch == '(' or ch == '.'

    def _is_class_method(self, method_name: str, class_name: str = None) -> bool:
        cls_name = class_name or (self.current_class.name if self.current_class else None)
        if not cls_name:
            return False
        if cls_name in ('ThisClass_', 'ItemClass_'):
            cls_name = self.current_class.name if self.current_class else cls_name
        if cls_name.startswith('<') and cls_name.endswith('>'):
            cls_name = cls_name[1:-1]
        if '{' in cls_name:
            cls_name = cls_name[:cls_name.index('{')]
        cls = self.decomp.classes.get(cls_name)
        while cls:
            for r in cls.class_methods:
                if r.name == method_name:
                    return True
            for r in cls.instance_methods:
                if r.name == method_name:
                    return False
            cls = cls.superclass
        return False

    def _parse_postfix(self, expr: dict) -> dict:
        while True:
            self.skip_ws_inline()
            if self.at_end():
                break

            ch = self.peek()

            if ch == '.':
                self.pos += 1
                self.skip_ws()

                if self.peek() == '@':
                    expr = self._parse_member_ident(owner=expr)
                    continue

                method_name = self.parse_name()

                inner = expr.get('expr') if isinstance(expr, dict) else None
                if (inner and isinstance(inner, tuple) and inner[0] == 'ident_raw_member'
                        and method_name not in ('negated', 'not')):
                    expr = self._parse_raw_member_invoke(expr, method_name)
                    continue

                expr = self._parse_invoke_on_receiver(expr, method_name, scope=None)
                continue


            if ch == '<' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '>':
                self.pos += 2
                cast_type = self.parse_class_ref_typed()
                expr = self._make_expr(EXPR_CAST, ('cast', cast_type, expr))
                continue

            if ch == '>' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '>':
                self.pos += 2
                conv_class = self.parse_class_name()
                conv_class_id = self.sym_id(conv_class)
                recv_type = self._infer_expr_type(expr)
                vtable_idx = self._lookup_vtable('', conv_class, receiver_class=recv_type)
                expr = self._make_expr(EXPR_CONVERSION, ('conversion', conv_class_id, conv_class, vtable_idx, expr))
                continue

            if ch == '?' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '?':
                self.pos += 2
                self.skip_ws()
                alt = self.parse_expression()
                expr = self._make_expr(EXPR_NIL_COALESCING, ('nil_coalescing', expr, alt))
                continue

            if ch == ':' and self.pos + 1 < len(self.source) and self.source[self.pos + 1] == '=':
                inner = expr.get('expr') if isinstance(expr, dict) else expr
                if inner and isinstance(inner, tuple) and inner[0] in ('ident_member', 'ident_raw_member', 'ident_class_member'):
                    self.pos += 2
                    self.skip_ws()
                    value = self.parse_expression()
                    if inner[0] == 'ident_raw_member':
                        real_owner, mc_id, mc, mi, cascade = self._unwrap_raw_member_chain(inner)
                        expr = self._make_expr(EXPR_RAW_MEMBER_ASSIGN,
                            ('raw_member_assign', real_owner, mc_id, mc, mi, cascade, value))
                    else:
                        member_type = self._infer_expr_type(expr)
                        assign_call = self._make_call_dict('assign', [value], receiver_class=member_type)
                        expr = self._make_expr(EXPR_INVOKE, ('invoke', expr, assign_call))
                    continue

            if self.check_keyword('when'):
                self.pos += 4
                self.skip_ws()
                test = self.parse_expression()
                expr = self._make_expr(EXPR_WHEN, ('when', expr, test))
                continue
            if self.check_keyword('unless'):
                self.pos += 6
                self.skip_ws()
                test = self.parse_expression()
                expr = self._make_expr(EXPR_UNLESS, ('unless', expr, test))
                continue

            if ch == '%':
                self.pos += 1
                if not self.at_end() and self.peek() == '>':
                    self.pos += 1
                    method_name = self.parse_name()
                    expr = self._parse_invoke_on_receiver(expr, method_name, scope=None, invoke_tag='invoke_race', expr_type=EXPR_INVOKE_RACE)
                else:
                    method_name = self.parse_name()
                    expr = self._parse_invoke_on_receiver(expr, method_name, scope=None, invoke_tag='invoke_sync', expr_type=EXPR_INVOKE_SYNC)
                continue

            if ch == '(':
                args, ret_args = self._parse_args()
                closure_params = self._get_closure_params(expr)
                is_coroutine = self._closure_is_coroutine_call(expr)
                expr_type = EXPR_INVOKE_CLOSURE_COROUTINE if is_coroutine else EXPR_INVOKE_CLOSURE_METHOD
                expr = self._make_expr(expr_type,
                    ('invoke_closure', expr, closure_params, args, ret_args))
                continue

            break

        return expr


    def _get_closure_params(self, closure_expr: dict) -> SkParams:
        inner = closure_expr.get('expr') if isinstance(closure_expr, dict) else None
        if inner and isinstance(inner, tuple):
            if inner[0] == 'ident_local':
                var_name = inner[1]
                cref = self._local_var_class_refs.get(var_name)
                if cref and hasattr(cref, 'ctype') and cref.ctype == CLASS_TYPE_INVOKABLE_CLASS:
                    ic = self.decomp.invokable_classes[cref.raw_id]
                    if ic:
                        return self._resolve_invoke_closure_params(ic['params'])
                type_name = self._local_var_types.get(var_name)
                if type_name and (type_name.startswith('(') or type_name.startswith('_(') or type_name.startswith('+(')):
                    for ic in self.decomp.invokable_classes:
                        if ic and ic['display'] == type_name:
                            return self._resolve_invoke_closure_params(ic['params'])
            elif inner[0] in ('ident_member', 'ident_raw_member', 'ident_class_member'):
                member_name = inner[1]
                cls = self.current_class
                while cls:
                    for dm_name, dm_id, dm_type in cls.data_members:
                        if dm_name == member_name:
                            if hasattr(dm_type, 'ctype') and dm_type.ctype == CLASS_TYPE_INVOKABLE_CLASS:
                                ic = self.decomp.invokable_classes[dm_type.raw_id]
                                if ic:
                                    return self._resolve_invoke_closure_params(ic['params'])
                            dm_display = dm_type.display if hasattr(dm_type, 'display') else str(dm_type)
                            if dm_display.startswith('(') or dm_display.startswith('_('):
                                for ic in self.decomp.invokable_classes:
                                    if ic and ic['display'] == dm_display:
                                        return self._resolve_invoke_closure_params(ic['params'])
                    for dm_name, dm_id, dm_type, *_ in cls.class_data_members:
                        if dm_name == member_name:
                            if hasattr(dm_type, 'ctype') and dm_type.ctype == CLASS_TYPE_INVOKABLE_CLASS:
                                ic = self.decomp.invokable_classes[dm_type.raw_id]
                                if ic:
                                    return self._resolve_invoke_closure_params(ic['params'])
                    cls = cls.superclass
        fallback = SkParams()
        fallback.result_type = self.class_ref_for_name('None')
        return fallback

    def _resolve_invoke_closure_params(self, ic_params: SkParams) -> SkParams:
        import copy
        resolved = copy.deepcopy(ic_params)
        cls_name = self.current_class.name if self.current_class else 'Object'
        for p in resolved.params:
            if hasattr(p.class_type, 'display'):
                if p.class_type.display == 'ThisClass_':
                    p.class_type = self.class_ref_for_name(cls_name)
                elif p.class_type.display == 'ItemClass_':
                    p.class_type = self.class_ref_for_name('Object')
        if hasattr(resolved.result_type, 'display'):
            if resolved.result_type.display == 'ThisClass_':
                resolved.result_type = self.class_ref_for_name(cls_name)
            elif resolved.result_type.display == 'ItemClass_':
                resolved.result_type = self.class_ref_for_name('Object')
        return resolved

    def _fix_closure_arg_params(self, call: dict, recv_class: str = None):
        method_name = call.get('name', '')
        routine = self._find_routine(method_name, recv_class)
        if not routine or not routine.params:
            return
        args = call.get('args', [])
        for i, arg in enumerate(args):
            if arg is None:
                continue
            if not isinstance(arg, dict):
                continue
            inner = arg.get('expr')
            if not isinstance(inner, tuple) or inner[0] != 'closure':
                continue
            if i < len(routine.params.params):
                param = routine.params.params[i]
                if hasattr(param.class_type, 'ctype') and param.class_type.ctype == CLASS_TYPE_INVOKABLE_CLASS:
                    ic = self.decomp.invokable_classes[param.class_type.raw_id]
                    if ic:
                        closure_params = inner[4]
                        ic_params = ic['params']
                        closure_params.result_type = ic_params.result_type

    def _closure_is_coroutine_call(self, closure_expr: dict) -> bool:
        inner = closure_expr.get('expr') if isinstance(closure_expr, dict) else None
        if inner and isinstance(inner, tuple) and inner[0] == 'ident_local':
            var_name = inner[1]
            type_name = self._local_var_types.get(var_name)
            if type_name and (type_name.startswith('_(') or type_name.startswith('+(')):
                return True
        return False

    def _parse_member_ident(self, owner=None) -> dict:
        self.expect('@')

        if not self.at_end() and self.peek() == '@':
            self.pos += 1
            extra_at = 0
            while not self.at_end() and self.peek() == '@':
                extra_at += 1
                self.pos += 1

            name = self.parse_name()
            name_id = self.sym_id(name)

            if extra_at < 2:
                raw_name = f"@{name}"

                search_cls = None
                if owner:
                    owner_type = self._infer_expr_type(owner)
                    if owner_type:
                        search_cls = self.decomp.classes.get(owner_type)
                else:
                    search_cls = self.current_class
                raw_match = self._find_raw_member(raw_name, search_class=search_cls)

                if raw_match:
                    data_idx, owner_class_name, owner_class_name_id = raw_match
                    raw_name_id = self.sym_id(raw_name)
                    return self._make_expr(EXPR_IDENT_RAW_MEMBER,
                        ('ident_raw_member', raw_name, raw_name_id, data_idx, owner, owner_class_name_id, owner_class_name))

            class_dm_name = f"@@{name}"
            class_dm_found = False
            data_idx = 0
            owner_class = self.current_class.name if self.current_class else 'Object'
            cls = self.current_class
            while cls:
                for i, (dm_name, dm_id, dm_type) in enumerate(cls.class_data_members):
                    if dm_name == class_dm_name or dm_name == name:
                        data_idx = i
                        owner_class = cls.name
                        class_dm_found = True
                        break
                else:
                    cls = cls.superclass
                    continue
                break

            if class_dm_found:
                class_dm_name_id = self.sym_id(class_dm_name)
                owner_class_id = self.sym_id(owner_class)
                return self._make_expr(EXPR_IDENT_CLASS_MEMBER,
                    ('ident_class_member', class_dm_name, class_dm_name_id, data_idx, owner_class_id, owner_class))

            at_name = f"@{name}"
            cls = self.current_class
            while cls:
                for i, (dm_name, dm_id, dm_type) in enumerate(cls.data_members):
                    if dm_name == at_name:
                        at_name_id = self.sym_id(at_name)
                        return self._make_expr(EXPR_IDENT_MEMBER,
                            ('ident_member', at_name, at_name_id, i, owner))
                cls = cls.superclass if hasattr(cls, 'superclass') else None

            if extra_at < 2:
                raw_global = self._find_raw_member(f"@{name}", global_fallback=True)
                if raw_global:
                    data_idx, owner_class_name, owner_class_name_id = raw_global
                    raw_name = f"@{name}"
                    raw_name_id = self.sym_id(raw_name)
                    return self._make_expr(EXPR_IDENT_RAW_MEMBER,
                        ('ident_raw_member', raw_name, raw_name_id, data_idx, owner, owner_class_name_id, owner_class_name))

            class_dm_name_id = self.sym_id(class_dm_name)
            owner_class_id = self.sym_id(owner_class)
            return self._make_expr(EXPR_IDENT_CLASS_MEMBER,
                ('ident_class_member', class_dm_name, class_dm_name_id, data_idx, owner_class_id, owner_class))
        else:
            name = self.parse_name()
            name_id = self.sym_id(name)

            data_idx = 0
            is_raw = False
            if self.current_class:
                for i, (dm_name, dm_id, dm_type, bname) in enumerate(self.current_class.raw_data_members):
                    if dm_name == name:
                        data_idx = i
                        is_raw = True
                        break
                if not is_raw:
                    for i, (dm_name, dm_id, dm_type) in enumerate(self.current_class.data_members):
                        if dm_name == name:
                            data_idx = i
                            break

            if is_raw:
                owner_class = self.current_class.name if self.current_class else 'Object'
                owner_class_id = self.sym_id(owner_class)
                return self._make_expr(EXPR_IDENT_RAW_MEMBER,
                    ('ident_raw_member', name, name_id, data_idx, owner, owner_class_id, owner_class))
            else:
                return self._make_expr(EXPR_IDENT_MEMBER,
                    ('ident_member', name, name_id, data_idx, owner))


    def _unwrap_raw_member_chain(self, raw_member_expr):
        inner = raw_member_expr if isinstance(raw_member_expr, tuple) else raw_member_expr.get('expr')
        chain = []
        real_owner = None
        while inner and isinstance(inner, tuple) and inner[0] == 'ident_raw_member':
            _, name, name_id, data_idx, owner_expr, owner_class_id, owner_class = inner
            chain.append((owner_class_id, owner_class, data_idx))
            if owner_expr and isinstance(owner_expr, dict):
                inner_owner = owner_expr.get('expr')
                if inner_owner and isinstance(inner_owner, tuple) and inner_owner[0] == 'ident_raw_member':
                    inner = inner_owner
                    continue
            real_owner = owner_expr
            break
        chain.reverse()
        mc_id, mc, mi = chain[0]
        cascade = [(c_id, c_name, c_idx) for c_id, c_name, c_idx in chain[1:]]
        return real_owner, mc_id, mc, mi, cascade

    def _parse_raw_member_invoke(self, raw_member_expr: dict, method_name: str) -> dict:
        real_owner, mc_id, mc, mi, cascade = self._unwrap_raw_member_chain(raw_member_expr)

        raw_member_type = self._infer_raw_member_type(mc, mi)

        args = []
        ret_args = []
        if not self.at_end() and self.peek() == '(':
            args, ret_args = self._parse_args()

        call = self._make_call_dict(method_name, args, ret_args, receiver_class=raw_member_type)

        BOOL_INVOKE_MAP = {
            'and': INVOKE_METHOD_BOOL_AND,
            'or': INVOKE_METHOD_BOOL_OR,
            'nand': INVOKE_METHOD_BOOL_NAND,
            'nor': INVOKE_METHOD_BOOL_NOR,
            'assert': INVOKE_METHOD_ASSERT,
            'assert_no_leak': INVOKE_METHOD_ASSERT_NO_LEAK,
        }
        if method_name.startswith('_'):
            call['invoke_type'] = INVOKE_COROUTINE
        elif method_name in BOOL_INVOKE_MAP:
            call['invoke_type'] = BOOL_INVOKE_MAP[method_name]
        else:
            call['invoke_type'] = INVOKE_METHOD_ON_INSTANCE

        return self._make_expr(EXPR_RAW_MEMBER_INVOKE,
            ('raw_member_invoke', real_owner, mc_id, mc, mi, cascade, call))

    def _infer_raw_member_type(self, owner_class: str, data_idx: int) -> Optional[str]:
        cls = self.decomp.classes.get(owner_class)
        if cls and data_idx < len(cls.raw_data_members):
            _, _, type_ref, _ = cls.raw_data_members[data_idx]
            name = str(type_ref) if type_ref else None
            if name and name.startswith('<') and name.endswith('>'):
                name = name[1:-1]
            return name
        return None

    def _find_routine(self, name: str, class_name: str = None) -> Optional[SkRoutine]:
        cls_name = class_name or (self.current_class.name if self.current_class else None)
        if not cls_name:
            return None
        if cls_name in ('ThisClass_', 'ItemClass_'):
            cls_name = self.current_class.name if self.current_class else cls_name
        if cls_name.startswith('<') and cls_name.endswith('>'):
            cls_name = cls_name[1:-1]
        if '{' in cls_name:
            cls_name = cls_name[:cls_name.index('{')]
        cls = self.decomp.classes.get(cls_name)
        while cls:
            for r in cls.instance_methods:
                if r.name == name:
                    return r
            for r in cls.class_methods:
                if r.name == name:
                    return r
            for r in cls.coroutines:
                if r.name == name:
                    return r
            cls = cls.superclass
        return None

    def _make_call_dict(self, name: str, args: list = None, ret_args: list = None,
                        scope: str = None, receiver_class: str = None) -> dict:
        name_id = self.sym_id(name)
        vtable_idx = self._lookup_vtable(scope or '', name, receiver_class=receiver_class)
        scope_id = self.sym_id(scope) if scope else 0xFFFFFFFF
        return {
            'name': name,
            'name_id': name_id,
            'vtable_idx': vtable_idx,
            'scope': scope if scope else None,
            'scope_id': scope_id,
            'invoke_type': INVOKE_METHOD_ON_INSTANCE,
            'args': args or [],
            'ret_args': ret_args or [],
        }

    def _parse_args(self) -> Tuple[list, list]:
        self.expect('(')
        args = []
        ret_args = []
        current = args
        self.skip_ws()

        if not self.at_end() and self.peek() == ')':
            self.pos += 1
            return args, ret_args

        while True:
            self.skip_ws()
            if self.at_end() or self.peek() == ')':
                break
            if self.peek() == ';':
                self.pos += 1
                current = ret_args
                self.skip_ws()
                continue
            if self.peek() == ',':
                self.pos += 1
                self.skip_ws()
                continue

            arg = self.parse_expression()
            if arg is not None:
                inner = arg.get('expr') if isinstance(arg, dict) else None
                if isinstance(inner, tuple) and len(inner) >= 2 and inner[0] == 'literal' and inner[1] == 'nil':
                    current.append(None)
                else:
                    current.append(arg)

        self.expect(')')
        return args, ret_args

    def _parse_invoke_on_receiver(self, receiver, method_name: str, scope: str = None,
                                   invoke_tag='invoke', expr_type=EXPR_INVOKE) -> dict:
        args = []
        ret_args = []
        if not self.at_end() and self.peek() == '(':
            args, ret_args = self._parse_args()

        recv_class = self._infer_expr_type(receiver) if receiver else (
            self.current_class.name if self.current_class else None)
        call = self._make_call_dict(method_name, args, ret_args, scope, receiver_class=recv_class)

        self._fix_closure_arg_params(call, recv_class)

        is_class_receiver = False
        if receiver and isinstance(receiver, dict):
            inner = receiver.get('expr')
            if isinstance(inner, tuple) and len(inner) >= 2 and inner[0] == 'literal' and inner[1] == 'Class':
                is_class_receiver = True

        BOOL_INVOKE_MAP = {
            'and': INVOKE_METHOD_BOOL_AND,
            'or': INVOKE_METHOD_BOOL_OR,
            'nand': INVOKE_METHOD_BOOL_NAND,
            'nor': INVOKE_METHOD_BOOL_NOR,
            'assert': INVOKE_METHOD_ASSERT,
            'assert_no_leak': INVOKE_METHOD_ASSERT_NO_LEAK,
        }
        if method_name.startswith('_'):
            call['invoke_type'] = INVOKE_COROUTINE
        elif method_name in BOOL_INVOKE_MAP:
            call['invoke_type'] = BOOL_INVOKE_MAP[method_name]
        elif is_class_receiver:
            call['invoke_type'] = INVOKE_METHOD_ON_CLASS
        elif recv_class and self._is_class_method(method_name, recv_class):
            if recv_class.startswith('<') and recv_class.endswith('>'):
                call['invoke_type'] = INVOKE_METHOD_ON_CLASS
            else:
                call['invoke_type'] = INVOKE_METHOD_ON_INSTANCE_CLASS
        else:
            call['invoke_type'] = INVOKE_METHOD_ON_INSTANCE

        result = self._make_expr(expr_type, (invoke_tag, receiver, call))

        if invoke_tag == 'invoke' and not self.at_end():
            save = self.pos
            self.skip_ws_inline()
            if not self.at_end() and self.peek() == '\n':
                save2 = self.pos
                self.skip_ws()
                if not self.at_end() and self.peek() == ':':
                    calls = [call]
                    while not self.at_end() and self.peek() == ':':
                        self.pos += 1
                        cascade_name = self.parse_name()
                        cascade_args = []
                        cascade_ret_args = []
                        if not self.at_end() and self.peek() == '(':
                            cascade_args, cascade_ret_args = self._parse_args()
                        cascade_call = self._make_call_dict(cascade_name, cascade_args, cascade_ret_args, scope, receiver_class=recv_class)
                        calls.append(cascade_call)
                        self.skip_ws()
                    return self._make_expr(EXPR_INVOKE_CASCADE, ('invoke_cascade', receiver, calls))
                else:
                    self.pos = save2
            else:
                self.pos = save

        return result

    def _parse_invoke_on_implicit(self, name: str, scope: str = None) -> dict:
        args, ret_args = self._parse_args()
        recv_class = self.current_class.name if self.current_class else None
        call = self._make_call_dict(name, args, ret_args, scope, receiver_class=recv_class)

        if name.startswith('_'):
            call['invoke_type'] = INVOKE_COROUTINE
        elif self._is_class_method(name, recv_class):
            if self._in_class_method:
                call['invoke_type'] = INVOKE_METHOD_ON_CLASS
            else:
                call['invoke_type'] = INVOKE_METHOD_ON_INSTANCE_CLASS

        return self._make_expr(EXPR_INVOKE, ('invoke', None, call))

    def _parse_scoped_invoke(self, scope_name: str) -> dict:
        self.expect('@')
        prefix = ''
        if not self.at_end() and self.peek() == '!':
            prefix = '!'
            self.pos += 1
        if prefix and (self.at_end() or self.peek() == '('):
            method_name = prefix
        else:
            method_name = prefix + self.parse_name()
        if not self.at_end() and self.peek() == '(':
            return self._parse_invoke_on_implicit(method_name, scope=scope_name)
        recv_class = self.current_class.name if self.current_class else None
        call = self._make_call_dict(method_name, [], [], scope_name, receiver_class=recv_class)
        return self._make_expr(EXPR_INVOKE, ('invoke', None, call))

    def _parse_instantiate(self, class_name: str) -> dict:
        self.expect('!')

        ctor_name = '!'
        if not self.at_end() and self.peek() == '!':
            self.pos += 1
            ctor_name_part = self.parse_name()
            ctor_name = f"!{ctor_name_part}"
        elif not self.at_end() and self.peek() != '(' and self.peek().isalpha():
            ctor_name_part = self.parse_name()
            ctor_name = f"!{ctor_name_part}"

        args = []
        ret_args = []
        if not self.at_end() and self.peek() == '(':
            args, ret_args = self._parse_args()

        class_id = self.sym_id(class_name)
        ctor_call = self._make_call_dict(ctor_name, args, ret_args, receiver_class=class_name)
        ctor_call.pop('invoke_type', None)
        return self._make_expr(EXPR_INSTANTIATE, ('instantiate', class_id, class_name, ctor_call))

    def _parse_object_id(self, class_name: str) -> dict:
        self.expect('@')
        flags = 0
        if self.match('?'):
            flags = OBJID_FLAG_POSSIBLE
        elif self.match('#'):

            flags = OBJID_FLAG_IDENTIFIER
        self.expect("'")
        start = self.pos
        while not self.at_end() and self.peek() != "'":
            self.pos += 1
        name = self.source[start:self.pos]
        self.expect("'")
        class_id = self.sym_id(class_name)
        return self._make_expr(EXPR_OBJECT_ID, ('object_id', name, class_id, class_name, flags))


    def parse_code_block(self) -> dict:
        self.expect('[')
        self.skip_ws()

        saved_temps = self.temp_vars
        self.temp_vars = []
        temp_start = self.next_data_idx

        stmts = []
        while not self.at_end() and self.peek() != ']':
            prev_pos = self.pos
            stmt = self.parse_expression()
            if stmt is not None:
                stmts.append(stmt)
            self.skip_ws()
            if self.pos == prev_pos:
                self.error(f"Parser stuck at '{self.source[self.pos:self.pos+20]}'")

        self.expect(']')

        block_temps = self.temp_vars
        self.temp_vars = saved_temps
        start_idx = temp_start
        result = self._make_expr(EXPR_CODE, ('code', start_idx, block_temps, stmts))
        self._redistribute_temps(result)
        return result

    @staticmethod
    def _collect_vars_at_level(stmts):
        names = set()
        for stmt in stmts:
            SkParser._collect_vars_from_expr(stmt, names)
        return names

    @staticmethod
    def _collect_vars_from_expr(node, names):
        if node is None:
            return
        if isinstance(node, dict):
            inner = node.get('expr')
            if isinstance(inner, tuple):
                if inner[0] == 'code':
                    return
                if inner[0] == 'ident_local':
                    names.add(inner[1])
                for item in inner:
                    if isinstance(item, (dict, list)):
                        SkParser._collect_vars_from_expr(item, names)
            elif isinstance(inner, list):
                for item in inner:
                    SkParser._collect_vars_from_expr(item, names)
        elif isinstance(node, list):
            for item in node:
                SkParser._collect_vars_from_expr(item, names)
        elif isinstance(node, tuple):
            if node[0] == 'code':
                return
            if node[0] == 'ident_local':
                names.add(node[1])
            for item in node:
                if isinstance(item, (dict, list, tuple)):
                    SkParser._collect_vars_from_expr(item, names)

    @staticmethod
    def _collect_child_code_blocks(stmts):
        blocks = []
        for stmt in stmts:
            SkParser._find_child_code_blocks(stmt, blocks)
        return blocks

    @staticmethod
    def _find_child_code_blocks(node, blocks):
        if node is None:
            return
        if isinstance(node, dict):
            inner = node.get('expr')
            if isinstance(inner, tuple):
                if inner[0] == 'code':
                    blocks.append(node)
                    return
                for item in inner:
                    if isinstance(item, (dict, list)):
                        SkParser._find_child_code_blocks(item, blocks)
            elif isinstance(inner, list):
                for item in inner:
                    SkParser._find_child_code_blocks(item, blocks)
        elif isinstance(node, list):
            for item in node:
                SkParser._find_child_code_blocks(item, blocks)
        elif isinstance(node, tuple):
            if node[0] == 'code':
                return
            for item in node:
                if isinstance(item, (dict, list, tuple)):
                    SkParser._find_child_code_blocks(item, blocks)

    def _redistribute_temps(self, code_block_dict):
        expr = code_block_dict.get('expr')
        if not isinstance(expr, tuple) or expr[0] != 'code':
            return

        _, start_idx, block_temps, stmts = expr

        child_blocks = self._collect_child_code_blocks(stmts)
        for child in child_blocks:
            self._redistribute_temps(child)

        level_vars = self._collect_vars_at_level(stmts)

        promoted = []
        for child in child_blocks:
            child_expr = child['expr']
            if not isinstance(child_expr, tuple) or child_expr[0] != 'code':
                continue
            c_start, c_temps, c_stmts = child_expr[1], child_expr[2], child_expr[3]
            remaining_temps = []
            for temp in c_temps:
                temp_name = temp[0]
                if temp_name in level_vars:
                    promoted.append(temp)
                else:
                    remaining_temps.append(temp)
            if len(remaining_temps) != len(c_temps):
                new_start = c_start + (len(c_temps) - len(remaining_temps))
                child['expr'] = ('code', new_start, remaining_temps, c_stmts)
                self._update_nested_data_sizes(child)

        if promoted:
            new_temps = promoted + list(block_temps)
            code_block_dict['expr'] = ('code', start_idx, new_temps, stmts)

    def _update_nested_data_sizes(self, code_block_dict):
        pass

    def parse_literal_list(self) -> dict:
        self.expect('{')
        self.skip_ws()

        items = []
        while not self.at_end() and self.peek() != '}':
            item = self.parse_expression()
            if item is not None:
                items.append(item)
            self.skip_ws()
            if not self.at_end() and self.peek() == ',':
                self.pos += 1
                self.skip_ws()

        self.expect('}')

        list_class_id = self.sym_id('List')
        return self._make_expr(EXPR_LITERAL_LIST,
            ('literal_list', list_class_id, 'List', INVOKE_INVALID, None, items))

    def parse_closure(self) -> dict:
        self.expect('^')
        self.skip_ws()

        is_coroutine = False

        saved_locals = self.local_vars.copy()
        saved_next_idx = self.next_data_idx
        saved_temps = self.temp_vars
        saved_local_types = self._local_var_types.copy()
        saved_outer_locals = self._outer_locals
        saved_outer_local_types = self._outer_local_types
        saved_outer_local_class_refs = self._outer_local_class_refs
        saved_local_class_refs = self._local_var_class_refs.copy()
        saved_captured = self._closure_captures

        self._outer_locals = saved_locals.copy()
        self._outer_local_types = saved_local_types.copy()
        self._outer_local_class_refs = saved_local_class_refs.copy()
        self._closure_captures = []
        self.local_vars = {}
        self.next_data_idx = 0
        self.temp_vars = []
        self._local_var_types = {}
        self._local_var_class_refs = {}

        params = SkParams()
        params.result_type = self.class_ref_for_name('Object')
        if not self.at_end() and self.peek() == '(':
            params = self._parse_param_signature()
            if str(params.result_type) == 'None':
                params.result_type = self.class_ref_for_name('Object')

        self.skip_ws()
        body = self.parse_expression()

        if body and isinstance(body, dict):
            body_inner = body.get('expr')
            if isinstance(body_inner, tuple) and len(body_inner) >= 2:
                if body_inner[0] == 'literal' and body_inner[1] == 'nil':
                    params.result_type = self.class_ref_for_name('None')

        is_coroutine = self._closure_is_coroutine(body)

        captured = sorted(self._closure_captures, key=lambda c: c[1])
        num_captures = len(captured)

        if num_captures > 0:
            capture_names = {cname for cname, _, _ in captured}
            self._shift_ast_data_indices(body, num_captures, skip_names=capture_names)
            capture_idx_map = {}
            for ci, (cname, cname_id, couter_idx) in enumerate(captured):
                capture_idx_map[cname] = ci
            self._fix_capture_indices(body, capture_idx_map)
            for p in params.params:
                if p.name in self.local_vars:
                    self.local_vars[p.name] += num_captures
            for ci, (cname, cname_id, couter_idx) in enumerate(captured):
                self.local_vars[cname] = ci

        closure_data_size = self.next_data_idx + num_captures

        self.local_vars = saved_locals
        self.next_data_idx = saved_next_idx
        self.temp_vars = saved_temps
        self._local_var_types = saved_local_types
        self._local_var_class_refs = saved_local_class_refs
        self._outer_locals = saved_outer_locals
        self._outer_local_types = saved_outer_local_types
        self._outer_local_class_refs = saved_outer_local_class_refs
        self._closure_captures = saved_captured

        expr_type = EXPR_CLOSURE_COROUTINE if is_coroutine else EXPR_CLOSURE_METHOD
        return self._make_expr(expr_type,
            ('closure', not is_coroutine, None, captured, params, closure_data_size, 0, body))

    def _shift_ast_data_indices(self, node, offset: int, skip_names: set = None):
        if node is None:
            return
        if isinstance(node, dict):
            inner = node.get('expr')
            if inner and isinstance(inner, tuple):
                if inner[0] == 'ident_local' and len(inner) >= 4:
                    if skip_names and inner[1] in skip_names:
                        return
                    node['expr'] = (inner[0], inner[1], inner[2], inner[3] + offset)
                    return
                elif inner[0] == 'code' and len(inner) >= 4:
                    node['expr'] = (inner[0], inner[1] + offset, inner[2], inner[3])
                    for stmt in inner[3]:
                        self._shift_ast_data_indices(stmt, offset, skip_names)
                    return
                elif inner[0] in ('closure',):
                    return
                elif inner[0] == 'concurrent_branch' and len(inner) >= 6:
                    old_captures = inner[1]
                    new_captures = []
                    for cname, cname_id, couter_idx in old_captures:
                        if skip_names and cname in skip_names:
                            new_captures.append((cname, cname_id, couter_idx))
                        else:
                            new_captures.append((cname, cname_id, couter_idx + offset))
                    node['expr'] = (inner[0], new_captures, inner[2], inner[3], inner[4], inner[5])
                    return
            for v in node.values():
                self._shift_ast_data_indices(v, offset, skip_names)
        elif isinstance(node, list):
            for item in node:
                self._shift_ast_data_indices(item, offset, skip_names)
        elif isinstance(node, tuple):
            for item in node:
                self._shift_ast_data_indices(item, offset, skip_names)

    def _fix_capture_indices(self, node, capture_map: dict):
        if node is None:
            return
        if isinstance(node, dict):
            inner = node.get('expr')
            if inner and isinstance(inner, tuple):
                if inner[0] == 'ident_local' and len(inner) >= 4 and inner[1] in capture_map:
                    node['expr'] = (inner[0], inner[1], inner[2], capture_map[inner[1]])
                    return
                elif inner[0] in ('closure',):
                    return
                elif inner[0] == 'concurrent_branch' and len(inner) >= 6:
                    old_captures = inner[1]
                    new_captures = []
                    for cname, cname_id, couter_idx in old_captures:
                        if cname in capture_map:
                            new_captures.append((cname, cname_id, capture_map[cname]))
                        else:
                            new_captures.append((cname, cname_id, couter_idx))
                    node['expr'] = (inner[0], new_captures, inner[2], inner[3], inner[4], inner[5])
                    return
            for v in node.values():
                self._fix_capture_indices(v, capture_map)
        elif isinstance(node, list):
            for item in node:
                self._fix_capture_indices(item, capture_map)
        elif isinstance(node, tuple):
            for item in node:
                self._fix_capture_indices(item, capture_map)

    def _closure_is_coroutine(self, expr) -> bool:
        if expr is None:
            return False
        if isinstance(expr, dict):
            inner = expr.get('expr')
            if inner:
                return self._closure_is_coroutine(inner)
        if isinstance(expr, tuple):
            if expr[0] in ('invoke', 'invoke_sync', 'invoke_race'):
                call = expr[2] if len(expr) > 2 else None
                if isinstance(call, dict) and call.get('invoke_type') == INVOKE_COROUTINE:
                    return True
            for item in expr:
                if self._closure_is_coroutine(item):
                    return True
        if isinstance(expr, list):
            for item in expr:
                if self._closure_is_coroutine(item):
                    return True
        return False

    def parse_bind(self) -> dict:
        self.expect('!')

        if not self.at_end() and self.peek() == '@':
            ident_expr = self._parse_member_ident(owner=None)
            self.skip_ws_inline()
            if self.match(':'):
                self.skip_ws()
                value = self.parse_expression()
                return self._make_expr(EXPR_BIND, ('bind', ident_expr, value))
            return self._make_expr(EXPR_BIND, ('bind', ident_expr, None))

        name = self.parse_name()
        name_id = self.sym_id(name)

        if name not in self.local_vars:
            self.local_vars[name] = self.next_data_idx
            self.next_data_idx += 1
            self.temp_vars.append((name, name_id))
        data_idx = self.local_vars[name]

        ident_expr = self._make_expr(EXPR_IDENT_LOCAL, ('ident_local', name, name_id, data_idx))

        self.skip_ws_inline()
        if self.match(':'):
            self.skip_ws()
            value = self.parse_expression()
            val_type = self._infer_expr_type(value)
            if val_type:
                self._local_var_types[name] = val_type
            return self._make_expr(EXPR_BIND, ('bind', ident_expr, value))

        return self._make_expr(EXPR_BIND, ('bind', ident_expr, None))

    def parse_conditional(self) -> dict:
        self.match_keyword('if')
        self.skip_ws()
        clauses = []

        test = self.parse_expression()
        self.skip_ws()

        branch_start_idx = self.next_data_idx
        branch_start_locals = self.local_vars.copy()
        branch_start_temps = list(self.temp_vars)
        branch_start_types = self._local_var_types.copy()
        max_idx_seen = branch_start_idx

        body = self.parse_expression()
        clauses.append((test, body))
        max_idx_seen = max(max_idx_seen, self.next_data_idx)

        while True:
            self.skip_ws()
            if self.check_keyword('elseif'):
                self.pos += 6
                self.skip_ws()
                self.next_data_idx = branch_start_idx
                self.local_vars = branch_start_locals.copy()
                self.temp_vars = list(branch_start_temps)
                self._local_var_types = branch_start_types.copy()
                test = self.parse_expression()
                self.skip_ws()
                body = self.parse_expression()
                clauses.append((test, body))
                max_idx_seen = max(max_idx_seen, self.next_data_idx)
            elif self.check_keyword('else'):
                self.pos += 4
                self.skip_ws()
                self.next_data_idx = branch_start_idx
                self.local_vars = branch_start_locals.copy()
                self.temp_vars = list(branch_start_temps)
                self._local_var_types = branch_start_types.copy()
                body = self.parse_expression()
                clauses.append((None, body))
                max_idx_seen = max(max_idx_seen, self.next_data_idx)
                break
            else:
                break

        self.next_data_idx = max_idx_seen

        return self._make_expr(EXPR_CONDITIONAL, ('conditional', clauses))

    def parse_case(self) -> dict:
        self.match_keyword('case')
        self.skip_ws()
        compare = self.parse_expression()
        self.skip_ws()

        branch_start_idx = self.next_data_idx
        branch_start_locals = self.local_vars.copy()
        branch_start_temps = list(self.temp_vars)
        branch_start_types = self._local_var_types.copy()
        max_idx_seen = branch_start_idx

        clauses = []
        while True:
            self.skip_ws()
            if self.at_end():
                break
            if self.check_keyword('else'):
                self.pos += 4
                self.skip_ws()
                self.next_data_idx = branch_start_idx
                self.local_vars = branch_start_locals.copy()
                self.temp_vars = list(branch_start_temps)
                self._local_var_types = branch_start_types.copy()
                body = self.parse_expression()
                clauses.append((None, body))
                max_idx_seen = max(max_idx_seen, self.next_data_idx)
                break
            if self.peek() == ']':
                break

            test = self.parse_expression()
            self.skip_ws()
            saved_idx = self.next_data_idx
            max_idx_seen = max(max_idx_seen, saved_idx)
            self.next_data_idx = branch_start_idx
            self.local_vars = branch_start_locals.copy()
            self.temp_vars = list(branch_start_temps)
            self._local_var_types = branch_start_types.copy()
            body = self.parse_expression()
            clauses.append((test, body))
            max_idx_seen = max(max_idx_seen, self.next_data_idx)

        self.next_data_idx = max_idx_seen

        return self._make_expr(EXPR_CASE, ('case', compare, clauses))

    def parse_loop(self) -> dict:
        self.match_keyword('loop')
        self.skip_ws()

        loop_name_id = 0xFFFFFFFF
        if not self.at_end() and self.peek() != '[' and self.peek().isalpha():
            if not (self.check_keyword('if') or self.check_keyword('exit') or
                    self.check_keyword('loop') or self.check_keyword('case') or
                    self.check_keyword('sync') or self.check_keyword('race') or
                    self.check_keyword('branch') or self.check_keyword('nil') or
                    self.check_keyword('this') or self.check_keyword('true') or
                    self.check_keyword('false')):
                name = self.parse_name()
                loop_name_id = self.sym_id(name)
                self.skip_ws()

        body = self.parse_expression()
        return self._make_expr(EXPR_LOOP, ('loop', loop_name_id, body))

    def parse_exit(self) -> dict:
        self.match_keyword('exit')
        loop_name_id = 0xFFFFFFFF
        self.skip_ws_inline()
        if not self.at_end() and self.peek().isalpha() and not self.check_keyword('when') and not self.check_keyword('unless'):
            name = self.parse_name()
            loop_name_id = self.sym_id(name)
        return self._make_expr(EXPR_LOOP_EXIT, ('loop_exit', loop_name_id))

    def parse_sync(self) -> dict:
        self.match_keyword('sync')
        self.skip_ws()
        exprs = self._parse_concurrent_body()
        return self._make_expr(EXPR_CONCURRENT_SYNC, ('concurrent_sync', exprs))

    def parse_race(self) -> dict:
        self.match_keyword('race')
        self.skip_ws()
        exprs = self._parse_concurrent_body()
        return self._make_expr(EXPR_CONCURRENT_RACE, ('concurrent_race', exprs))

    def parse_branch(self) -> dict:
        self.match_keyword('branch')
        self.skip_ws()

        saved_locals = self.local_vars.copy()
        saved_next_idx = self.next_data_idx
        saved_temps = self.temp_vars
        saved_local_types = self._local_var_types.copy()
        saved_outer_locals = self._outer_locals
        saved_outer_local_types = self._outer_local_types
        saved_outer_local_class_refs = self._outer_local_class_refs
        saved_local_class_refs = self._local_var_class_refs.copy()
        saved_captured = self._closure_captures

        combined_locals = {}
        if saved_outer_locals:
            combined_locals.update(saved_outer_locals)
        combined_locals.update(saved_locals)
        combined_types = {}
        if saved_outer_local_types:
            combined_types.update(saved_outer_local_types)
        combined_types.update(saved_local_types)
        combined_class_refs = {}
        if saved_outer_local_class_refs:
            combined_class_refs.update(saved_outer_local_class_refs)
        combined_class_refs.update(saved_local_class_refs)
        self._outer_locals = combined_locals
        self._outer_local_types = combined_types
        self._outer_local_class_refs = combined_class_refs
        self._closure_captures = []
        self.local_vars = {}
        self.next_data_idx = 0
        self.temp_vars = []
        self._local_var_types = {}
        self._local_var_class_refs = {}

        body = self.parse_expression()

        captured = sorted(self._closure_captures, key=lambda c: c[1])
        num_captures = len(captured)

        if num_captures > 0:
            capture_names = {cname for cname, _, _ in captured}
            self._shift_ast_data_indices(body, num_captures, skip_names=capture_names)
            capture_idx_map = {}
            for ci, (cname, cname_id, couter_idx) in enumerate(captured):
                capture_idx_map[cname] = ci
            self._fix_capture_indices(body, capture_idx_map)
            for ci, (cname, cname_id, couter_idx) in enumerate(captured):
                self.local_vars[cname] = ci

        branch_data_size = self.next_data_idx + num_captures

        self.local_vars = saved_locals
        self.next_data_idx = saved_next_idx
        self.temp_vars = saved_temps
        self._local_var_types = saved_local_types
        self._local_var_class_refs = saved_local_class_refs
        self._outer_locals = saved_outer_locals
        self._outer_local_types = saved_outer_local_types
        self._outer_local_class_refs = saved_outer_local_class_refs
        self._closure_captures = saved_captured

        for cname, cname_id, couter_idx in captured:
            if cname not in saved_locals and saved_outer_locals and cname in saved_outer_locals:
                existing = None
                for ec in self._closure_captures:
                    if ec[0] == cname:
                        existing = ec
                        break
                if existing is None:
                    outer_idx = saved_outer_locals[cname]
                    self._closure_captures.append((cname, cname_id, outer_idx))
                    self.local_vars[cname] = 0xDEAD

        params = SkParams()
        params.result_type = self.class_ref_for_name('Object')
        return self._make_expr(EXPR_CONCURRENT_BRANCH,
            ('concurrent_branch', captured, params, branch_data_size, 0, body))

    def parse_divert(self) -> dict:
        self.match_keyword('divert')
        self.skip_ws()
        exprs = self._parse_concurrent_body()
        return self._make_expr(EXPR_CONCURRENT_SYNC, ('concurrent_sync', exprs))

    def parse_change(self) -> dict:
        self.match_keyword('change')
        self.skip_ws()
        mind = self.parse_expression()
        self.skip_ws()
        body = self.parse_expression()
        return self._make_expr(EXPR_CHANGE, ('change', mind, body))

    def _parse_concurrent_body(self) -> list:
        self.expect('[')
        self.skip_ws()
        exprs = []
        while not self.at_end() and self.peek() != ']':
            expr = self.parse_expression()
            if expr is not None:
                exprs.append(expr)
            self.skip_ws()
        self.expect(']')
        return exprs


    def _parse_param_signature(self) -> SkParams:
        self.expect('(')
        self.skip_ws()
        params = SkParams()
        params.result_type = self.class_ref_for_name('None')

        in_return_params = False
        while True:
            self.skip_ws()
            if self.at_end() or self.peek() == ')':
                break
            if self.peek() == ';':
                self.pos += 1
                in_return_params = True
                self.skip_ws()
                continue
            if self.peek() == ',':
                self.pos += 1
                self.skip_ws()
                continue

            if in_return_params:
                ctype = self.parse_class_ref_typed()
                self.skip_ws()
                name = self.parse_name()
                name_id = self.sym_id(name)
                params.return_params.append((name, name_id, ctype))
                if name not in self.local_vars:
                    self.local_vars[name] = self.next_data_idx
                    self.next_data_idx += 1
                type_name = ctype.display if hasattr(ctype, 'display') else str(ctype) if ctype else None
                if type_name:
                    self._local_var_types[name] = type_name
            else:
                param = self._parse_single_param()
                params.params.append(param)

        self.expect(')')
        return params

    def _parse_single_param(self) -> SkParam:
        if self.peek() == '{':
            self.pos += 1
            self.skip_ws()
            classes = []
            while not self.at_end() and self.peek() != '}':
                ctype = self.parse_class_ref_typed()
                classes.append(ctype)
                self.skip_ws()
                if self.peek() == ',':
                    self.pos += 1
                    self.skip_ws()
            self.expect('}')
            self.skip_ws()
            name = self.parse_name()
            name_id = self.sym_id(name)
            if name not in self.local_vars:
                self.local_vars[name] = self.next_data_idx
                self.next_data_idx += 1
            self._local_var_types[name] = 'List'
            param = SkParam(kind=PARAM_GROUP, name=name, name_id=name_id)
            param.group_classes = classes
            param.type_info = len(classes)
            return param

        ctype = self.parse_class_ref_typed(allow_invokable=True)
        self.skip_ws()
        name = self.parse_name()
        name_id = self.sym_id(name)

        if hasattr(ctype, 'ctype') and ctype.ctype == CLASS_TYPE_INVOKABLE_CLASS:
            orig = getattr(self, '_original_routine', None)
            if orig and orig.params:
                for op in orig.params.params:
                    if op.name == name and hasattr(op.class_type, 'ctype') and op.class_type.ctype == CLASS_TYPE_INVOKABLE_CLASS:
                        ctype = op.class_type
                        break

        if name not in self.local_vars:
            self.local_vars[name] = self.next_data_idx
            self.next_data_idx += 1

        type_name = ctype.display if hasattr(ctype, 'display') else str(ctype) if ctype else None
        if type_name:
            self._local_var_types[name] = type_name
            if hasattr(ctype, 'ctype') and ctype.ctype == CLASS_TYPE_INVOKABLE_CLASS:
                self._local_var_class_refs[name] = ctype

        self.skip_ws_inline()
        if self.peek() == ':' and (self.pos + 1 >= len(self.source) or self.source[self.pos + 1] != '='):
            self.pos += 1
            self.skip_ws()
            default_expr = self.parse_expression()
            param = SkParam(kind=PARAM_UNARY_DEFAULT, name=name, name_id=name_id, class_type=ctype)
            if default_expr and isinstance(default_expr, dict):
                param.default_expr_type = default_expr.get('type', 0)
                param.default_expr = default_expr.get('expr')
            else:
                param.default_expr = default_expr
            return param
        else:
            param = SkParam(kind=PARAM_UNARY, name=name, name_id=name_id, class_type=ctype)
            return param


    def parse_routine_file(self, source: str, class_name: str, routine_name: str,
                           is_coroutine: bool, is_class_method: bool) -> SkRoutine:
        self.source = source
        self.pos = 0
        self.local_vars = {}
        self._local_var_types = {}
        self._local_var_class_refs = {}
        self._outer_locals = {}
        self._outer_local_types = {}
        self._outer_local_class_refs = {}
        self._closure_captures = []
        self.next_data_idx = 0
        self.temp_vars = []
        self.current_class = self.decomp.classes.get(class_name)
        self._in_class_method = is_class_method
        self._original_routine = self._find_routine(routine_name, class_name)

        self.skip_ws()
        while not self.at_end() and self.source[self.pos:self.pos+2] == '//':
            while self.pos < len(self.source) and self.source[self.pos] != '\n':
                self.pos += 1
            self.skip_ws()

        if is_coroutine:
            inv_type = INVOKABLE_COROUTINE
        else:
            inv_type = INVOKABLE_METHOD

        params = SkParams()
        if not self.at_end() and self.peek() == '(':
            params = self._parse_param_signature()

        self.skip_ws_inline()
        result_type = self.class_ref_for_name('None')
        if not self.at_end() and self.peek() not in ('\n', '\r', '[', '\0'):
            type_name = self.parse_class_name()
            if type_name and type_name != 'None':
                result_type = self.resolve_class_ref_typed(type_name)
        params.result_type = result_type

        self.skip_ws()
        expression = None
        if not self.at_end():
            expression = self.parse_expression()

        name_id = self.sym_id(routine_name)
        routine = SkRoutine(
            name=routine_name,
            name_id=name_id,
            invokable_type=inv_type,
            params=params,
            expression=expression,
            annotation_flags=0,
            invoked_data_array_size=self.next_data_idx,
        )

        return routine

    def parse_data_file(self, source: str, class_name: str):
        self.source = source
        self.pos = 0
        self.current_class = self.decomp.classes.get(class_name)

        data_members = []
        raw_data_members = []
        class_data_members = []

        while not self.at_end():
            self.skip_ws()
            if self.at_end():
                break

            if self.peek() != '&':
                while self.pos < len(self.source) and self.source[self.pos] != '\n':
                    self.pos += 1
                continue

            self.pos += 1
            is_raw = False
            if self.check_keyword('raw'):
                self.pos += 3
                is_raw = True

            self.skip_ws_inline()
            ctype = self.parse_class_ref_typed(allow_invokable=True)
            self.skip_ws_inline()

            self.expect('@')
            is_class = False
            if self.peek() == '@':
                self.pos += 1
                is_class = True

            bare_name = self.parse_name()
            name = '@@' + bare_name if is_class else '@' + bare_name
            name_id = self.sym_id(name)

            bind_name = ""
            self.skip_ws_inline()
            if self.pos + 1 < len(self.source) and self.source[self.pos:self.pos+2] == '//':
                self.pos += 2
                self.skip_ws_inline()
                if self.check_keyword('bind'):
                    self.pos += 4
                    self.skip_ws_inline()
                    if self.match(':'):
                        self.skip_ws_inline()
                        start = self.pos
                        while self.pos < len(self.source) and self.source[self.pos] not in '\r\n':
                            self.pos += 1
                        bind_name = self.source[start:self.pos].rstrip('\r\n')

            if is_raw:
                raw_data_members.append((name, name_id, ctype, bind_name))
            elif is_class:
                class_data_members.append((name, name_id, ctype))
            else:
                data_members.append((name, name_id, ctype))

        return data_members, raw_data_members, class_data_members


SANITIZE_REVERSE = {
    '-Q': '?',
    '-E': '!',
    '-S': '*',
    '-L': '<',
    '-G': '>',
    '-P': '|',
    '-C': ':',
    '-D': '"',
    '-F': '/',
    '-B': '\\',
}


def unsanitize_filename(filename: str) -> str:
    for sanitized, original in SANITIZE_REVERSE.items():
        filename = filename.replace(sanitized, original)
    return filename


def classify_sk_file(filepath: str, mod_root: str) -> Optional[dict]:
    filepath = filepath.replace('\\', '/')
    mod_root = mod_root.replace('\\', '/')
    if not mod_root.endswith('/'):
        mod_root += '/'

    rel = filepath
    if filepath.startswith(mod_root):
        rel = filepath[len(mod_root):]

    for prefix in ('script/', 'cpp-bound/'):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break

    parts = rel.split('/')
    if len(parts) < 2:
        return None

    filename = parts[-1]
    class_name = parts[-2]

    if not filename.endswith('.sk'):
        return None
    basename = filename[:-3]

    if basename in ('!Data', '!DataC'):
        return {
            'class_name': class_name,
            'routine_name': None,
            'is_coroutine': False,
            'is_class_method': basename == '!DataC',
            'is_data': True,
        }

    is_class_method = False
    is_coroutine = False

    if basename.startswith('!') and basename.endswith('C'):
        is_class_method = True
        basename = basename[1:-1]

    routine_name = unsanitize_filename(basename)

    if routine_name.startswith('_'):
        is_coroutine = True
        routine_name = routine_name[1:]

    return {
        'class_name': class_name,
        'routine_name': routine_name,
        'is_coroutine': is_coroutine,
        'is_class_method': is_class_method,
        'is_data': False,
    }


def scan_mod_directory(mod_dir: str) -> List[str]:
    sk_files = []
    for root, dirs, files in os.walk(mod_dir):
        for f in files:
            if f.endswith('.sk'):
                sk_files.append(os.path.join(root, f))
    return sk_files


def compile_mod(original_bin: str, original_sym: str, mod_dir: str,
                output_bin: str = None, output_sym: str = None):
    print("=== SkookumScript Compiler ===\n")

    print("Phase 1: Loading original binary...")
    t0 = time.time()

    decomp = SkDecompiler(original_sym, original_bin)
    decomp.read_header()
    decomp.read_class_hierarchy()
    decomp.read_compound_types()
    decomp.read_class_members()
    symbols = decomp.symbols

    print(f"  Loaded in {time.time() - t0:.2f}s — {len(decomp.classes)} classes\n")

    print(f"Phase 2: Scanning mod directory: {mod_dir}")
    sk_files = scan_mod_directory(mod_dir)
    print(f"  Found {len(sk_files)} .sk files\n")

    if not sk_files:
        print("No .sk files found. Nothing to compile.")
        return

    print("Phase 3: Parsing and patching routines...")
    parser = SkParser(symbols, decomp)

    patched = 0
    errors = 0

    for sk_path in sk_files:
        info = classify_sk_file(sk_path, mod_dir)
        if info is None:
            print(f"  SKIP (unrecognized): {sk_path}")
            continue

        class_name = info['class_name']
        cls = decomp.classes.get(class_name)
        if cls is None:
            print(f"  SKIP (unknown class '{class_name}'): {sk_path}")
            continue

        with open(sk_path, 'r', encoding='utf-8') as f:
            source = f.read()

        if info['is_data']:
            try:
                dm, rdm, cdm = parser.parse_data_file(source, class_name)
                if dm:
                    new_names = {m[0] for m in dm}
                    kept = [m for m in cls.data_members if m[0] not in new_names]
                    cls.data_members = kept + dm
                if rdm:
                    new_names = {m[0] for m in rdm}
                    kept = [m for m in cls.raw_data_members if m[0] not in new_names]
                    cls.raw_data_members = kept + rdm
                if cdm:
                    new_names = {m[0] for m in cdm}
                    kept = [m for m in cls.class_data_members if m[0] not in new_names]
                    cls.class_data_members = kept + cdm
                print(f"  PATCHED data: {class_name} ({len(dm)} data, {len(rdm)} raw, {len(cdm)} class)")
                patched += 1
            except Exception as e:
                print(f"  ERROR parsing data {sk_path}: {e}")
                errors += 1
            continue

        routine_name = info['routine_name']
        is_coroutine = info['is_coroutine']
        is_class_method = info['is_class_method']

        try:
            new_routine = parser.parse_routine_file(
                source, class_name, routine_name, is_coroutine, is_class_method)
        except Exception as e:
            print(f"  ERROR parsing {sk_path}: {e}")
            errors += 1
            continue

        replaced = False
        if is_class_method:
            routine_list = cls.class_methods
        elif is_coroutine:
            routine_list = cls.coroutines
        else:
            routine_list = cls.instance_methods

        for i, existing in enumerate(routine_list):
            if existing.name == routine_name:
                if existing.invokable_type in (INVOKABLE_METHOD_FUNC, INVOKABLE_METHOD_MTHD,
                                                INVOKABLE_COROUTINE_FUNC, INVOKABLE_COROUTINE_MTHD):
                    print(f"  SKIP (C++ bound): {class_name}.{routine_name}")
                    replaced = True
                    break

                new_routine.invokable_type = existing.invokable_type
                new_routine.annotation_flags = existing.annotation_flags
                routine_list[i] = new_routine
                replaced = True
                print(f"  PATCHED: {class_name}.{routine_name}")
                patched += 1
                break

        if not replaced:
            routine_list.append(new_routine)
            print(f"  ADDED NEW: {class_name}.{routine_name}")
            patched += 1

    print(f"\n  Patched: {patched}, Errors: {errors}\n")

    if errors > 0:
        print("WARNING: There were parsing errors. Output may be incomplete.\n")

    if output_bin is None:
        output_bin = original_bin.replace('.sk-bin', '.patched.sk-bin')
    if output_sym is None:
        output_sym = original_sym.replace('.sk-sym', '.patched.sk-sym')

    print(f"Phase 4: Writing output...")
    print(f"  Binary: {output_bin}")
    print(f"  Symbols: {output_sym}")

    recompiler = SkRecompiler(decomp)
    recompiler.compile()

    with open(output_bin, 'wb') as f:
        f.write(bytes(recompiler.w.buf))
    print(f"  Wrote {len(recompiler.w.buf):,} bytes to {output_bin}")

    write_sk_sym(symbols, output_sym)
    print(f"  Wrote symbols to {output_sym}")

    print(f"\nDone!")


def main():
    if len(sys.argv) < 4:
        print("Usage: python sk_patcher.py <original.sk-bin> <original.sk-sym> <mod_dir> [--output <out.sk-bin> <out.sk-sym>]")
        print()
        print("Patch-based compiler: loads original binary, applies .sk source edits, writes patched binary.")
        print()
        print("  mod_dir should contain .sk files in the same directory structure as the decompiler output.")
        print("  Only include files you've modified — unmodified files are kept from the original binary.")
        print()
        print("Example:")
        print("  python sk_patcher.py Classes.sk-bin Classes.sk-sym ./my_mod --output Patched.sk-bin Patched.sk-sym")
        sys.exit(1)

    original_bin = sys.argv[1]
    original_sym = sys.argv[2]
    mod_dir = sys.argv[3]

    output_bin = None
    output_sym = None

    if '--output' in sys.argv:
        idx = sys.argv.index('--output')
        if idx + 2 < len(sys.argv):
            output_bin = sys.argv[idx + 1]
            output_sym = sys.argv[idx + 2]
        else:
            print("Error: --output requires two arguments: <out.sk-bin> <out.sk-sym>")
            sys.exit(1)

    compile_mod(original_bin, original_sym, mod_dir, output_bin, output_sym)


if __name__ == '__main__':
    main()
