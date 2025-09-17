/* tc-s12z.c -- Assembler code for the Freescale S12Z
   Copyright (C) 2018-2025 Free Software Foundation, Inc.

   This file is part of GAS, the GNU Assembler.

   GAS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS; see the file COPYING.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "as.h"
#include "safe-ctype.h"
#include "subsegs.h"
#include "dwarf2dbg.h"
#include "opcode/s12z.h"
#include <limits.h>

const char comment_chars[] = ";";

const char line_comment_chars[] = "#*";
const char line_separator_chars[] = "";

static char * register_prefix = NULL;

const char EXP_CHARS[] = "eE";
const char FLT_CHARS[] = "dD";

static char *fail_line_pointer;

/* A wrapper around the standard library's strtol.
   It converts STR into an integral value.
   This wrapper deals with literal_prefix_dollar_hex.  */
static bool is_sign_character(char c)
{
    return c == '-' || c == '+';
}

static bool handle_sign(const char **str)
{
    if (**str == '-')
    {
        (*str)++;
        return true;
    }
    if (**str == '+')
    {
        (*str)++;
    }
    return false;
}

static int handle_literal_prefix(const char **str)
{
    if (literal_prefix_dollar_hex && **str == '$')
    {
        (*str)++;
        return 16;
    }
    return 0;
}

static long s12z_strtol(const char *str, char **endptr)
{
    char *start = (char *)str;
    bool negative = handle_sign(&str);
    int base = handle_literal_prefix(&str);
    
    long result = strtol(str, endptr, base);
    
    if (*endptr == str)
    {
        *endptr = start;
    }
    
    if (negative)
    {
        result = -result;
    }
    
    return result;
}



/* Options and initialization.  */

const char md_shortopts[] = "";

const struct option md_longopts[] =
  {
#define OPTION_REG_PREFIX (OPTION_MD_BASE)
   {"mreg-prefix", required_argument, NULL, OPTION_REG_PREFIX},
#define OPTION_DOLLAR_HEX (OPTION_MD_BASE + 1)
   {"mdollar-hex", no_argument, NULL, OPTION_DOLLAR_HEX},
   {NULL, no_argument, NULL, 0}
  };

const size_t md_longopts_size = sizeof (md_longopts);


relax_typeS md_relax_table[] =
  {

  };

/* This table describes all the machine specific pseudo-ops the assembler
   has to support.  The fields are:
   pseudo-op name without dot
   function to call to execute this pseudo-op
   Integer arg to pass to the function.  */
const pseudo_typeS md_pseudo_table[] =
  {
    {0, 0, 0}
  };


/* Get the target cpu for the assembler.  */
const char *
s12z_arch_format (void)
{
  return "elf32-s12z";
}

enum bfd_architecture
s12z_arch (void)
{
  return bfd_arch_s12z;
}

int s12z_mach(void)
{
  return 0;
}

/* Listing header selected according to cpu.  */
const char *
s12z_listing_header (void)
{
  return "S12Z GAS ";
}

void
md_show_usage (FILE *stream)
{
  fputs (_("\ns12z options:\n"), stream);
  fputs (_("  -mreg-prefix=PREFIX     set a prefix used to indicate register names (default none)\n"), stream);
  fputs (_("  -mdollar-hex            the prefix '$' instead of '0x' is used to indicate literal hexadecimal constants\n"), stream);
}

void
s12z_print_statistics (FILE *file ATTRIBUTE_UNUSED)
{
}

int
md_parse_option (int c, const char *arg)
{
  switch (c)
    {
    case OPTION_REG_PREFIX:
      register_prefix = xstrdup (arg);
      break;
    case OPTION_DOLLAR_HEX:
      literal_prefix_dollar_hex = true;
      break;
    default:
      return 0;
    }
  return 1;
}

symbolS *
md_undefined_symbol (char *name ATTRIBUTE_UNUSED)
{
  return 0;
}

const char *
md_atof (int type, char *litP, int *sizeP)
{
  return ieee_md_atof (type, litP, sizeP, true);
}

valueT
md_section_align (asection *seg, valueT addr)
{
  int align = bfd_section_alignment (seg);
  valueT alignment_mask = (valueT) 1 << align;
  valueT alignment_offset = alignment_mask - 1;
  return (addr + alignment_offset) & -alignment_mask;
}

void md_begin(void)
{
}

void
s12z_init_after_args (void)
{
  if (flag_traditional_format)
    literal_prefix_dollar_hex = true;
}

/* Builtin help.  */


static char *skip_whites(char *p)
{
  while (is_whitespace(*p))
    p++;

  return p;
}



/* Start a new insn that contains at least 'size' bytes.  Record the
   line information of that insn in the dwarf2 debug sections.  */
static char *
s12z_new_insn (int size)
{
  char *f = frag_more (size);
  dwarf2_emit_insn (size);
  return f;
}



static bool lex_reg_name (uint16_t which, int *reg);

static bool is_register_name(void)
{
    int dummy;
    return lex_reg_name(~0, &dummy);
}

static bool parse_long_value(char *p, long *v, char **end)
{
    errno = 0;
    *v = s12z_strtol(p, end);
    return errno == 0 && *end != p;
}

static bool lex_constant(long *v)
{
    char *end = NULL;
    char *p = input_line_pointer;

    if (is_register_name())
    {
        input_line_pointer = p;
        return false;
    }

    if (parse_long_value(p, v, &end))
    {
        input_line_pointer = end;
        return true;
    }

    return false;
}

static bool
lex_match (char x)
{
  if (*input_line_pointer != x)
    return false;

  input_line_pointer++;
  return true;
}


static bool
lex_expression (expressionS *exp)
{
  char *ilp = input_line_pointer;
  int dummy;
  exp->X_op = O_absent;

  if (lex_match ('#') || lex_reg_name (~0, &dummy))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  expression (exp);
  if (exp->X_op != O_absent)
    return true;

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

/* Immediate operand.
   If EXP_O is non-null, then a symbolic expression is permitted,
   in which case, EXP_O will be populated with the parsed expression.
 */
static bool
lex_imm (long *v, expressionS *exp_o)
{
  char *ilp = input_line_pointer;

  if (*input_line_pointer != '#')
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  input_line_pointer++;
  expressionS exp;
  if (!lex_expression (&exp))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  if (exp.X_op != O_constant)
    {
      if (!exp_o)
        as_bad (_("A non-constant expression is not permitted here"));
      else
        *exp_o = exp;
    }

  *v = exp.X_add_number;
  return true;
}

/* Short mmediate operand */
static bool
lex_imm_e4 (long *val)
{
  char *ilp = input_line_pointer;
  
  if (!lex_imm(val, NULL))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }
    
  if (*val == -1 || (*val > 0 && *val <= 15))
    {
      return true;
    }
    
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool is_token_delimiter(char c)
{
  return c == 0 || is_whitespace(c) || is_end_of_stmt(c);
}

static size_t get_token_length(const char *start)
{
  char *p = (char *)start;
  while (!is_token_delimiter(*p))
    {
      p++;
    }
  return p - start;
}

static bool token_matches(const char *s, const char *token, size_t token_len)
{
  return token_len == strlen(s) && strncasecmp(s, token, token_len) == 0;
}

static bool
lex_match_string (const char *s)
{
  size_t len = get_token_length(input_line_pointer);
  
  if (!token_matches(s, input_line_pointer, len))
    return false;

  input_line_pointer += len;
  return true;
}

/* Parse a register name.
   WHICH is a ORwise combination of the registers which are accepted.
   ~0 accepts all.
   On success, REG will be filled with the index of the register which
   was successfully scanned.
*/
static bool check_register_prefix(char **p)
{
  if (!register_prefix)
    return true;
    
  int len = strlen(register_prefix);
  if (strncmp(register_prefix, *p, len) == 0)
    {
      *p += len;
      return true;
    }
  return false;
}

static bool is_valid_reg_char(char c)
{
  return (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') ||
         (c >= 'A' && c <= 'Z');
}

static size_t get_register_name_length(char *p)
{
  char *start = p;
  while (is_valid_reg_char(*p))
    p++;
  return p - start;
}

static bool matches_register(const char *reg_name, const char *input, size_t len)
{
  return len == strlen(reg_name) && 
         strncasecmp(reg_name, input, len) == 0;
}

static bool
lex_reg_name(uint16_t which, int *reg)
{
  if (!input_line_pointer)
    return false;

  char *p = input_line_pointer;
  
  if (!check_register_prefix(&p))
    return false;

  char *start_of_reg_name = p;
  size_t len = get_register_name_length(p);
  
  if (len == 0)
    return false;

  for (int i = 0; i < S12Z_N_REGISTERS; ++i)
    {
      gas_assert(registers[i].name);
      
      if (matches_register(registers[i].name, start_of_reg_name, len) &&
          ((0x1U << i) & which))
        {
          input_line_pointer = start_of_reg_name + len;
          *reg = i;
          return true;
        }
    }

  return false;
}

static bool
lex_force_match (char x)
{
  char *p = input_line_pointer;
  if (*p != x)
    {
      as_bad (_("Expecting '%c'"), x);
      return false;
    }

  input_line_pointer++;
  return true;
}

static bool handle_immediate_value(uint8_t *xb, int *n_bytes, bool immediate_ok)
{
    long imm;
    if (!lex_imm_e4(&imm))
        return false;
    
    if (!immediate_ok)
    {
        as_bad(_("An immediate value in a source operand is inappropriate"));
        return false;
    }
    
    *xb = (imm > 0) ? imm : 0;
    *xb |= 0x70;
    *n_bytes = 1;
    return true;
}

static bool handle_dn_register(uint8_t *xb, int *n_bytes)
{
    int reg;
    if (!lex_reg_name(REG_BIT_Dn, &reg))
        return false;
    
    *xb = reg | 0xb8;
    *n_bytes = 1;
    return true;
}

static void set_constant_offset_bytes(uint8_t *buffer, long c, int n_bytes)
{
    for (int i = 1; i < n_bytes; ++i)
    {
        buffer[i] = c >> (8 * (n_bytes - i - 1));
    }
}

static bool handle_bracket_expression_constant(uint8_t *xb, uint8_t *buffer, int *n_bytes, long c)
{
    int reg;
    if (!lex_match(','))
    {
        *xb = 0xfe;
        *n_bytes = 4;
        buffer[1] = c >> 16;
        buffer[2] = c >> 8;
        buffer[3] = c;
        return true;
    }
    
    if (!lex_reg_name(REG_BIT_XYSP, &reg))
    {
        as_bad(_("Bad operand for constant offset"));
        return false;
    }
    
    if (c <= 255 && c >= -256)
    {
        *n_bytes = 2;
        *xb |= 0xc4;
    }
    else
    {
        *n_bytes = 4;
        *xb |= 0xc6;
    }
    
    *xb |= (reg - REG_X) << 4;
    if (c < 0)
        *xb |= 0x01;
    
    set_constant_offset_bytes(buffer, c, *n_bytes);
    return true;
}

static bool handle_bracket_register_offset(uint8_t *xb, int *n_bytes)
{
    int reg, reg2;
    if (!lex_reg_name(REG_BIT_Dn, &reg))
        return false;
    
    if (!lex_force_match(','))
        return false;
    
    if (!lex_reg_name(REG_BIT_XY, &reg2))
    {
        as_bad(_("Invalid operand for register offset"));
        return false;
    }
    
    *n_bytes = 1;
    *xb = reg | ((reg2 - REG_X) << 4) | 0xc8;
    return true;
}

static bool handle_bracket_syntax(uint8_t *xb, uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    if (!lex_match('['))
        return false;
    
    if (lex_expression(exp))
    {
        if (!handle_bracket_expression_constant(xb, buffer, n_bytes, exp->X_add_number))
            return false;
    }
    else if (!handle_bracket_register_offset(xb, n_bytes))
    {
        return false;
    }
    
    return lex_force_match(']');
}

static bool handle_paren_constant_xysp(uint8_t *xb, uint8_t *buffer, int *n_bytes, long c, int reg2)
{
    if (reg2 != REG_P && c >= 0 && c <= 15)
    {
        *n_bytes = 1;
        *xb = 0x40 | ((reg2 - REG_X) << 4) | c;
    }
    else if (c >= -256 && c <= 255)
    {
        *n_bytes = 2;
        *xb = 0xc0 | ((reg2 - REG_X) << 4);
        if (c < 0)
            *xb |= 0x01;
        buffer[1] = c;
    }
    else
    {
        *n_bytes = 4;
        *xb = 0xc2 | ((reg2 - REG_X) << 4);
        buffer[1] = c >> 16;
        buffer[2] = c >> 8;
        buffer[3] = c;
    }
    return true;
}

#define CONSTANT_17_BIT_LIMIT (1L << 17)

static bool handle_paren_constant_dn(uint8_t *xb, uint8_t *buffer, int *n_bytes, long c, int reg2)
{
    if (c >= -CONSTANT_17_BIT_LIMIT && c < CONSTANT_17_BIT_LIMIT - 1)
    {
        *n_bytes = 3;
        *xb = 0x80 | reg2 | (((c >> 16) & 0x03) << 4);
        buffer[1] = c >> 8;
        buffer[2] = c;
    }
    else
    {
        *n_bytes = 4;
        *xb = 0xe8 | reg2;
        buffer[1] = c >> 16;
        buffer[2] = c >> 8;
        buffer[3] = c;
    }
    return true;
}

static bool handle_paren_constant_offset(uint8_t *xb, uint8_t *buffer, int *n_bytes)
{
    long c;
    int reg2;
    
    if (!lex_constant(&c) || !lex_force_match(','))
        return false;
    
    if (lex_reg_name(REG_BIT_XYSP, &reg2))
        return handle_paren_constant_xysp(xb, buffer, n_bytes, c, reg2);
    
    if (lex_reg_name(REG_BIT_Dn, &reg2))
        return handle_paren_constant_dn(xb, buffer, n_bytes, c, reg2);
    
    as_bad(_("Bad operand for constant offset"));
    return false;
}

static bool handle_paren_register_offset(uint8_t *xb, int *n_bytes)
{
    int reg, reg2;
    
    if (!lex_reg_name(REG_BIT_Dn, &reg))
        return false;
    
    if (!lex_match(','))
        return false;
    
    if (!lex_reg_name(REG_BIT_XYS, &reg2))
    {
        as_bad(_("Invalid operand for register offset"));
        return false;
    }
    
    *n_bytes = 1;
    *xb = 0x88 | ((reg2 - REG_X) << 4) | reg;
    return true;
}

static bool handle_postdec_postinc(uint8_t *xb, int *n_bytes, int reg)
{
    if (lex_match('-'))
    {
        if (reg == REG_S)
        {
            as_bad(_("Invalid register for postdecrement operation"));
            return false;
        }
        *n_bytes = 1;
        *xb = (reg == REG_X) ? 0xc7 : 0xd7;
        return true;
    }
    
    if (lex_match('+'))
    {
        *n_bytes = 1;
        if (reg == REG_X)
            *xb = 0xe7;
        else if (reg == REG_Y)
            *xb = 0xf7;
        else if (reg == REG_S)
            *xb = 0xff;
        return true;
    }
    
    return false;
}

static bool handle_preinc_operation(uint8_t *xb, int *n_bytes)
{
    int reg;
    if (!lex_reg_name(REG_BIT_XY, &reg))
    {
        as_bad(_("Invalid register for preincrement operation"));
        return false;
    }
    
    *n_bytes = 1;
    *xb = (reg == REG_X) ? 0xe3 : 0xf3;
    return true;
}

static bool handle_predec_operation(uint8_t *xb, int *n_bytes)
{
    int reg;
    if (!lex_reg_name(REG_BIT_XYS, &reg))
    {
        as_bad(_("Invalid register for predecrement operation"));
        return false;
    }
    
    *n_bytes = 1;
    if (reg == REG_X)
        *xb = 0xc3;
    else if (reg == REG_Y)
        *xb = 0xd3;
    else if (reg == REG_S)
        *xb = 0xfb;
    return true;
}

static bool handle_paren_syntax(uint8_t *xb, uint8_t *buffer, int *n_bytes)
{
    int reg;
    
    if (!lex_match('('))
        return false;
    
    if (lex_constant(NULL))
    {
        input_line_pointer--;
        while (*input_line_pointer >= '0' && *input_line_pointer <= '9')
            input_line_pointer--;
        input_line_pointer++;
        
        if (!handle_paren_constant_offset(xb, buffer, n_bytes))
            return false;
    }
    else if (lex_reg_name(REG_BIT_Dn, &reg))
    {
        input_line_pointer -= 2;
        if (!handle_paren_register_offset(xb, n_bytes))
            return false;
    }
    else if (lex_reg_name(REG_BIT_XYS, &reg))
    {
        if (!handle_postdec_postinc(xb, n_bytes, reg))
            return false;
    }
    else if (lex_match('+'))
    {
        if (!handle_preinc_operation(xb, n_bytes))
            return false;
    }
    else if (lex_match('-'))
    {
        if (!handle_predec_operation(xb, n_bytes))
            return false;
    }
    else
    {
        return false;
    }
    
    return lex_match(')');
}

#define VALUE_14_BIT_LIMIT (0x1U << 14)
#define VALUE_19_BIT_LIMIT (0x1U << 19)
#define VALUE_17_BIT_MASK (0x1U << 17)
#define VALUE_16_BIT_MASK (0x1U << 16)

static void handle_constant_expression_value(uint8_t *xb, uint8_t *buffer, int *n_bytes, valueT value)
{
    if (value < VALUE_14_BIT_LIMIT)
    {
        *xb = 0x00 | (value >> 8);
        *n_bytes = 2;
        buffer[1] = value;
    }
    else if (value < VALUE_19_BIT_LIMIT)
    {
        *xb = 0xf8;
        if (value & VALUE_17_BIT_MASK)
            *xb |= 0x04;
        if (value & VALUE_16_BIT_MASK)
            *xb |= 0x01;
        *n_bytes = 3;
        buffer[1] = value >> 8;
        buffer[2] = value;
    }
    else
    {
        *xb = 0xfa;
        *n_bytes = 4;
        buffer[1] = value >> 16;
        buffer[2] = value >> 8;
        buffer[3] = value;
    }
}

static bool handle_expression(uint8_t *xb, uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    if (!lex_expression(exp))
        return false;
    
    *xb = 0xfa;
    *n_bytes = 4;
    buffer[1] = 0;
    buffer[2] = 0;
    buffer[3] = 0;
    
    if (exp->X_op == O_constant)
        handle_constant_expression_value(xb, buffer, n_bytes, exp->X_add_number);
    
    return true;
}

static bool lex_opr(uint8_t *buffer, int *n_bytes, expressionS *exp, bool immediate_ok)
{
    char *ilp = input_line_pointer;
    uint8_t *xb = buffer;
    
    exp->X_op = O_absent;
    *n_bytes = 0;
    *xb = 0;
    
    if (handle_immediate_value(xb, n_bytes, immediate_ok))
        return true;
    
    if (handle_dn_register(xb, n_bytes))
        return true;
    
    if (handle_bracket_syntax(xb, buffer, n_bytes, exp))
        return true;
    
    if (handle_paren_syntax(xb, buffer, n_bytes))
        return true;
    
    if (handle_expression(xb, buffer, n_bytes, exp))
        return true;
    
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

static bool
lex_offset (long *val)
{
  char *end = NULL;
  char *p = input_line_pointer;

  if (*p++ != '*')
    return false;

  if (*p != '+' && *p != '-')
    return false;

  bool negative = (*p == '-');
  p++;

  errno = 0;
  *val = s12z_strtol (p, &end);
  if (errno != 0)
    return false;

  if (negative)
    *val *= -1;
  
  input_line_pointer = end;
  return true;
}



struct instruction;

typedef bool (*parse_operand_func) (const struct instruction *);

struct instruction
{
  const char *name;

  /* The "page" to which the instruction belongs.
     This is also only a hint.  Some instructions might have modes in both
     pages... */
  char page;

  /* This is a hint - and only a hint - about the opcode of the instruction.
     The parse_operand_func is free to ignore it.
  */
  uint8_t opc;

  parse_operand_func parse_operands;

  /* Some instructions can be encoded with a different opcode */
  uint8_t alt_opc;
};

static bool has_garbage_at_end(void)
{
  if (*input_line_pointer != '\0')
    {
      as_bad (_("Garbage at end of instruction"));
      return true;
    }
  return false;
}

static void emit_page_prebyte(char **f, int page)
{
  if (page == 2)
    {
      number_to_chars_bigendian (*f, PAGE2_PREBYTE, 1);
      (*f)++;
    }
}

static void emit_opcode(char *f, int opc)
{
  number_to_chars_bigendian (f, opc, 1);
}

static bool
no_operands (const struct instruction *insn)
{
  if (has_garbage_at_end())
    return false;

  char *f = s12z_new_insn (insn->page);
  emit_page_prebyte(&f, insn->page);
  emit_opcode(f, insn->opc);

  return true;
}


static void
emit_reloc (expressionS *exp, char *f, int size, enum bfd_reloc_code_real reloc)
{
  const int THIRD_PARTY_ADDEND_FLAGS = 0x00;
  
  if (exp->X_op == O_absent || exp->X_op == O_constant)
    return;
    
  fixS *fix = fix_new_exp (frag_now,
                           f - frag_now->fr_literal,
                           size,
                           exp,
                           false,
                           reloc);
  fix->fx_addnumber = THIRD_PARTY_ADDEND_FLAGS;
}

/* Emit the code for an OPR address mode operand */
static char *
emit_opr (char *f, const uint8_t *buffer, int n_bytes, expressionS *exp)
{
  number_to_chars_bigendian (f++, buffer[0], 1);
  emit_reloc (exp, f, 3, BFD_RELOC_S12Z_OPR);
  
  for (int i = 1; i < n_bytes; ++i)
    number_to_chars_bigendian (f++, buffer[i], 1);

  return f;
}

/* Emit the code for a 24 bit direct address operand */
static char *
emit_ext24 (char *f, long v)
{
  const int EXT24_SIZE = 3;
  number_to_chars_bigendian (f, v, EXT24_SIZE);
  return f + EXT24_SIZE;
}

static bool is_large_constant_direct_value(const uint8_t *buffer, const expressionS *exp, const struct instruction *insn)
{
    return exp->X_op == O_constant && buffer[0] == 0xFA && insn->alt_opc != 0;
}

static void emit_alt_opcode(const struct instruction *insn, const expressionS *exp)
{
    char *f = s12z_new_insn(4);
    gas_assert(insn->page == 1);
    number_to_chars_bigendian(f++, insn->alt_opc, 1);
    emit_ext24(f, exp->X_add_number);
}

static void emit_standard_opcode(const struct instruction *insn, const uint8_t *buffer, int n_bytes, const expressionS *exp)
{
    char *f = s12z_new_insn(n_bytes + 1);
    number_to_chars_bigendian(f++, insn->opc, 1);
    emit_opr(f, buffer, n_bytes, exp);
}

static bool opr(const struct instruction *insn)
{
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    
    if (!lex_opr(buffer, &n_bytes, &exp, false))
        return false;
    
    if (is_large_constant_direct_value(buffer, &exp, insn))
        emit_alt_opcode(insn, &exp);
    else
        emit_standard_opcode(insn, buffer, n_bytes, &exp);
    
    return true;
}

/* Parse a 15 bit offset, as an expression.
   LONG_DISPLACEMENT will be set to true if the offset is wider than 7 bits.
   */
static bool
lex_15_bit_offset (bool *long_displacement, expressionS *exp)
{
  char *ilp = input_line_pointer;
  long val;

  if (!get_offset_value(&val, exp))
    {
      exp->X_op = O_absent;
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  if (!validate_15_bit_range(val))
    return false;

  *long_displacement = is_long_displacement(val);
  return true;
}

static bool
get_offset_value(long *val, expressionS *exp)
{
  if (lex_offset(val))
    {
      exp->X_op = O_absent;
      exp->X_add_number = *val;
      return true;
    }

  if (!lex_expression(exp))
    return false;

  if (exp->X_op != O_constant)
    return true;

  *val = exp->X_add_number;
  return true;
}

static bool
validate_15_bit_range(long val)
{
  #define MAX_15_BIT_OFFSET 0x3FFF
  #define MIN_15_BIT_OFFSET -0x4000
  
  if (val > MAX_15_BIT_OFFSET || val < MIN_15_BIT_OFFSET)
    {
      as_fatal(_("Offset is outside of 15 bit range"));
      return false;
    }
  return true;
}

static bool
is_long_displacement(long val)
{
  #define MAX_SHORT_DISPLACEMENT 63
  #define MIN_SHORT_DISPLACEMENT -64
  
  return (val > MAX_SHORT_DISPLACEMENT || val < MIN_SHORT_DISPLACEMENT);
}

static void handle_non_constant_expression(char *f, int where, expressionS *exp)
{
    exp->X_add_number += where;
    fixS *fix = fix_new_exp(frag_now,
                            f - frag_now->fr_literal,
                            2,
                            exp,
                            true,
                            BFD_RELOC_16_PCREL);
    fix->fx_addnumber = where - 2;
}

static bool is_long_displacement(long val)
{
    const long MAX_SHORT_DISPLACEMENT = 63;
    const long MIN_SHORT_DISPLACEMENT = -64;
    return (val > MAX_SHORT_DISPLACEMENT || val < MIN_SHORT_DISPLACEMENT);
}

static void handle_constant_expression(char *f, expressionS *exp)
{
    const long LONG_DISPLACEMENT_FLAG = 0x8000;
    const long SHORT_DISPLACEMENT_MASK = 0x7F;
    
    long val = exp->X_add_number;
    bool long_displacement = is_long_displacement(val);
    
    if (long_displacement)
        val |= LONG_DISPLACEMENT_FLAG;
    else
        val &= SHORT_DISPLACEMENT_MASK;
    
    int num_bytes = long_displacement ? 2 : 1;
    number_to_chars_bigendian(f, val, num_bytes);
}

static void emit_15_bit_offset(char *f, int where, expressionS *exp)
{
    gas_assert(exp);
    
    if (exp->X_op != O_absent && exp->X_op != O_constant)
        handle_non_constant_expression(f, where, exp);
    else
        handle_constant_expression(f, exp);
}

static bool
rel (const struct instruction *insn)
{
  bool long_displacement;
  expressionS exp;
  
  if (!lex_15_bit_offset(&long_displacement, &exp))
    return false;

  int insn_size = long_displacement ? 3 : 2;
  char *f = s12z_new_insn(insn_size);
  number_to_chars_bigendian(f++, insn->opc, 1);
  emit_15_bit_offset(f, 3, &exp);
  
  return true;
}

static bool
reg_inh (const struct instruction *insn)
{
  int reg;
  if (!lex_reg_name (REG_BIT_Dn, &reg))
    return false;

  char *f = s12z_new_insn (insn->page);
  if (insn->page == 2)
    number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);

  number_to_chars_bigendian (f++, insn->opc + reg, 1);
  return true;
}


/* Special case for CLR X and CLR Y */
static bool
clr_xy (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  int reg;
  if (!lex_reg_name (REG_BIT_XY, &reg))
    return false;

  char *f = s12z_new_insn (1);
  const unsigned char CLR_XY_BASE_OPCODE = 0x9a;
  number_to_chars_bigendian (f, CLR_XY_BASE_OPCODE + reg - REG_X, 1);
  return true;
}

/* Some instructions have a suffix like ".l", ".b", ".w" etc
   which indicates the size of the operands. */
static int get_size_for_suffix_char(char suffix)
{
  switch (suffix)
    {
    case 'b':
      return 1;
    case 'w':
      return 2;
    case 'p':
      return 3;
    case 'l':
      return 4;
    default:
      as_fatal (_("Bad size"));
      return -2;
    }
}

static int
size_from_suffix  (const struct instruction *insn, int idx)
{
  const char *dot = strchr (insn->name, '.');

  if (dot == NULL)
    return -3;

  return get_size_for_suffix_char(dot[1 + idx]);
}

static bool parse_register_operand(int reg_type, int *reg_value)
{
  if (!lex_reg_name(reg_type, reg_value))
    return false;
  return lex_match(',');
}

static bool parse_last_register_operand(int reg_type, int *reg_value)
{
  return lex_reg_name(reg_type, reg_value);
}

static uint8_t get_mul_sign_bit(const char *insn_name)
{
  const char *dot = strchrnul(insn_name, '.');
  char sign_char = dot[-1];
  
  if (sign_char == 's')
    return 0x80;
  if (sign_char == 'u')
    return 0x00;
    
  as_fatal(_("BAD MUL"));
  return 0x00;
}

static void write_instruction_bytes(const struct instruction *insn, int Dd, int Dj, int Dk)
{
  char *f = s12z_new_insn(insn->page + 1);
  
  if (insn->page == 2)
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    
  number_to_chars_bigendian(f++, insn->opc + Dd, 1);
  
  uint8_t mb = get_mul_sign_bit(insn->name);
  mb |= Dj << 3;
  mb |= Dk;
  
  number_to_chars_bigendian(f++, mb, 1);
}

static bool
mul_reg_reg_reg(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd, Dj, Dk;

  if (!parse_register_operand(REG_BIT_Dn, &Dd))
    goto fail;

  if (!parse_register_operand(REG_BIT_Dn, &Dj))
    goto fail;

  if (!parse_last_register_operand(REG_BIT_Dn, &Dk))
    goto fail;

  write_instruction_bytes(insn, Dd, Dj, Dk);
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool
parse_register(int reg_type, int *reg_value)
{
  return lex_reg_name(reg_type, reg_value);
}

static bool
parse_comma(void)
{
  return lex_match(',');
}

static bool
parse_immediate(long *value)
{
  return lex_imm(value, NULL);
}

static uint8_t
get_mul_modifier_byte(const char *name, int Dj, int size)
{
  const uint8_t BASE_MB = 0x44;
  const uint8_t SIGNED_FLAG = 0x80;
  const uint8_t UNSIGNED_FLAG = 0x00;
  
  uint8_t mb = BASE_MB;
  const char *dot = strchrnul(name, '.');
  
  switch (dot[-1])
    {
    case 's':
      mb |= SIGNED_FLAG;
      break;
    case 'u':
      mb |= UNSIGNED_FLAG;
      break;
    default:
      as_fatal(_("BAD MUL"));
      break;
    }
  
  mb |= Dj << 3;
  mb |= size - 1;
  
  return mb;
}

static void
encode_mul_instruction(const struct instruction *insn, int Dd, int Dj, long imm, int size)
{
  char *f = s12z_new_insn(insn->page + 1 + size);
  
  if (insn->page == 2)
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  
  number_to_chars_bigendian(f++, insn->opc + Dd, 1);
  
  uint8_t mb = get_mul_modifier_byte(insn->name, Dj, size);
  number_to_chars_bigendian(f++, mb, 1);
  number_to_chars_bigendian(f++, imm, size);
}

static bool
mul_reg_reg_imm(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd, Dj;
  long imm;
  
  if (!parse_register(REG_BIT_Dn, &Dd))
    goto fail;
  
  if (!parse_comma())
    goto fail;
  
  if (!parse_register(REG_BIT_Dn, &Dj))
    goto fail;
  
  if (!parse_comma())
    goto fail;
  
  if (!parse_immediate(&imm))
    goto fail;
  
  int size = size_from_suffix(insn, 0);
  encode_mul_instruction(insn, Dd, Dj, imm, size);
  
  return true;
  
fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool
parse_register(int reg_type, int *reg_value)
{
  return lex_reg_name(reg_type, reg_value);
}

static bool
parse_comma(void)
{
  return lex_match(',');
}

static bool
parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
  return lex_opr(buffer, n_bytes, exp, true);
}

static uint8_t
get_mul_modifier_byte(const struct instruction *insn, int Dj, int size)
{
  uint8_t mb = 0x40;
  const char *dot = strchrnul(insn->name, '.');
  
  switch (dot[-1])
    {
    case 's':
      mb |= 0x80;
      break;
    case 'u':
      mb |= 0x00;
      break;
    default:
      as_fatal(_("BAD MUL"));
      break;
    }
  
  mb |= Dj << 3;
  mb |= size - 1;
  
  return mb;
}

static void
emit_instruction_bytes(char *f, const struct instruction *insn, 
                      int Dd, uint8_t mb, uint8_t *buffer, 
                      int n_bytes, expressionS *exp)
{
  if (insn->page == 2)
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  
  number_to_chars_bigendian(f++, insn->opc + Dd, 1);
  number_to_chars_bigendian(f++, mb, 1);
  
  emit_opr(f, buffer, n_bytes, exp);
}

static bool
mul_reg_reg_opr(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd, Dj;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  
  if (!parse_register(REG_BIT_Dn, &Dd))
    goto fail;
  
  if (!parse_comma())
    goto fail;
  
  if (!parse_register(REG_BIT_Dn, &Dj))
    goto fail;
  
  if (!parse_comma())
    goto fail;
  
  if (!parse_operand(buffer, &n_bytes, &exp))
    goto fail;
  
  int size = size_from_suffix(insn, 0);
  uint8_t mb = get_mul_modifier_byte(insn, Dj, size);
  
  char *f = s12z_new_insn(insn->page + 1 + n_bytes);
  emit_instruction_bytes(f, insn, Dd, mb, buffer, n_bytes, &exp);
  
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool parse_register(int *Dd)
{
    return lex_reg_name(REG_BIT_Dn, Dd);
}

static bool parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    return lex_opr(buffer, n_bytes, exp, false);
}

static bool parse_comma(void)
{
    return lex_match(',');
}

static uint8_t get_mul_mode_byte(const struct instruction *insn, int size1, int size2)
{
    uint8_t mb = 0x42;
    const char *dot = strchrnul(insn->name, '.');
    
    switch (dot[-1])
    {
    case 's':
        mb |= 0x80;
        break;
    case 'u':
        mb |= 0x00;
        break;
    default:
        as_fatal(_("BAD MUL"));
        break;
    }
    
    mb |= (size1 - 1) << 4;
    mb |= (size2 - 1) << 2;
    return mb;
}

static char* emit_instruction_header(const struct instruction *insn, int Dd, int n_bytes1, int n_bytes2)
{
    char *f = s12z_new_insn(insn->page + 1 + n_bytes1 + n_bytes2);
    
    if (insn->page == 2)
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    
    number_to_chars_bigendian(f++, insn->opc + Dd, 1);
    return f;
}

static bool mul_reg_opr_opr(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    
    int Dd;
    if (!parse_register(&Dd))
        goto fail;
    
    if (!parse_comma())
        goto fail;
    
    uint8_t buffer1[4];
    int n_bytes1;
    expressionS exp1;
    if (!parse_operand(buffer1, &n_bytes1, &exp1))
        goto fail;
    
    if (!parse_comma())
        goto fail;
    
    uint8_t buffer2[4];
    int n_bytes2;
    expressionS exp2;
    if (!parse_operand(buffer2, &n_bytes2, &exp2))
        goto fail;
    
    int size1 = size_from_suffix(insn, 0);
    int size2 = size_from_suffix(insn, 1);
    
    char *f = emit_instruction_header(insn, Dd, n_bytes1, n_bytes2);
    
    uint8_t mb = get_mul_mode_byte(insn, size1, size2);
    number_to_chars_bigendian(f++, mb, 1);
    
    f = emit_opr(f, buffer1, n_bytes1, &exp1);
    f = emit_opr(f, buffer2, n_bytes2, &exp2);
    
    return true;
    
fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}


#define REG_BIT_GRP0				\
  ((0x1U << REG_D2) |				\
   (0x1U << REG_D3) |				\
   (0x1U << REG_CCH) |				\
   (0x1U << REG_CCL) |				\
   (0x1U << REG_D0) |				\
   (0x1U << REG_D1))

#define REG_BIT_GRP1				\
  ((0x1U << REG_D4) |				\
   (0x1U << REG_D5) |				\
   (0x1U << REG_D6) |				\
   (0x1U << REG_D7) |				\
   (0x1U << REG_X) |				\
   (0x1U << REG_Y))

static const uint8_t reg_map [] =
  {
    0x02,  /* D2 */
    0x01,  /* D3 */
    0x20,
    0x10,  /* D5 */
    0x08,  /* D0 */
    0x04,  /* D1 */
    0x08,  /* D6 */
    0x04,  /* D7 */
    0x02,
    0x01,  /* Y */
    0x00,
    0x00,
    0x20,  /* CCH */
    0x10,  /* CCL */
    0x00
  };

static bool
lex_reg_list (uint16_t grp, uint16_t *reg_bits)
{
  while (lex_match (','))
    {
      int reg;
      if (!lex_reg_name (grp, &reg))
        return false;
      *reg_bits |= 0x1u << reg;
    }
  return true;
}

static bool
psh_pull (const struct instruction *insn)
{
  uint8_t pb = get_initial_pb_value(insn);

  if (!parse_register_specification(&pb))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  write_instruction_bytes(insn->opc, pb);
  return true;
}

static uint8_t
get_initial_pb_value(const struct instruction *insn)
{
  return (0 == strcmp("pul", insn->name)) ? 0x80 : 0x00;
}

static bool
parse_register_specification(uint8_t *pb)
{
  if (lex_match_string("all16b"))
    {
      *pb |= 0x40;
      return true;
    }
  
  if (lex_match_string("all"))
    {
      return true;
    }
  
  return parse_register_list(pb);
}

static bool
parse_register_list(uint8_t *pb)
{
  int reg1;
  if (!lex_reg_name(REG_BIT_GRP1 | REG_BIT_GRP0, &reg1))
    return false;

  uint16_t admitted_group = get_admitted_group(reg1);
  uint16_t reg_bits = 0x1 << reg1;
  
  if (!lex_reg_list(admitted_group, &reg_bits))
    return false;

  update_pb_from_reg_bits(pb, reg_bits);
  return true;
}

static uint16_t
get_admitted_group(int reg1)
{
  if ((0x1U << reg1) & REG_BIT_GRP1)
    return REG_BIT_GRP1;
  
  if ((0x1U << reg1) & REG_BIT_GRP0)
    return REG_BIT_GRP0;
  
  return 0;
}

static void
update_pb_from_reg_bits(uint8_t *pb, uint16_t reg_bits)
{
  if (reg_bits & REG_BIT_GRP1)
    *pb |= 0x40;

  for (int i = 0; i < 16; ++i)
    {
      if (reg_bits & (0x1u << i))
        *pb |= reg_map[i];
    }
}

static void
write_instruction_bytes(uint8_t opc, uint8_t pb)
{
  char *f = s12z_new_insn(2);
  number_to_chars_bigendian(f++, opc, 1);
  number_to_chars_bigendian(f++, pb, 1);
}


static bool parse_register_name(int *reg)
{
  return lex_reg_name(~0, reg);
}

static bool parse_comma(void)
{
  return lex_match(',');
}

static void check_register_warnings(const struct instruction *insn, int reg1, int reg2)
{
  if ((0 == strcasecmp("sex", insn->name) || 0 == strcasecmp("zex", insn->name)) &&
      (registers[reg2].bytes <= registers[reg1].bytes))
  {
    as_warn(_("Source register for %s is no larger than the destination register"),
            insn->name);
  }
  else if (reg1 == reg2)
  {
    as_warn(_("The destination and source registers are identical"));
  }
}

static void encode_instruction(const struct instruction *insn, int reg1, int reg2)
{
  char *f = s12z_new_insn(1 + insn->page);
  
  if (insn->page == 2)
  {
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  }
  
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, reg1 << 4 | reg2, 1);
}

static bool
tfr(const struct instruction *insn)
{
  int reg1;
  if (!parse_register_name(&reg1))
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  if (!parse_comma())
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  int reg2;
  if (!parse_register_name(&reg2))
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  check_register_warnings(insn, reg1, reg2);
  encode_instruction(insn, reg1, reg2);

  return true;
}

static bool is_imm8_in_range(long imm)
{
  return imm >= -128 && imm <= 127;
}

static void report_imm_out_of_range(long imm, const char *insn_name)
{
  as_bad(_("Immediate value %ld is out of range for instruction %s"),
         imm, insn_name);
}

static void encode_imm8_instruction(unsigned char opc, long imm)
{
  char *f = s12z_new_insn(2);
  number_to_chars_bigendian(f++, opc, 1);
  number_to_chars_bigendian(f++, imm, 1);
}

static bool
imm8 (const struct instruction *insn)
{
  long imm;
  if (!lex_imm(&imm, NULL))
    return false;
    
  if (!is_imm8_in_range(imm))
    report_imm_out_of_range(imm, insn->name);

  encode_imm8_instruction(insn->opc, imm);
  return true;
}

static bool parse_register(int allowed_reg, int *reg)
{
    return lex_reg_name(allowed_reg, reg) && lex_force_match(',');
}

static bool parse_immediate(long *imm)
{
    return lex_imm(imm, NULL);
}

static void write_page_prebyte(char **f)
{
    number_to_chars_bigendian((*f)++, PAGE2_PREBYTE, 1);
}

static void write_opcode(char **f, int opc, int reg)
{
    number_to_chars_bigendian((*f)++, opc + reg, 1);
}

static void write_immediate(char **f, long imm, short size)
{
    number_to_chars_bigendian((*f)++, imm, size);
}

static void encode_instruction(const struct instruction *insn, int reg, long imm)
{
    short size = registers[reg].bytes;
    char *f = s12z_new_insn(insn->page + size);
    
    if (insn->page == 2)
        write_page_prebyte(&f);
    
    write_opcode(&f, insn->opc, reg);
    write_immediate(&f, imm, size);
}

static bool
reg_imm(const struct instruction *insn, int allowed_reg)
{
    char *ilp = input_line_pointer;
    int reg;
    long imm;
    
    if (!parse_register(allowed_reg, &reg))
        goto fail;
    
    if (!parse_immediate(&imm))
        goto fail;
    
    encode_instruction(insn, reg, imm);
    return true;
    
fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}


static bool
regd_imm (const struct instruction *insn)
{
  return reg_imm (insn, REG_BIT_Dn);
}

static bool
regdxy_imm (const struct instruction *insn)
{
  return reg_imm (insn, REG_BIT_Dn | REG_BIT_XY);
}


static bool regs_imm(const struct instruction *insn)
{
    const unsigned int REG_S_MASK = 0x1U << REG_S;
    return reg_imm(insn, REG_S_MASK);
}

static bool is_valid_trap_value(long imm)
{
    const long TRAP_MIN = 0x92;
    const long TRAP_MAX = 0xFF;
    const long INVALID_RANGE1_START = 0xA0;
    const long INVALID_RANGE1_END = 0xA7;
    const long INVALID_RANGE2_START = 0xB0;
    const long INVALID_RANGE2_END = 0xB7;
    
    if (imm < TRAP_MIN || imm > TRAP_MAX)
        return false;
    
    if (imm >= INVALID_RANGE1_START && imm <= INVALID_RANGE1_END)
        return false;
    
    if (imm >= INVALID_RANGE2_START && imm <= INVALID_RANGE2_END)
        return false;
    
    return true;
}

static void emit_trap_instruction(long imm)
{
    const int INSTRUCTION_SIZE = 2;
    const int BYTE_SIZE = 1;
    
    char *f = s12z_new_insn(INSTRUCTION_SIZE);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, BYTE_SIZE);
    number_to_chars_bigendian(f++, imm & 0xFF, BYTE_SIZE);
}

static bool trap_imm(const struct instruction *insn ATTRIBUTE_UNUSED)
{
    long imm = -1;
    
    if (!lex_imm(&imm, NULL))
    {
        fail_line_pointer = input_line_pointer;
        return false;
    }
    
    if (!is_valid_trap_value(imm))
    {
        as_bad(_("trap value %ld is not valid"), imm);
        return false;
    }
    
    emit_trap_instruction(imm);
    return true;
}



/* Special one byte instruction CMP X, Y */
static bool
regx_regy (const struct instruction *insn)
{
  int reg;
  
  if (!lex_reg_name (0x1U << REG_X, &reg))
    return false;
    
  if (!lex_force_match (','))
    return false;
    
  if (!lex_reg_name (0x1U << REG_Y, &reg))
    return false;
  
  char *f = s12z_new_insn (1);
  number_to_chars_bigendian (f, insn->opc, 1);
  return true;
}

/* Special one byte instruction SUB D6, X, Y */
static bool
regd6_regx_regy (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  
  if (!lex_reg_name (0x1U << REG_D6, &(int){0}) ||
      !lex_match (',') ||
      !lex_reg_name (0x1U << REG_X, &(int){0}) ||
      !lex_match (',') ||
      !lex_reg_name (0x1U << REG_Y, &(int){0}))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  char *f = s12z_new_insn (1);
  number_to_chars_bigendian (f, insn->opc, 1);
  return true;
}

/* Special one byte instruction SUB D6, Y, X */
static bool
regd6_regy_regx (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  
  if (!lex_reg_name (0x1U << REG_D6, NULL))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (0x1U << REG_Y, NULL))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (0x1U << REG_X, NULL))
    goto fail;

  char *f = s12z_new_insn (1);
  number_to_chars_bigendian (f, insn->opc, 1);
  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool should_use_ext24_mode(const expressionS *exp, const uint8_t *buffer, const struct instruction *insn)
{
    return exp->X_op == O_constant && buffer[0] == 0xFA && insn->alt_opc != 0;
}

static void emit_ext24_instruction(const struct instruction *insn, int reg, const expressionS *exp)
{
    char *f = s12z_new_insn(4);
    gas_assert(insn->page == 1);
    number_to_chars_bigendian(f++, insn->alt_opc + reg, 1);
    emit_ext24(f, exp->X_add_number);
}

static void emit_regular_instruction(const struct instruction *insn, int reg, const uint8_t *buffer, int n_bytes, const expressionS *exp)
{
    char *f = s12z_new_insn(n_bytes + insn->page);
    
    if (insn->page == 2)
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    
    number_to_chars_bigendian(f++, insn->opc + reg, 1);
    emit_opr(f, buffer, n_bytes, exp);
}

static bool process_operand(const struct instruction *insn, int reg, bool immediate_ok)
{
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    
    if (!lex_opr(buffer, &n_bytes, &exp, immediate_ok))
        return false;
    
    if (should_use_ext24_mode(&exp, buffer, insn))
        emit_ext24_instruction(insn, reg, &exp);
    else
        emit_regular_instruction(insn, reg, buffer, n_bytes, &exp);
    
    return true;
}

static bool reg_opr(const struct instruction *insn, int allowed_regs, bool immediate_ok)
{
    char *ilp = input_line_pointer;
    int reg;
    
    if (!lex_reg_name(allowed_regs, &reg))
        goto fail;
    
    if (!lex_force_match(','))
        goto fail;
    
    if (process_operand(insn, reg, immediate_ok))
        return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}


static bool regdxy_opr_dest(const struct instruction *insn)
{
    const int DEST_REG_MASK = REG_BIT_Dn | REG_BIT_XY;
    const bool IS_SOURCE = false;
    return reg_opr(insn, DEST_REG_MASK, IS_SOURCE);
}

static bool
regdxy_opr_src (const struct instruction *insn)
{
  return reg_opr (insn, REG_BIT_Dn | REG_BIT_XY, true);
}


static bool
regd_opr (const struct instruction *insn)
{
  return reg_opr (insn, REG_BIT_Dn, true);
}


/* OP0: S; OP1: destination OPR */
static bool
regs_opr_dest(const struct instruction *insn)
{
    const unsigned int REG_S_MASK = 0x1U << REG_S;
    const bool IS_DESTINATION = false;
    
    return reg_opr(insn, REG_S_MASK, IS_DESTINATION);
}

/* OP0: S; OP1: source OPR */
static bool
regs_opr_src(const struct instruction *insn)
{
    const unsigned int REG_S_MASK = 0x1U << REG_S;
    const bool IS_SOURCE = true;
    return reg_opr(insn, REG_S_MASK, IS_SOURCE);
}

static bool
imm_opr(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    long imm;
    expressionS exp0;
    int size = size_from_suffix(insn, 0);
    exp0.X_op = O_absent;

    if (!parse_immediate(&imm, &exp0, size))
        return restore_and_fail(ilp);

    if (!lex_match(','))
        return restore_and_fail(ilp);

    uint8_t buffer[4];
    int n_bytes;
    expressionS exp1;
    if (!lex_opr(buffer, &n_bytes, &exp1, false))
        return restore_and_fail(ilp);

    generate_instruction(insn, imm, &exp0, buffer, n_bytes, &exp1, size);
    return true;
}

static bool parse_immediate(long *imm, expressionS *exp0, int size)
{
    return lex_imm(imm, size > 1 ? exp0 : NULL);
}

static bool restore_and_fail(char *ilp)
{
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

static void generate_instruction(const struct instruction *insn, long imm, 
                                 expressionS *exp0, uint8_t *buffer, 
                                 int n_bytes, expressionS *exp1, int size)
{
    char *f = s12z_new_insn(1 + n_bytes + size);
    
    write_opcode(&f, insn->opc);
    write_relocation(&f, exp0, size);
    write_immediate_bytes(&f, imm, size);
    emit_opr(f, buffer, n_bytes, exp1);
}

static void write_opcode(char **f, uint8_t opc)
{
    number_to_chars_bigendian(*f, opc, 1);
    (*f)++;
}

static void write_relocation(char **f, expressionS *exp0, int size)
{
    emit_reloc(exp0, *f, size, size == 4 ? BFD_RELOC_32 : BFD_RELOC_S12Z_OPR);
}

static void write_immediate_bytes(char **f, long imm, int size)
{
    for (int i = 0; i < size; ++i) {
        int shift = CHAR_BIT * (size - i - 1);
        number_to_chars_bigendian(*f, imm >> shift, 1);
        (*f)++;
    }
}

static bool parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    return lex_opr(buffer, n_bytes, exp, false);
}

static bool parse_comma(void)
{
    return lex_match(',');
}

static void emit_instruction(const struct instruction *insn, 
                            uint8_t *buffer1, int n_bytes1, expressionS *exp1,
                            uint8_t *buffer2, int n_bytes2, expressionS *exp2)
{
    char *f = s12z_new_insn(1 + n_bytes1 + n_bytes2);
    number_to_chars_bigendian(f++, insn->opc, 1);
    f = emit_opr(f, buffer1, n_bytes1, exp1);
    f = emit_opr(f, buffer2, n_bytes2, exp2);
}

static bool opr_opr(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    
    uint8_t buffer1[4];
    int n_bytes1;
    expressionS exp1;
    
    uint8_t buffer2[4];
    int n_bytes2;
    expressionS exp2;
    
    if (!parse_operand(buffer1, &n_bytes1, &exp1))
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }
    
    if (!parse_comma())
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }
    
    if (!parse_operand(buffer2, &n_bytes2, &exp2))
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }
    
    emit_instruction(insn, buffer1, n_bytes1, &exp1, buffer2, n_bytes2, &exp2);
    
    return true;
}

static bool parse_register(int *reg)
{
    return lex_reg_name(REG_BIT_XYS | (0x1U << REG_D6) | (0x1U << REG_D7), reg);
}

static bool parse_comma(void)
{
    return lex_match(',');
}

static bool parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    return lex_opr(buffer, n_bytes, exp, false);
}

static void emit_instruction(const struct instruction *insn, int reg, 
                            uint8_t *buffer, int n_bytes, expressionS *exp)
{
    char *f = s12z_new_insn(1 + n_bytes);
    number_to_chars_bigendian(f++, insn->opc + reg - REG_D6, 1);
    emit_opr(f, buffer, n_bytes, exp);
}

static bool reg67sxy_opr(const struct instruction *insn)
{
    int reg;
    if (!parse_register(&reg))
        return false;

    if (!parse_comma())
        return false;

    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    if (!parse_operand(buffer, &n_bytes, &exp))
        return false;

    emit_instruction(insn, reg, buffer, n_bytes, &exp);
    return true;
}

static bool rotate(const struct instruction *insn, short dir)
{
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    
    if (!lex_opr(buffer, &n_bytes, &exp, false))
        return false;
    
    char *f = s12z_new_insn(n_bytes + 2);
    number_to_chars_bigendian(f++, insn->opc, 1);
    
    int size = size_from_suffix(insn, 0);
    if (size < 0)
        size = 1;
    
    uint8_t sb = 0x24;
    sb |= size - 1;
    if (dir)
        sb |= 0x40;
    
    number_to_chars_bigendian(f++, sb, 1);
    emit_opr(f, buffer, n_bytes, &exp);
    
    return true;
}

static bool
rol(const struct instruction *insn)
{
  const int LEFT_ROTATE_COUNT = 1;
  return rotate(insn, LEFT_ROTATE_COUNT);
}

static bool
ror(const struct instruction *insn)
{
    const int RIGHT_ROTATION = 0;
    return rotate(insn, RIGHT_ROTATION);
}


/* Shift instruction with a register operand and an immediate #1 or #2
   left = 1; right = 0;
   logical = 0; arithmetic = 1;
*/
static bool
parse_register_and_immediate(int *Dd, long *imm)
{
  if (!lex_reg_name(REG_BIT_Dn, Dd))
    return false;

  if (!lex_match(','))
    return false;

  if (!lex_imm(imm, NULL))
    return false;

  if (*imm != 1 && *imm != 2)
    return false;

  return true;
}

static bool
parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
  if (!lex_opr(buffer, n_bytes, exp, false))
    return false;

  gas_assert(*n_bytes == 1);
  return true;
}

static uint8_t
build_sb_byte(short type, short dir, long imm)
{
  const uint8_t SB_BASE = 0x34;
  const uint8_t DIR_SHIFT = 6;
  const uint8_t TYPE_SHIFT = 7;
  const uint8_t IMM2_BIT = 0x08;

  uint8_t sb = SB_BASE;
  sb |= dir << DIR_SHIFT;
  sb |= type << TYPE_SHIFT;
  if (imm == 2)
    sb |= IMM2_BIT;

  return sb;
}

static void
emit_instruction(const struct instruction *insn, uint8_t sb, 
                 uint8_t *buffer, int n_bytes, expressionS *exp)
{
  char *f = s12z_new_insn(3);
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, sb, 1);
  emit_opr(f, buffer, n_bytes, exp);
}

static bool
lex_shift_reg_imm1(const struct instruction *insn, short type, short dir)
{
  char *ilp = input_line_pointer;

  int Dd;
  long imm;
  if (!parse_register_and_immediate(&Dd, &imm))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  input_line_pointer = ilp;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  if (!parse_operand(buffer, &n_bytes, &exp))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  uint8_t sb = build_sb_byte(type, dir, imm);
  emit_instruction(insn, sb, buffer, n_bytes, &exp);

  return true;
}

/* Shift instruction with a register operand.
   left = 1; right = 0;
   logical = 0; arithmetic = 1; */
static bool parse_register_operand(int reg_type, int *reg_value)
{
    if (!lex_reg_name(reg_type, reg_value))
        return false;
    
    if (!lex_match(','))
    {
        fail_line_pointer = input_line_pointer;
        return false;
    }
    
    return true;
}

static bool parse_last_register(int *reg_value)
{
    return lex_reg_name(REG_BIT_Dn, reg_value);
}

static void emit_register_shift(const struct instruction *insn, int Dd, uint8_t sb, int Dn)
{
    char *f = s12z_new_insn(3);
    number_to_chars_bigendian(f++, insn->opc | Dd, 1);
    number_to_chars_bigendian(f++, sb, 1);
    uint8_t xb = 0xb8 | Dn;
    number_to_chars_bigendian(f++, xb, 1);
}

static bool validate_shift_immediate(long imm)
{
    if (imm < 0 || imm > 31)
    {
        as_bad(_("Shift value should be in the range [0,31]"));
        return false;
    }
    return true;
}

static void emit_immediate_shift(const struct instruction *insn, int Dd, uint8_t sb, long imm)
{
    #define SHIFT_ONE 1
    #define SHIFT_TWO 2
    
    int n_bytes = 3;
    
    if (imm == SHIFT_ONE || imm == SHIFT_TWO)
    {
        n_bytes = 2;
        sb &= ~0x10;
    }
    else
    {
        sb |= (imm & 0x01) << 3;
    }
    
    char *f = s12z_new_insn(n_bytes);
    number_to_chars_bigendian(f++, insn->opc | Dd, 1);
    number_to_chars_bigendian(f++, sb, 1);
    
    if (n_bytes > 2)
    {
        uint8_t xb = 0x70 | (imm >> 1);
        number_to_chars_bigendian(f++, xb, 1);
    }
}

static bool lex_shift_reg(const struct instruction *insn, short type, short dir)
{
    int Dd, Ds, Dn;
    
    if (!parse_register_operand(REG_BIT_Dn, &Dd))
        return false;
    
    if (!lex_reg_name(REG_BIT_Dn, &Ds))
    {
        fail_line_pointer = input_line_pointer;
        return false;
    }
    
    if (!lex_match(','))
    {
        fail_line_pointer = input_line_pointer;
        return false;
    }
    
    uint8_t sb = 0x10 | Ds | (dir << 6) | (type << 7);
    
    if (parse_last_register(&Dn))
    {
        emit_register_shift(insn, Dd, sb, Dn);
        return true;
    }
    
    long imm;
    if (lex_imm(&imm, NULL))
    {
        if (!validate_shift_immediate(imm))
        {
            fail_line_pointer = input_line_pointer;
            return false;
        }
        
        emit_immediate_shift(insn, Dd, sb, imm);
        return true;
    }
    
    fail_line_pointer = input_line_pointer;
    return false;
}

static void determine_shift_type(char first_char, short *type)
{
    *type = -1;
    switch (first_char)
    {
    case 'l':
        *type = 0;
        break;
    case 'a':
        *type = 1;
        break;
    default:
        as_fatal(_("Bad shift mode"));
        break;
    }
}

static void determine_shift_direction(char third_char, short *dir)
{
    *dir = -1;
    switch (third_char)
    {
    case 'l':
        *dir = 1;
        break;
    case 'r':
        *dir = 0;
        break;
    default:
        as_fatal(_("Bad shift *direction"));
        break;
    }
}

static void impute_shift_dir_and_type(const struct instruction *insn, short *type, short *dir)
{
    determine_shift_type(insn->name[0], type);
    determine_shift_direction(insn->name[2], dir);
}

/* Shift instruction with a OPR operand */
static bool
shift_two_operand(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    
    uint8_t sb = build_shift_byte(insn);
    
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;
    
    if (!parse_shift_operands(buffer, &n_opr_bytes, &exp, &sb))
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }
    
    emit_shift_instruction(insn, sb, buffer, n_opr_bytes, &exp);
    return true;
}

static uint8_t
build_shift_byte(const struct instruction *insn)
{
    uint8_t sb = 0x34;
    short dir = -1;
    short type = -1;
    
    impute_shift_dir_and_type(insn, &type, &dir);
    sb |= dir << 6;
    sb |= type << 7;
    
    int size = size_from_suffix(insn, 0);
    sb |= size - 1;
    
    return sb;
}

static bool
parse_shift_operands(uint8_t *buffer, int *n_opr_bytes, expressionS *exp, uint8_t *sb)
{
    if (!lex_opr(buffer, n_opr_bytes, exp, false))
        return false;
    
    if (!lex_match(','))
        return false;
    
    long imm = -1;
    if (!lex_imm(&imm, NULL))
        return false;
    
    if (!validate_and_encode_immediate(imm, sb))
        return false;
    
    return true;
}

static bool
validate_and_encode_immediate(long imm, uint8_t *sb)
{
    #define VALID_IMM_1 1
    #define VALID_IMM_2 2
    #define IMM2_FLAG 0x08
    
    if (imm != VALID_IMM_1 && imm != VALID_IMM_2)
        return false;
    
    if (imm == VALID_IMM_2)
        *sb |= IMM2_FLAG;
    
    return true;
}

static void
emit_shift_instruction(const struct instruction *insn, uint8_t sb, 
                      uint8_t *buffer, int n_opr_bytes, expressionS *exp)
{
    char *f = s12z_new_insn(2 + n_opr_bytes);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, sb, 1);
    emit_opr(f, buffer, n_opr_bytes, exp);
}

/* Shift instruction with a OPR operand */
static bool
shift_opr_imm(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    short dir = -1;
    short type = -1;
    int Dd = 0;
    int n_bytes = 2;
    uint8_t buffer1[4];
    int n_opr_bytes1;
    expressionS exp1;
    uint8_t buffer2[4];
    int n_opr_bytes2 = 0;
    expressionS exp2;
    long imm;
    bool immediate = false;
    uint8_t sb = 0x20;
    
    impute_shift_dir_and_type(insn, &type, &dir);
    
    if (!lex_reg_name(REG_BIT_Dn, &Dd))
        goto fail;
    
    if (!lex_match(','))
        goto fail;
    
    if (!lex_opr(buffer1, &n_opr_bytes1, &exp1, false))
        goto fail;
    
    n_bytes += n_opr_bytes1;
    
    if (!lex_match(','))
        goto fail;
    
    if (lex_imm(&imm, NULL)) {
        immediate = true;
    } else if (!lex_opr(buffer2, &n_opr_bytes2, &exp2, false)) {
        goto fail;
    }
    
    int size = size_from_suffix(insn, 0);
    if (size != -1)
        sb |= size - 1;
    
    sb |= dir << 6;
    sb |= type << 7;
    
    if (immediate) {
        handle_immediate_shift(&sb, &n_bytes, imm);
    } else {
        n_bytes += n_opr_bytes2;
        sb |= 0x10;
    }
    
    emit_shift_instruction(insn->opc | Dd, sb, buffer1, n_opr_bytes1, &exp1,
                          buffer2, n_opr_bytes2, &exp2, immediate, imm, n_bytes);
    
    return true;
    
fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

static void
handle_immediate_shift(uint8_t *sb, int *n_bytes, long imm)
{
    #define SHIFT_BY_ONE 1
    #define SHIFT_BY_TWO 2
    
    if (imm == SHIFT_BY_TWO || imm == SHIFT_BY_ONE) {
        if (imm == SHIFT_BY_TWO)
            *sb |= 0x08;
    } else {
        (*n_bytes)++;
        *sb |= 0x10;
        if (imm % 2)
            *sb |= 0x08;
    }
}

static void
emit_shift_instruction(uint8_t opcode, uint8_t sb, uint8_t *buffer1, int n_opr_bytes1,
                      expressionS *exp1, uint8_t *buffer2, int n_opr_bytes2,
                      expressionS *exp2, bool immediate, long imm, int n_bytes)
{
    #define SHIFT_BY_ONE 1
    #define SHIFT_BY_TWO 2
    
    char *f = s12z_new_insn(n_bytes);
    number_to_chars_bigendian(f++, opcode, 1);
    number_to_chars_bigendian(f++, sb, 1);
    f = emit_opr(f, buffer1, n_opr_bytes1, exp1);
    
    if (immediate) {
        if (imm != SHIFT_BY_ONE && imm != SHIFT_BY_TWO) {
            number_to_chars_bigendian(f++, 0x70 | (imm >> 1), 1);
        }
    } else {
        f = emit_opr(f, buffer2, n_opr_bytes2, exp2);
    }
}

/* Shift instruction with a register operand */
static bool shift_reg(const struct instruction *insn)
{
    short dir = -1;
    short type = -1;
    impute_shift_dir_and_type(insn, &type, &dir);
    
    return lex_shift_reg_imm1(insn, type, dir) || lex_shift_reg(insn, type, dir);
}

static bool parse_register(int *Di)
{
  return lex_reg_name(REG_BIT_Dn, Di);
}

static bool parse_comma(void)
{
  return lex_match(',');
}

static bool parse_immediate(long *imm)
{
  return lex_imm(imm, NULL);
}

static uint8_t build_bitmask(long imm, int Di)
{
  const int SHIFT_AMOUNT = 3;
  return (imm << SHIFT_AMOUNT) | Di;
}

static void emit_instruction(uint8_t opc, uint8_t bm)
{
  const int INSTRUCTION_SIZE = 2;
  char *f = s12z_new_insn(INSTRUCTION_SIZE);
  number_to_chars_bigendian(f++, opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
}

static void restore_input_pointer(char *original)
{
  fail_line_pointer = input_line_pointer;
  input_line_pointer = original;
}

static bool
bm_regd_imm(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Di = 0;
  long imm;

  if (!parse_register(&Di))
  {
    restore_input_pointer(ilp);
    return false;
  }

  if (!parse_comma())
  {
    restore_input_pointer(ilp);
    return false;
  }

  if (!parse_immediate(&imm))
  {
    restore_input_pointer(ilp);
    return false;
  }

  uint8_t bm = build_bitmask(imm, Di);
  emit_instruction(insn->opc, bm);

  return true;
}

static bool
bm_opr_reg(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;
    int Dn = 0;

    if (!lex_opr(buffer, &n_opr_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_reg_name(REG_BIT_Dn, &Dn)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    uint8_t bm = (Dn << 4) | ((size_from_suffix(insn, 0) - 1) << 2) | 0x81;

    char *f = s12z_new_insn(2 + n_opr_bytes);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    emit_opr(f, buffer, n_opr_bytes, &exp);

    return true;
}


static bool
parse_operand_and_comma(uint8_t *buffer, int *n_opr_bytes, expressionS *exp)
{
  if (!lex_opr(buffer, n_opr_bytes, exp, false))
    return false;
  
  if (!lex_match(','))
    return false;
  
  return true;
}

static bool
validate_immediate(long imm, int size)
{
  if (imm < 0 || imm >= size * 8)
    {
      as_bad(_("Immediate operand %ld is inappropriate for size of instruction"), imm);
      return false;
    }
  return true;
}

static uint8_t
calculate_bm_value(int size, long imm)
{
  uint8_t bm = 0x80;
  
  if (size == 2)
    bm |= 0x02;
  else if (size == 4)
    bm |= 0x08;
  
  bm |= (imm & 0x07) << 4;
  bm |= (imm >> 3);
  
  return bm;
}

static void
emit_instruction(const struct instruction *insn, uint8_t bm, 
                uint8_t *buffer, int n_opr_bytes, expressionS *exp)
{
  char *f = s12z_new_insn(2 + n_opr_bytes);
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
  emit_opr(f, buffer, n_opr_bytes, exp);
}

static bool
bm_opr_imm(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  uint8_t buffer[4];
  int n_opr_bytes;
  expressionS exp;
  long imm;
  
  if (!parse_operand_and_comma(buffer, &n_opr_bytes, &exp))
    goto fail;
  
  if (!lex_imm(&imm, NULL))
    goto fail;
  
  int size = size_from_suffix(insn, 0);
  
  if (!validate_immediate(imm, size))
    goto fail;
  
  uint8_t bm = calculate_bm_value(size, imm);
  
  emit_instruction(insn, bm, buffer, n_opr_bytes, &exp);
  
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool parse_register(int reg_type, int *reg_value)
{
  return lex_reg_name(reg_type, reg_value);
}

static bool parse_comma(void)
{
  return lex_match(',');
}

static uint8_t create_bm_value(int Dn)
{
  return (Dn << 4) | 0x81;
}

static uint8_t create_xb_value(int Di)
{
  return Di | 0xb8;
}

static void encode_instruction(const struct instruction *insn, uint8_t bm, uint8_t xb)
{
  char *f = s12z_new_insn(3);
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
  number_to_chars_bigendian(f++, xb, 1);
}

static bool
bm_regd_reg(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Di = 0;
  int Dn = 0;

  if (!parse_register(REG_BIT_Dn, &Di))
    goto fail;

  if (!parse_comma())
    goto fail;

  if (!parse_register(REG_BIT_Dn, &Dn))
    goto fail;

  uint8_t bm = create_bm_value(Dn);
  uint8_t xb = create_xb_value(Di);

  encode_instruction(insn, bm, xb);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}





static bool parse_register(int *Dd)
{
    return lex_reg_name(REG_BIT_Dn, Dd);
}

static bool parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    return lex_opr(buffer, n_bytes, exp, false);
}

static bool validate_width(long width, const char *insn_name)
{
    if (width < 0 || width > 31)
    {
        as_bad(_("Invalid width value for %s"), insn_name);
        return false;
    }
    return true;
}

static bool validate_offset(long offset, const char *insn_name)
{
    if (offset < 0 || offset > 31)
    {
        as_bad(_("Invalid offset value for %s"), insn_name);
        return false;
    }
    return true;
}

static bool parse_width(long *width, const char *insn_name)
{
    if (!lex_imm(width, NULL))
        return false;
    return validate_width(*width, insn_name);
}

static bool parse_offset(long *offset, const char *insn_name)
{
    if (!lex_constant(offset))
        return false;
    return validate_offset(*offset, insn_name);
}

static uint8_t calculate_i1(long width, long offset)
{
    return (width << 5) | offset;
}

static uint8_t calculate_bb(const struct instruction *insn, short ie, long width)
{
    int size = size_from_suffix(insn, 0);
    uint8_t bb = ie ? 0x80 : 0x00;
    bb |= 0x60;
    bb |= (size - 1) << 2;
    bb |= width >> 3;
    return bb;
}

static void emit_instruction(int Dd, uint8_t bb, uint8_t i1, 
                            uint8_t *buffer, int n_bytes, expressionS *exp)
{
    char *f = s12z_new_insn(4 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Dd, 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);
    emit_opr(f, buffer, n_bytes, exp);
}

static bool
bf_reg_opr_imm(const struct instruction *insn, short ie)
{
    char *ilp = input_line_pointer;
    int Dd = 0;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    long width;
    long offset;

    if (!parse_register(&Dd))
        goto fail;

    if (!lex_match(','))
        goto fail;

    if (!parse_operand(buffer, &n_bytes, &exp))
        goto fail;

    if (!lex_match(','))
        goto fail;

    if (!parse_width(&width, insn->name))
        goto fail;

    if (!lex_match(':'))
        goto fail;

    if (!parse_offset(&offset, insn->name))
        goto fail;

    uint8_t i1 = calculate_i1(width, offset);
    uint8_t bb = calculate_bb(insn, ie, width);
    
    emit_instruction(Dd, bb, i1, buffer, n_bytes, &exp);
    
    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}


static bool parse_register(int *Ds)
{
    if (!lex_match(','))
        return false;
    if (!lex_reg_name(REG_BIT_Dn, Ds))
        return false;
    if (!lex_match(','))
        return false;
    return true;
}

static bool parse_width(long *width, const struct instruction *insn)
{
    if (!lex_imm(width, NULL))
        return false;
    if (*width < 0 || *width > 31) {
        as_bad(_("Invalid width value for %s"), insn->name);
        return false;
    }
    return true;
}

static bool parse_offset(long *offset, const struct instruction *insn)
{
    if (!lex_match(':'))
        return false;
    if (!lex_constant(offset))
        return false;
    if (*offset < 0 || *offset > 31) {
        as_bad(_("Invalid offset value for %s"), insn->name);
        return false;
    }
    return true;
}

static uint8_t calculate_i1_byte(long width, long offset)
{
    return (width << 5) | offset;
}

static uint8_t calculate_bb_byte(short ie, int size, long width)
{
    uint8_t bb = ie ? 0x80 : 0x00;
    bb |= 0x70;
    bb |= (size - 1) << 2;
    bb |= width >> 3;
    return bb;
}

static void emit_instruction_bytes(int Ds, uint8_t bb, uint8_t i1, uint8_t *buffer, 
                                  int n_bytes, expressionS *exp)
{
    char *f = s12z_new_insn(4 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Ds, 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);
    emit_opr(f, buffer, n_bytes, exp);
}

static bool bf_opr_reg_imm(const struct instruction *insn, short ie)
{
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    int Ds = 0;
    long width, offset;
    
    if (!lex_opr(buffer, &n_bytes, &exp, false))
        goto fail;
    
    if (!parse_register(&Ds))
        goto fail;
    
    if (!parse_width(&width, insn))
        goto fail;
    
    if (!parse_offset(&offset, insn))
        goto fail;
    
    uint8_t i1 = calculate_i1_byte(width, offset);
    int size = size_from_suffix(insn, 0);
    uint8_t bb = calculate_bb_byte(ie, size, width);
    
    emit_instruction_bytes(Ds, bb, i1, buffer, n_bytes, &exp);
    
    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}



static bool parse_register(int reg_type, int *reg_value)
{
  return lex_reg_name(reg_type, reg_value);
}

static bool parse_comma(void)
{
  return lex_match(',');
}

static bool parse_colon(void)
{
  return lex_match(':');
}

static bool validate_range(long value, long min, long max, const char *type, const char *insn_name)
{
  if (value < min || value > max)
    {
      as_bad(_("Invalid %s value for %s"), type, insn_name);
      return false;
    }
  return true;
}

static uint8_t compute_bb_byte(short ie, int Ds, long width)
{
  uint8_t bb = ie ? 0x80 : 0x00;
  bb |= 0x20;
  bb |= Ds << 2;
  bb |= width >> 3;
  return bb;
}

static uint8_t compute_i1_byte(long width, long offset)
{
  return (width << 5) | offset;
}

static void emit_instruction_bytes(int Dd, uint8_t bb, uint8_t i1)
{
  char *f = s12z_new_insn(4);
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, 0x08 | Dd, 1);
  number_to_chars_bigendian(f++, bb, 1);
  number_to_chars_bigendian(f++, i1, 1);
}

#define MIN_WIDTH_OFFSET 0
#define MAX_WIDTH_OFFSET 31

static bool
bf_reg_reg_imm(const struct instruction *insn, short ie)
{
  char *ilp = input_line_pointer;
  int Dd = 0;
  int Ds = 0;
  long width;
  long offset;

  if (!parse_register(REG_BIT_Dn, &Dd))
    goto fail;

  if (!parse_comma())
    goto fail;

  if (!parse_register(REG_BIT_Dn, &Ds))
    goto fail;

  if (!parse_comma())
    goto fail;

  if (!lex_imm(&width, NULL))
    goto fail;

  if (!validate_range(width, MIN_WIDTH_OFFSET, MAX_WIDTH_OFFSET, "width", insn->name))
    goto fail;

  if (!parse_colon())
    goto fail;

  if (!lex_constant(&offset))
    goto fail;

  if (!validate_range(offset, MIN_WIDTH_OFFSET, MAX_WIDTH_OFFSET, "offset", insn->name))
    goto fail;

  uint8_t bb = compute_bb_byte(ie, Ds, width);
  uint8_t i1 = compute_i1_byte(width, offset);
  
  emit_instruction_bytes(Dd, bb, i1);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool parse_register(int reg_mask, int *reg_value)
{
  return lex_reg_name(reg_mask, reg_value) && lex_match(',');
}

static bool parse_last_register(int reg_mask, int *reg_value)
{
  return lex_reg_name(reg_mask, reg_value);
}

static void encode_instruction(int Dd, int Ds, int Dp, short ie)
{
  uint8_t bb = ie ? 0x80 : 0x00;
  bb |= Ds << 2;
  bb |= Dp;

  char *f = s12z_new_insn(3);
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, 0x08 | Dd, 1);
  number_to_chars_bigendian(f++, bb, 1);
}

static bool
bf_reg_reg_reg(const struct instruction *insn ATTRIBUTE_UNUSED, short ie)
{
  char *ilp = input_line_pointer;
  int Dd = 0;
  int Ds = 0;
  int Dp = 0;

  #define DP_REG_MASK ((0x01u << REG_D2) | \
                       (0x01u << REG_D3) | \
                       (0x01u << REG_D4) | \
                       (0x01u << REG_D5))

  if (!parse_register(REG_BIT_Dn, &Dd))
    goto fail;

  if (!parse_register(REG_BIT_Dn, &Ds))
    goto fail;

  if (!parse_last_register(DP_REG_MASK, &Dp))
    goto fail;

  encode_instruction(Dd, Ds, Dp, ie);
  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
  return lex_opr(buffer, n_bytes, exp, false) && lex_match(',');
}

static bool
parse_source_register(int *Ds)
{
  return lex_reg_name(REG_BIT_Dn, Ds) && lex_match(',');
}

static bool
parse_destination_register(int *Dp)
{
  const uint16_t valid_regs = (0x01u << REG_D2) |
                              (0x01u << REG_D3) |
                              (0x01u << REG_D4) |
                              (0x01u << REG_D5);
  return lex_reg_name(valid_regs, Dp);
}

static uint8_t
build_control_byte(bool ie, int Dp, int size)
{
  const uint8_t IE_BIT = 0x80;
  const uint8_t BASE_VALUE = 0x50;
  
  uint8_t bb = ie ? IE_BIT : 0x00;
  bb |= BASE_VALUE;
  bb |= Dp;
  bb |= (size - 1) << 2;
  return bb;
}

static void
emit_instruction(int Ds, uint8_t bb, uint8_t *buffer, int n_bytes, expressionS *exp)
{
  const uint8_t DS_MASK = 0x08;
  
  char *f = s12z_new_insn(3 + n_bytes);
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, DS_MASK | Ds, 1);
  number_to_chars_bigendian(f++, bb, 1);
  emit_opr(f, buffer, n_bytes, exp);
}

static bool
bf_opr_reg_reg(const struct instruction *insn, short ie)
{
  char *ilp = input_line_pointer;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  
  if (!parse_operand(buffer, &n_bytes, &exp))
    goto fail;

  int Ds = 0;
  if (!parse_source_register(&Ds))
    goto fail;

  int Dp = 0;
  if (!parse_destination_register(&Dp))
    goto fail;

  int size = size_from_suffix(insn, 0);
  uint8_t bb = build_control_byte(ie, Dp, size);
  
  emit_instruction(Ds, bb, buffer, n_bytes, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool parse_bit_field_register(int *reg)
{
  return lex_reg_name(REG_BIT_Dn, reg);
}

static bool parse_parameter_register(int *reg)
{
  return lex_reg_name((0x01u << REG_D2) |
                      (0x01u << REG_D3) |
                      (0x01u << REG_D4) |
                      (0x01u << REG_D5),
                      reg);
}

static bool parse_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
  return lex_opr(buffer, n_bytes, exp, false);
}

static uint8_t build_control_byte(const struct instruction *insn, short ie, int Dp)
{
  int size = size_from_suffix(insn, 0);
  uint8_t bb = ie ? 0x80 : 0x00;
  bb |= 0x40;
  bb |= Dp;
  bb |= (size - 1) << 2;
  return bb;
}

static void emit_instruction(int Dd, uint8_t bb, uint8_t *buffer, int n_bytes, expressionS *exp)
{
  char *f = s12z_new_insn(3 + n_bytes);
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, 0x08 | Dd, 1);
  number_to_chars_bigendian(f++, bb, 1);
  emit_opr(f, buffer, n_bytes, exp);
}

static bool
bf_reg_opr_reg(const struct instruction *insn, short ie)
{
  char *ilp = input_line_pointer;
  int Dd = 0;
  
  if (!parse_bit_field_register(&Dd))
    goto fail;
    
  if (!lex_match(','))
    goto fail;
    
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  
  if (!parse_operand(buffer, &n_bytes, &exp))
    goto fail;
    
  if (!lex_match(','))
    goto fail;
    
  int Dp = 0;
  
  if (!parse_parameter_register(&Dp))
    goto fail;
    
  uint8_t bb = build_control_byte(insn, ie, Dp);
  emit_instruction(Dd, bb, buffer, n_bytes, &exp);
  
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}



static bool
bfe_reg_reg_reg(const struct instruction *insn)
{
    const int BFE_OPERATION_MODE = 0;
    return bf_reg_reg_reg(insn, BFE_OPERATION_MODE);
}

static bool
bfi_reg_reg_reg(const struct instruction *insn)
{
    const int BFI_OPERATION_MODE = 1;
    return bf_reg_reg_reg(insn, BFI_OPERATION_MODE);
}

static bool bfe_reg_reg_imm(const struct instruction *insn)
{
  return bf_reg_reg_imm(insn, 0);
}

static bool bfi_reg_reg_imm(const struct instruction *insn)
{
    const int BFI_OPERATION_MODE = 1;
    return bf_reg_reg_imm(insn, BFI_OPERATION_MODE);
}


static bool bfe_reg_opr_reg(const struct instruction *insn)
{
    return bf_reg_opr_reg(insn, 0);
}

static bool bfi_reg_opr_reg(const struct instruction *insn)
{
    return bf_reg_opr_reg(insn, 1);
}


static bool
bfe_opr_reg_reg(const struct instruction *insn)
{
  const int BFE_OPERATION_MODE = 0;
  return bf_opr_reg_reg(insn, BFE_OPERATION_MODE);
}

static bool
bfi_opr_reg_reg(const struct instruction *insn)
{
  const int BFI_OPERATION_MODE = 1;
  return bf_opr_reg_reg(insn, BFI_OPERATION_MODE);
}

static bool bfe_reg_opr_imm(const struct instruction *insn)
{
    const int BFE_IMMEDIATE_VALUE = 0;
    return bf_reg_opr_imm(insn, BFE_IMMEDIATE_VALUE);
}

static bool bfi_reg_opr_imm(const struct instruction *insn)
{
    const int BFI_OPERATION_MODE = 1;
    return bf_reg_opr_imm(insn, BFI_OPERATION_MODE);
}

static bool bfe_opr_reg_imm(const struct instruction *insn)
{
    const int BFE_DEFAULT_FLAG = 0;
    return bf_opr_reg_imm(insn, BFE_DEFAULT_FLAG);
}

static bool
bfi_opr_reg_imm(const struct instruction *insn)
{
    const int BFI_OPERATION_MODE = 1;
    return bf_opr_reg_imm(insn, BFI_OPERATION_MODE);
}




static bool
tb_reg_rel(const struct instruction *insn)
{
  char *ilp = input_line_pointer;

  int reg;
  if (!lex_reg_name(REG_BIT_Dn | REG_BIT_XY, &reg))
    goto fail;

  if (!lex_match(','))
    goto fail;

  bool long_displacement;
  expressionS exp;
  if (!lex_15_bit_offset(&long_displacement, &exp))
    goto fail;

  uint8_t lb = build_lb_byte(reg, insn);

  char *f = s12z_new_insn(long_displacement ? 4 : 3);
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, lb, 1);

  emit_15_bit_offset(f, 4, &exp);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static uint8_t
get_register_bits(int reg)
{
  if (reg == REG_X || reg == REG_Y)
    return 0x08;
  return reg;
}

static uint8_t
get_y_register_bit(int reg)
{
  return (reg == REG_Y) ? 0x01 : 0x00;
}

#define CONDITION_NE 0x00
#define CONDITION_EQ 0x01
#define CONDITION_PL 0x02
#define CONDITION_MI 0x03
#define CONDITION_GT 0x04
#define CONDITION_LE 0x05
#define CONDITION_SHIFT 4
#define DECREMENT_FLAG 0x80

static uint8_t
get_condition_bits(const char *name)
{
  const char *condition = name + 2;
  
  if (startswith(condition, "ne"))
    return CONDITION_NE << CONDITION_SHIFT;
  if (startswith(condition, "eq"))
    return CONDITION_EQ << CONDITION_SHIFT;
  if (startswith(condition, "pl"))
    return CONDITION_PL << CONDITION_SHIFT;
  if (startswith(condition, "mi"))
    return CONDITION_MI << CONDITION_SHIFT;
  if (startswith(condition, "gt"))
    return CONDITION_GT << CONDITION_SHIFT;
  if (startswith(condition, "le"))
    return CONDITION_LE << CONDITION_SHIFT;
  
  return 0;
}

static uint8_t
get_operation_bits(char op)
{
  if (op == 'd')
    return DECREMENT_FLAG;
  if (op == 't')
    return 0;
  gas_assert(0);
  return 0;
}

static uint8_t
build_lb_byte(int reg, const struct instruction *insn)
{
  uint8_t lb = 0x00;
  
  lb |= get_register_bits(reg);
  lb |= get_y_register_bit(reg);
  lb |= get_condition_bits(insn->name);
  lb |= get_operation_bits(insn->name[0]);
  
  return lb;
}


static uint8_t get_condition_code(const char *name)
{
  if (startswith(name + 2, "ne"))
    return 0x00 << 4;
  if (startswith(name + 2, "eq"))
    return 0x01 << 4;
  if (startswith(name + 2, "pl"))
    return 0x02 << 4;
  if (startswith(name + 2, "mi"))
    return 0x03 << 4;
  if (startswith(name + 2, "gt"))
    return 0x04 << 4;
  if (startswith(name + 2, "le"))
    return 0x05 << 4;
  return 0;
}

static uint8_t get_instruction_modifier(char first_char)
{
  if (first_char == 'd')
    return 0x80;
  if (first_char == 't')
    return 0x00;
  gas_assert(0);
  return 0x00;
}

static bool parse_operand_and_offset(uint8_t *buffer, int *n_bytes, 
                                     expressionS *exp, bool *long_displacement,
                                     expressionS *exp2)
{
  if (!lex_opr(buffer, n_bytes, exp, false))
    return false;
  
  if (!lex_match(','))
    return false;
  
  return lex_15_bit_offset(long_displacement, exp2);
}

static uint8_t build_lb_byte(const struct instruction *insn)
{
  uint8_t lb = 0x0C;
  lb |= get_condition_code(insn->name);
  lb |= get_instruction_modifier(insn->name[0]);
  lb |= size_from_suffix(insn, 0) - 1;
  return lb;
}

static void emit_instruction(const struct instruction *insn, uint8_t lb,
                            uint8_t *buffer, int n_bytes, expressionS *exp,
                            bool long_displacement, expressionS *exp2)
{
  int instruction_size = n_bytes + (long_displacement ? 4 : 3);
  char *f = s12z_new_insn(instruction_size);
  
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, lb, 1);
  f = emit_opr(f, buffer, n_bytes, exp);
  emit_15_bit_offset(f, n_bytes + 4, exp2);
}

static bool tb_opr_rel(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  bool long_displacement;
  expressionS exp2;
  
  if (!parse_operand_and_offset(buffer, &n_bytes, &exp, 
                                &long_displacement, &exp2))
    goto fail;
  
  uint8_t lb = build_lb_byte(insn);
  
  emit_instruction(insn, lb, buffer, n_bytes, &exp, 
                  long_displacement, &exp2);
  
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}




static bool parse_register(int reg_type, int *reg_value)
{
  return lex_reg_name(reg_type, reg_value);
}

static bool parse_comma(void)
{
  return lex_match(',');
}

static bool parse_registers_and_offset(int *Di, int *Dn, bool *long_displacement, expressionS *exp)
{
  if (!parse_register(REG_BIT_Dn, Di))
    return false;
    
  if (!parse_comma())
    return false;
    
  if (!parse_register(REG_BIT_Dn, Dn))
    return false;
    
  if (!parse_comma())
    return false;
    
  if (!lex_15_bit_offset(long_displacement, exp))
    return false;
    
  return true;
}

static void encode_instruction(const struct instruction *insn, int Di, int Dn, 
                               bool long_displacement, expressionS *exp)
{
  const uint8_t BM_BASE = 0x81;
  const uint8_t XB_BASE = 0xb8;
  const int BM_SHIFT = 4;
  const int SHORT_INSN_SIZE = 4;
  const int LONG_INSN_SIZE = 5;
  
  uint8_t bm = BM_BASE | (Dn << BM_SHIFT);
  uint8_t xb = XB_BASE | Di;
  
  int insn_size = long_displacement ? LONG_INSN_SIZE : SHORT_INSN_SIZE;
  char *f = s12z_new_insn(insn_size);
  
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
  number_to_chars_bigendian(f++, xb, 1);
  
  emit_15_bit_offset(f, LONG_INSN_SIZE, exp);
}

static bool test_br_reg_reg_rel(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Di = 0;
  int Dn = 0;
  bool long_displacement;
  expressionS exp;
  
  if (!parse_registers_and_offset(&Di, &Dn, &long_displacement, &exp))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }
  
  encode_instruction(insn, Di, Dn, long_displacement, &exp);
  return true;
}

static bool parse_opr_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    return lex_opr(buffer, n_bytes, exp, false);
}

static bool parse_register_operand(int *Dn)
{
    return lex_reg_name(REG_BIT_Dn, Dn);
}

static bool parse_comma(void)
{
    return lex_match(',');
}

static uint8_t build_bm_byte(int Dn, int size)
{
    const uint8_t BM_BASE = 0x81;
    const int DN_SHIFT = 4;
    const int SIZE_SHIFT = 2;
    
    uint8_t bm = BM_BASE;
    bm |= Dn << DN_SHIFT;
    bm |= (size - 1) << SIZE_SHIFT;
    return bm;
}

static void emit_instruction_bytes(char *f, const struct instruction *insn, 
                                  uint8_t bm, uint8_t *buffer, int n_bytes,
                                  expressionS *exp, expressionS *exp2, int n)
{
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    f = emit_opr(f, buffer, n_bytes, exp);
    emit_15_bit_offset(f, n, exp2);
}

static bool parse_operands(uint8_t *buffer, int *n_bytes, expressionS *exp,
                          int *Dn, bool *long_displacement, expressionS *exp2)
{
    if (!parse_opr_operand(buffer, n_bytes, exp))
        return false;
    
    if (!parse_comma())
        return false;
    
    if (!parse_register_operand(Dn))
        return false;
    
    if (!parse_comma())
        return false;
    
    if (!lex_15_bit_offset(long_displacement, exp2))
        return false;
    
    return true;
}

static bool test_br_opr_reg_rel(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    int Dn = 0;
    bool long_displacement;
    expressionS exp2;
    
    if (!parse_operands(buffer, &n_bytes, &exp, &Dn, &long_displacement, &exp2))
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }
    
    int size = size_from_suffix(insn, 0);
    uint8_t bm = build_bm_byte(Dn, size);
    
    const int LONG_DISP_SIZE = 4;
    const int SHORT_DISP_SIZE = 3;
    int n = n_bytes + (long_displacement ? LONG_DISP_SIZE : SHORT_DISP_SIZE);
    
    char *f = s12z_new_insn(n);
    emit_instruction_bytes(f, insn, bm, buffer, n_bytes, &exp, &exp2, n);
    
    return true;
}


static bool lex_operand_and_comma(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
    if (!lex_opr(buffer, n_bytes, exp, false))
        return false;
    return lex_match(',');
}

static bool lex_immediate_and_comma(long *imm)
{
    if (!lex_imm(imm, NULL))
        return false;
    if (*imm < 0 || *imm > 31)
        return false;
    return lex_match(',');
}

static uint8_t build_bitmap(long imm, int size)
{
    uint8_t bm = 0x80;
    bm |= (imm & 0x07) << 4;
    bm |= (imm >> 3) & 0x03;
    
    if (size == 4)
        bm |= 0x08;
    else if (size == 2)
        bm |= 0x02;
    
    return bm;
}

static void emit_instruction(const struct instruction *insn, uint8_t bm, 
                            uint8_t *buffer, int n_bytes, expressionS *exp,
                            bool long_displacement, expressionS *exp2)
{
    char *f = s12z_new_insn(n_bytes + (long_displacement ? 4 : 3));
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    f = emit_opr(f, buffer, n_bytes, exp);
    emit_15_bit_offset(f, n_bytes + 4, exp2);
}

static bool test_br_opr_imm_rel(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    long imm;
    bool long_displacement;
    expressionS exp2;
    
    if (!lex_operand_and_comma(buffer, &n_bytes, &exp))
        goto fail;
    
    if (!lex_immediate_and_comma(&imm))
        goto fail;
    
    if (!lex_15_bit_offset(&long_displacement, &exp2))
        goto fail;
    
    int size = size_from_suffix(insn, 0);
    uint8_t bm = build_bitmap(imm, size);
    
    emit_instruction(insn, bm, buffer, n_bytes, &exp, long_displacement, &exp2);
    
    return true;
    
fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}


static bool parse_register(int *Di)
{
    return lex_reg_name(REG_BIT_Dn, Di);
}

static bool parse_immediate(long *imm)
{
    return lex_imm(imm, NULL) && *imm >= 0 && *imm <= 31;
}

static bool parse_comma(void)
{
    return lex_match(',');
}

static bool parse_offset(bool *long_displacement, expressionS *exp)
{
    return lex_15_bit_offset(long_displacement, exp);
}

static void encode_instruction(const struct instruction *insn, int Di, long imm, 
                               bool long_displacement, expressionS *exp)
{
    uint8_t bm = Di | (imm << 3);
    char *f = s12z_new_insn(long_displacement ? 4 : 3);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    emit_15_bit_offset(f, 4, exp);
}

static bool test_br_reg_imm_rel(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    int Di = 0;
    long imm;
    bool long_displacement;
    expressionS exp;

    if (!parse_register(&Di))
        goto fail;

    if (!parse_comma())
        goto fail;

    if (!parse_immediate(&imm))
        goto fail;

    if (!parse_comma())
        goto fail;

    if (!parse_offset(&long_displacement, &exp))
        goto fail;

    encode_instruction(insn, Di, imm, long_displacement, &exp);
    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}




static const struct instruction opcodes[] = {
  {"bgnd", 1,  0x00,  no_operands, 0},
  {"nop", 1,   0x01,  no_operands, 0},

  {"brclr", 1, 0x02,  test_br_reg_reg_rel, 0},
  {"brset", 1, 0x03,  test_br_reg_reg_rel, 0},

  {"brclr", 1, 0x02,  test_br_reg_imm_rel, 0},
  {"brset", 1, 0x03,  test_br_reg_imm_rel, 0},

  {"brclr.b", 1, 0x02, test_br_opr_reg_rel, 0},
  {"brclr.w", 1, 0x02, test_br_opr_reg_rel, 0},
  {"brclr.l", 1, 0x02, test_br_opr_reg_rel, 0},

  {"brset.b", 1, 0x03, test_br_opr_reg_rel, 0},
  {"brset.w", 1, 0x03, test_br_opr_reg_rel, 0},
  {"brset.l", 1, 0x03, test_br_opr_reg_rel, 0},

  {"brclr.b", 1, 0x02, test_br_opr_imm_rel, 0},
  {"brclr.w", 1, 0x02, test_br_opr_imm_rel, 0},
  {"brclr.l", 1, 0x02, test_br_opr_imm_rel, 0},

  {"brset.b", 1, 0x03, test_br_opr_imm_rel, 0},
  {"brset.w", 1, 0x03, test_br_opr_imm_rel, 0},
  {"brset.l", 1, 0x03, test_br_opr_imm_rel, 0},

  {"psh", 1,   0x04,  psh_pull, 0},
  {"pul", 1,   0x04,  psh_pull, 0},

  {"rts", 1,   0x05,  no_operands, 0},
  {"lea", 1,   0x06,  reg67sxy_opr, 0},

  {"dbne", 1,  0x0b,  tb_reg_rel, 0},
  {"dbeq", 1,  0x0b,  tb_reg_rel, 0},
  {"dbpl", 1,  0x0b,  tb_reg_rel, 0},
  {"dbmi", 1,  0x0b,  tb_reg_rel, 0},
  {"dbgt", 1,  0x0b,  tb_reg_rel, 0},
  {"dble", 1,  0x0b,  tb_reg_rel, 0},

  {"dbne.b", 1,  0x0b,  tb_opr_rel, 0},
  {"dbeq.b", 1,  0x0b,  tb_opr_rel, 0},
  {"dbpl.b", 1,  0x0b,  tb_opr_rel, 0},
  {"dbmi.b", 1,  0x0b,  tb_opr_rel, 0},
  {"dbgt.b", 1,  0x0b,  tb_opr_rel, 0},
  {"dble.b", 1,  0x0b,  tb_opr_rel, 0},

  {"dbne.w", 1,  0x0b,  tb_opr_rel, 0},
  {"dbeq.w", 1,  0x0b,  tb_opr_rel, 0},
  {"dbpl.w", 1,  0x0b,  tb_opr_rel, 0},
  {"dbmi.w", 1,  0x0b,  tb_opr_rel, 0},
  {"dbgt.w", 1,  0x0b,  tb_opr_rel, 0},
  {"dble.w", 1,  0x0b,  tb_opr_rel, 0},

  {"dbne.p", 1,  0x0b,  tb_opr_rel, 0},
  {"dbeq.p", 1,  0x0b,  tb_opr_rel, 0},
  {"dbpl.p", 1,  0x0b,  tb_opr_rel, 0},
  {"dbmi.p", 1,  0x0b,  tb_opr_rel, 0},
  {"dbgt.p", 1,  0x0b,  tb_opr_rel, 0},
  {"dble.p", 1,  0x0b,  tb_opr_rel, 0},

  {"dbne.l", 1,  0x0b,  tb_opr_rel, 0},
  {"dbeq.l", 1,  0x0b,  tb_opr_rel, 0},
  {"dbpl.l", 1,  0x0b,  tb_opr_rel, 0},
  {"dbmi.l", 1,  0x0b,  tb_opr_rel, 0},
  {"dbgt.l", 1,  0x0b,  tb_opr_rel, 0},
  {"dble.l", 1,  0x0b,  tb_opr_rel, 0},

  {"tbne", 1,  0x0b,  tb_reg_rel, 0},
  {"tbeq", 1,  0x0b,  tb_reg_rel, 0},
  {"tbpl", 1,  0x0b,  tb_reg_rel, 0},
  {"tbmi", 1,  0x0b,  tb_reg_rel, 0},
  {"tbgt", 1,  0x0b,  tb_reg_rel, 0},
  {"tble", 1,  0x0b,  tb_reg_rel, 0},

  {"tbne.b", 1,  0x0b,  tb_opr_rel, 0},
  {"tbeq.b", 1,  0x0b,  tb_opr_rel, 0},
  {"tbpl.b", 1,  0x0b,  tb_opr_rel, 0},
  {"tbmi.b", 1,  0x0b,  tb_opr_rel, 0},
  {"tbgt.b", 1,  0x0b,  tb_opr_rel, 0},
  {"tble.b", 1,  0x0b,  tb_opr_rel, 0},

  {"tbne.w", 1,  0x0b,  tb_opr_rel, 0},
  {"tbeq.w", 1,  0x0b,  tb_opr_rel, 0},
  {"tbpl.w", 1,  0x0b,  tb_opr_rel, 0},
  {"tbmi.w", 1,  0x0b,  tb_opr_rel, 0},
  {"tbgt.w", 1,  0x0b,  tb_opr_rel, 0},
  {"tble.w", 1,  0x0b,  tb_opr_rel, 0},

  {"tbne.p", 1,  0x0b,  tb_opr_rel, 0},
  {"tbeq.p", 1,  0x0b,  tb_opr_rel, 0},
  {"tbpl.p", 1,  0x0b,  tb_opr_rel, 0},
  {"tbmi.p", 1,  0x0b,  tb_opr_rel, 0},
  {"tbgt.p", 1,  0x0b,  tb_opr_rel, 0},
  {"tble.p", 1,  0x0b,  tb_opr_rel, 0},

  {"tbne.l", 1,  0x0b,  tb_opr_rel, 0},
  {"tbeq.l", 1,  0x0b,  tb_opr_rel, 0},
  {"tbpl.l", 1,  0x0b,  tb_opr_rel, 0},
  {"tbmi.l", 1,  0x0b,  tb_opr_rel, 0},
  {"tbgt.l", 1,  0x0b,  tb_opr_rel, 0},
  {"tble.l", 1,  0x0b,  tb_opr_rel, 0},

  {"mov.b", 1, 0x0c,  imm_opr, 0},
  {"mov.w", 1, 0x0d,  imm_opr, 0},
  {"mov.p", 1, 0x0e,  imm_opr, 0},
  {"mov.l", 1, 0x0f,  imm_opr, 0},

  {"rol",   1, 0x10,  rol, 0},
  {"rol.b", 1, 0x10,  rol, 0},
  {"rol.w", 1, 0x10,  rol, 0},
  {"rol.p", 1, 0x10,  rol, 0},
  {"rol.l", 1, 0x10,  rol, 0},

  {"ror",   1, 0x10,  ror, 0},
  {"ror.b", 1, 0x10,  ror, 0},
  {"ror.w", 1, 0x10,  ror, 0},
  {"ror.p", 1, 0x10,  ror, 0},
  {"ror.l", 1, 0x10,  ror, 0},

  {"lsl", 1,   0x10,  shift_reg, 0},
  {"lsr", 1,   0x10,  shift_reg, 0},
  {"asl", 1,   0x10,  shift_reg, 0},
  {"asr", 1,   0x10,  shift_reg, 0},

  {"lsl.b", 1, 0x10,  shift_two_operand, 0},
  {"lsl.w", 1, 0x10,  shift_two_operand, 0},
  {"lsl.p", 1, 0x10,  shift_two_operand, 0},
  {"lsl.l", 1, 0x10,  shift_two_operand, 0},
  {"asl.b", 1, 0x10,  shift_two_operand, 0},
  {"asl.w", 1, 0x10,  shift_two_operand, 0},
  {"asl.p", 1, 0x10,  shift_two_operand, 0},
  {"asl.l", 1, 0x10,  shift_two_operand, 0},

  {"lsr.b", 1, 0x10,  shift_two_operand, 0},
  {"lsr.w", 1, 0x10,  shift_two_operand, 0},
  {"lsr.p", 1, 0x10,  shift_two_operand, 0},
  {"lsr.l", 1, 0x10,  shift_two_operand, 0},
  {"asr.b", 1, 0x10,  shift_two_operand, 0},
  {"asr.w", 1, 0x10,  shift_two_operand, 0},
  {"asr.p", 1, 0x10,  shift_two_operand, 0},
  {"asr.l", 1, 0x10,  shift_two_operand, 0},

  {"lsl.b", 1, 0x10,  shift_opr_imm, 0},
  {"lsl.w", 1, 0x10,  shift_opr_imm, 0},
  {"lsl.p", 1, 0x10,  shift_opr_imm, 0},
  {"lsl.l", 1, 0x10,  shift_opr_imm, 0},
  {"asl.b", 1, 0x10,  shift_opr_imm, 0},
  {"asl.w", 1, 0x10,  shift_opr_imm, 0},
  {"asl.p", 1, 0x10,  shift_opr_imm, 0},
  {"asl.l", 1, 0x10,  shift_opr_imm, 0},

  {"lsr.b", 1, 0x10,  shift_opr_imm, 0},
  {"lsr.w", 1, 0x10,  shift_opr_imm, 0},
  {"lsr.p", 1, 0x10,  shift_opr_imm, 0},
  {"lsr.l", 1, 0x10,  shift_opr_imm, 0},
  {"asr.b", 1, 0x10,  shift_opr_imm, 0},
  {"asr.w", 1, 0x10,  shift_opr_imm, 0},
  {"asr.p", 1, 0x10,  shift_opr_imm, 0},
  {"asr.l", 1, 0x10,  shift_opr_imm, 0},

  {"mov.b", 1, 0x1c,  opr_opr, 0},
  {"mov.w", 1, 0x1d,  opr_opr, 0},
  {"mov.p", 1, 0x1e,  opr_opr, 0},
  {"mov.l", 1, 0x1f,  opr_opr, 0},

  {"bra", 1,   0x20,  rel, 0},
  {"bsr", 1,   0x21,  rel, 0},
  {"bhi", 1,   0x22,  rel, 0},
  {"bls", 1,   0x23,  rel, 0},
  {"bcc", 1,   0x24,  rel, 0},
  {"bhs", 1,   0x24,  rel, 0}, /* Alias for bcc */
  {"bcs", 1,   0x25,  rel, 0},
  {"blo", 1,   0x25,  rel, 0}, /* Alias for bcs */
  {"bne", 1,   0x26,  rel, 0},
  {"beq", 1,   0x27,  rel, 0},
  {"bvc", 1,   0x28,  rel, 0},
  {"bvs", 1,   0x29,  rel, 0},
  {"bpl", 1,   0x2a,  rel, 0},
  {"bmi", 1,   0x2b,  rel, 0},
  {"bge", 1,   0x2c,  rel, 0},
  {"blt", 1,   0x2d,  rel, 0},
  {"bgt", 1,   0x2e,  rel, 0},
  {"ble", 1,   0x2f,  rel, 0},

  {"inc", 1,   0x30,  reg_inh, 0},
  {"clr", 1,   0x38,  reg_inh, 0},
  {"dec", 1,   0x40,  reg_inh, 0},

  {"muls", 1,  0x48,  mul_reg_reg_reg, 0},
  {"mulu", 1,  0x48,  mul_reg_reg_reg, 0},

  {"muls.b", 1,  0x48,  mul_reg_reg_opr, 0},
  {"muls.w", 1,  0x48,  mul_reg_reg_opr, 0},
  {"muls.l", 1,  0x48,  mul_reg_reg_opr, 0},

  {"mulu.b", 1,  0x48,  mul_reg_reg_opr, 0},
  {"mulu.w", 1,  0x48,  mul_reg_reg_opr, 0},
  {"mulu.l", 1,  0x48,  mul_reg_reg_opr, 0},

  {"muls.b", 1,  0x48,  mul_reg_reg_imm, 0},
  {"muls.w", 1,  0x48,  mul_reg_reg_imm, 0},
  {"muls.l", 1,  0x48,  mul_reg_reg_imm, 0},

  {"mulu.b", 1,  0x48,  mul_reg_reg_imm, 0},
  {"mulu.w", 1,  0x48,  mul_reg_reg_imm, 0},
  {"mulu.l", 1,  0x48,  mul_reg_reg_imm, 0},

  {"muls.bb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.bw", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.bp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.bl", 1,  0x48,  mul_reg_opr_opr, 0},

  {"muls.wb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.ww", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.wp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.wl", 1,  0x48,  mul_reg_opr_opr, 0},

  {"muls.pb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.pw", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.pp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.pl", 1,  0x48,  mul_reg_opr_opr, 0},

  {"muls.lb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.lw", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.lp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"muls.ll", 1,  0x48,  mul_reg_opr_opr, 0},

  {"mulu.bb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.bw", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.bp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.bl", 1,  0x48,  mul_reg_opr_opr, 0},

  {"mulu.wb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.ww", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.wp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.wl", 1,  0x48,  mul_reg_opr_opr, 0},

  {"mulu.pb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.pw", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.pp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.pl", 1,  0x48,  mul_reg_opr_opr, 0},

  {"mulu.lb", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.lw", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.lp", 1,  0x48,  mul_reg_opr_opr, 0},
  {"mulu.ll", 1,  0x48,  mul_reg_opr_opr, 0},

  {"add", 1,   0x50,  regd_imm, 0},
  {"and", 1,   0x58,  regd_imm, 0},

  {"add", 1,   0x60,  regd_opr, 0},
  {"and", 1,   0x68,  regd_opr, 0},

  {"sub", 1,   0x70,  regd_imm, 0},
  {"or", 1,    0x78,  regd_imm, 0},

  {"sub", 1,   0x80,  regd_opr, 0},
  {"or",  1,    0x88,  regd_opr, 0},

  {"ld",  1,    0x90,  regdxy_imm, 0},

  {"clr", 1,   0x9a,  clr_xy, 0},
  {"tfr", 1,   0x9e,  tfr, 0},
  {"zex", 1,   0x9e,  tfr, 0},

  {"ld",  1,   0xa0,  regdxy_opr_src, 0xb0},

  {"jmp", 1,   0xaa,  opr, 0xba},
  {"jsr", 1,   0xab,  opr, 0xbb},

  {"exg", 1,   0xae,  tfr, 0},
  {"sex", 1,   0xae,  tfr, 0},

  {"st", 1,    0xc0,  regdxy_opr_dest, 0xd0},

  {"andcc", 1, 0xce,  imm8, 0},
  {"orcc", 1,  0xde,  imm8, 0},

  {"inc.b", 1, 0x9c,  opr, 0},
  {"inc.w", 1, 0x9d,  opr, 0},
  {"inc.l", 1, 0x9f,  opr, 0},

  {"dec.b", 1, 0xac,  opr, 0},
  {"dec.w", 1, 0xad,  opr, 0},
  {"dec.l", 1, 0xaf,  opr, 0},

  {"clr.b", 1, 0xbc,  opr, 0},
  {"clr.w", 1, 0xbd,  opr, 0},
  {"clr.p", 1, 0xbe,  opr, 0},
  {"clr.l", 1, 0xbf,  opr, 0},

  {"com.b", 1, 0xcc,  opr, 0},
  {"com.w", 1, 0xcd,  opr, 0},
  {"com.l", 1, 0xcf,  opr, 0},

  {"neg.b", 1, 0xdc,  opr, 0},
  {"neg.w", 1, 0xdd,  opr, 0},
  {"neg.l", 1, 0xdf,  opr, 0},

  {"bclr",  1, 0xec, bm_regd_imm, 0},
  {"bset",  1, 0xed, bm_regd_imm, 0},
  {"btgl",  1, 0xee, bm_regd_imm, 0},

  {"bclr",  1, 0xec, bm_regd_reg, 0},
  {"bset",  1, 0xed, bm_regd_reg, 0},
  {"btgl",  1, 0xee, bm_regd_reg, 0},

  {"bclr.b",  1, 0xec, bm_opr_imm, 0},
  {"bclr.w",  1, 0xec, bm_opr_imm, 0},
  {"bclr.l",  1, 0xec, bm_opr_imm, 0},

  {"bset.b",  1, 0xed, bm_opr_imm, 0},
  {"bset.w",  1, 0xed, bm_opr_imm, 0},
  {"bset.l",  1, 0xed, bm_opr_imm, 0},

  {"btgl.b",  1, 0xee, bm_opr_imm, 0},
  {"btgl.w",  1, 0xee, bm_opr_imm, 0},
  {"btgl.l",  1, 0xee, bm_opr_imm, 0},

  {"bclr.b",  1, 0xec, bm_opr_reg, 0},
  {"bclr.w",  1, 0xec, bm_opr_reg, 0},
  {"bclr.l",  1, 0xec, bm_opr_reg, 0},

  {"bset.b",  1, 0xed, bm_opr_reg, 0},
  {"bset.w",  1, 0xed, bm_opr_reg, 0},
  {"bset.l",  1, 0xed, bm_opr_reg, 0},

  {"btgl.b",  1, 0xee, bm_opr_reg, 0},
  {"btgl.w",  1, 0xee, bm_opr_reg, 0},
  {"btgl.l",  1, 0xee, bm_opr_reg, 0},

  {"cmp", 1,   0xe0,  regdxy_imm, 0},
  {"cmp", 1,   0xf0,  regdxy_opr_src, 0},

  {"cmp", 1,   0xfc,  regx_regy, 0},
  {"sub", 1,   0xfd,  regd6_regx_regy, 0},
  {"sub", 1,   0xfe,  regd6_regy_regx, 0},

  {"swi", 1,   0xff,  no_operands, 0},

  /* Page 2 */

  /* The -10 below is a kludge.  The opcode is in fact 0x00 */
  {"ld",    2,  -10,  regs_opr_src, 0},

  /* The -9 below is a kludge.  The opcode is in fact 0x01 */
  {"st",    2,  -9,  regs_opr_dest, 0},

  /* The -8 below is a kludge.  The opcode is in fact 0x02 */
  {"cmp",    2,  -8,  regs_opr_src, 0},

  /* The -7 below is a kludge.  The opcode is in fact 0x03 */
  {"ld",    2,  -7,  regs_imm, 0},

  /* The -6 below is a kludge.  The opcode is in fact 0x04 */
  {"cmp",    2,  -6,  regs_imm, 0},

  {"bfext",   2,  0x08,  bfe_reg_reg_reg, 0},
  {"bfext",   2,  0x08,  bfe_reg_reg_imm, 0},
  {"bfext.b", 2,  0x08,  bfe_reg_opr_reg, 0},
  {"bfext.w", 2,  0x08,  bfe_reg_opr_reg, 0},
  {"bfext.p", 2,  0x08,  bfe_reg_opr_reg, 0},
  {"bfext.l", 2,  0x08,  bfe_reg_opr_reg, 0},
  {"bfext.b", 2,  0x08,  bfe_opr_reg_reg, 0},
  {"bfext.w", 2,  0x08,  bfe_opr_reg_reg, 0},
  {"bfext.p", 2,  0x08,  bfe_opr_reg_reg, 0},
  {"bfext.l", 2,  0x08,  bfe_opr_reg_reg, 0},
  {"bfext.b", 2,  0x08,  bfe_reg_opr_imm, 0},
  {"bfext.w", 2,  0x08,  bfe_reg_opr_imm, 0},
  {"bfext.p", 2,  0x08,  bfe_reg_opr_imm, 0},
  {"bfext.l", 2,  0x08,  bfe_reg_opr_imm, 0},
  {"bfext.b", 2,  0x08,  bfe_opr_reg_imm, 0},
  {"bfext.w", 2,  0x08,  bfe_opr_reg_imm, 0},
  {"bfext.p", 2,  0x08,  bfe_opr_reg_imm, 0},
  {"bfext.l", 2,  0x08,  bfe_opr_reg_imm, 0},


  {"bfins",   2,  0x08,  bfi_reg_reg_reg, 0},
  {"bfins",   2,  0x08,  bfi_reg_reg_imm, 0},
  {"bfins.b", 2,  0x08,  bfi_reg_opr_reg, 0},
  {"bfins.w", 2,  0x08,  bfi_reg_opr_reg, 0},
  {"bfins.p", 2,  0x08,  bfi_reg_opr_reg, 0},
  {"bfins.l", 2,  0x08,  bfi_reg_opr_reg, 0},
  {"bfins.b", 2,  0x08,  bfi_opr_reg_reg, 0},
  {"bfins.w", 2,  0x08,  bfi_opr_reg_reg, 0},
  {"bfins.p", 2,  0x08,  bfi_opr_reg_reg, 0},
  {"bfins.l", 2,  0x08,  bfi_opr_reg_reg, 0},
  {"bfins.b", 2,  0x08,  bfi_reg_opr_imm, 0},
  {"bfins.w", 2,  0x08,  bfi_reg_opr_imm, 0},
  {"bfins.p", 2,  0x08,  bfi_reg_opr_imm, 0},
  {"bfins.l", 2,  0x08,  bfi_reg_opr_imm, 0},
  {"bfins.b", 2,  0x08,  bfi_opr_reg_imm, 0},
  {"bfins.w", 2,  0x08,  bfi_opr_reg_imm, 0},
  {"bfins.p", 2,  0x08,  bfi_opr_reg_imm, 0},
  {"bfins.l", 2,  0x08,  bfi_opr_reg_imm, 0},


  {"minu",  2,  0x10,  regd_opr, 0},
  {"maxu",  2,  0x18,  regd_opr, 0},
  {"mins",  2,  0x20,  regd_opr, 0},
  {"maxs",  2,  0x28,  regd_opr, 0},

  {"clb",   2,  0x91,  tfr, 0},

  {"trap",  2,  0x00, trap_imm, 0},
  {"abs",   2,  0x40, reg_inh, 0},
  {"sat",   2,  0xa0, reg_inh, 0},

  {"rti",   2,  0x90, no_operands, 0},
  {"stop",  2,  0x05, no_operands, 0},
  {"wai",   2,  0x06, no_operands, 0},
  {"sys",   2,  0x07, no_operands, 0},

  {"bit",   2,   0x58,  regd_imm, 0},
  {"bit",   2,   0x68,  regd_opr, 0},

  {"adc",   2,   0x50,  regd_imm, 0},
  {"adc",   2,   0x60,  regd_opr, 0},

  {"sbc",   2,   0x70,  regd_imm, 0},
  {"eor",   2,   0x78,  regd_imm, 0},

  {"sbc",   2,   0x80,  regd_opr, 0},
  {"eor",   2,   0x88,  regd_opr, 0},

  {"divs",   2,  0x30,  mul_reg_reg_reg, 0},
  {"divu",   2,  0x30,  mul_reg_reg_reg, 0},

  {"divs.b", 2,  0x30,  mul_reg_reg_opr, 0},
  {"divs.w", 2,  0x30,  mul_reg_reg_opr, 0},
  {"divs.l", 2,  0x30,  mul_reg_reg_opr, 0},

  {"divu.b", 2,  0x30,  mul_reg_reg_opr, 0},
  {"divu.w", 2,  0x30,  mul_reg_reg_opr, 0},
  {"divu.l", 2,  0x30,  mul_reg_reg_opr, 0},

  {"divs.b", 2,  0x30,  mul_reg_reg_imm, 0},
  {"divs.w", 2,  0x30,  mul_reg_reg_imm, 0},
  {"divs.l", 2,  0x30,  mul_reg_reg_imm, 0},

  {"divu.b", 2,  0x30,  mul_reg_reg_imm, 0},
  {"divu.w", 2,  0x30,  mul_reg_reg_imm, 0},
  {"divu.l", 2,  0x30,  mul_reg_reg_imm, 0},

  {"divs.bb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.bw", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.bp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.bl", 2,  0x30,  mul_reg_opr_opr, 0},

  {"divs.wb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.ww", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.wp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.wl", 2,  0x30,  mul_reg_opr_opr, 0},

  {"divs.pb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.pw", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.pp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.pl", 2,  0x30,  mul_reg_opr_opr, 0},

  {"divs.lb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.lw", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.lp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divs.ll", 2,  0x30,  mul_reg_opr_opr, 0},

  {"divu.bb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.bw", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.bp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.bl", 2,  0x30,  mul_reg_opr_opr, 0},

  {"divu.wb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.ww", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.wp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.wl", 2,  0x30,  mul_reg_opr_opr, 0},

  {"divu.pb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.pw", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.pp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.pl", 2,  0x30,  mul_reg_opr_opr, 0},

  {"divu.lb", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.lw", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.lp", 2,  0x30,  mul_reg_opr_opr, 0},
  {"divu.ll", 2,  0x30,  mul_reg_opr_opr, 0},

  {"qmuls",   2,  0xb0,  mul_reg_reg_reg, 0},
  {"qmulu",   2,  0xb0,  mul_reg_reg_reg, 0},

  {"qmuls.b", 2,  0xb0,  mul_reg_reg_opr, 0},
  {"qmuls.w", 2,  0xb0,  mul_reg_reg_opr, 0},
  {"qmuls.l", 2,  0xb0,  mul_reg_reg_opr, 0},

  {"qmulu.b", 2,  0xb0,  mul_reg_reg_opr, 0},
  {"qmulu.w", 2,  0xb0,  mul_reg_reg_opr, 0},
  {"qmulu.l", 2,  0xb0,  mul_reg_reg_opr, 0},

  {"qmuls.b", 2,  0xb0,  mul_reg_reg_imm, 0},
  {"qmuls.w", 2,  0xb0,  mul_reg_reg_imm, 0},
  {"qmuls.l", 2,  0xb0,  mul_reg_reg_imm, 0},

  {"qmulu.b", 2,  0xb0,  mul_reg_reg_imm, 0},
  {"qmulu.w", 2,  0xb0,  mul_reg_reg_imm, 0},
  {"qmulu.l", 2,  0xb0,  mul_reg_reg_imm, 0},

  {"qmuls.bb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.bw", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.bp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.bl", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"qmuls.wb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.ww", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.wp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.wl", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"qmuls.pb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.pw", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.pp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.pl", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"qmuls.lb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.lw", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.lp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmuls.ll", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"qmulu.bb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.bw", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.bp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.bl", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"qmulu.wb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.ww", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.wp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.wl", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"qmulu.pb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.pw", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.pp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.pl", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"qmulu.lb", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.lw", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.lp", 2,  0xb0,  mul_reg_opr_opr, 0},
  {"qmulu.ll", 2,  0xb0,  mul_reg_opr_opr, 0},

  {"macs",   2,  0x48,  mul_reg_reg_reg, 0},
  {"macu",   2,  0x48,  mul_reg_reg_reg, 0},

  {"macs.b", 2,  0x48,  mul_reg_reg_opr, 0},
  {"macs.w", 2,  0x48,  mul_reg_reg_opr, 0},
  {"macs.l", 2,  0x48,  mul_reg_reg_opr, 0},

  {"macu.b", 2,  0x48,  mul_reg_reg_opr, 0},
  {"macu.w", 2,  0x48,  mul_reg_reg_opr, 0},
  {"macu.l", 2,  0x48,  mul_reg_reg_opr, 0},

  {"macs.b", 2,  0x48,  mul_reg_reg_imm, 0},
  {"macs.w", 2,  0x48,  mul_reg_reg_imm, 0},
  {"macs.l", 2,  0x48,  mul_reg_reg_imm, 0},

  {"macu.b", 2,  0x48,  mul_reg_reg_imm, 0},
  {"macu.w", 2,  0x48,  mul_reg_reg_imm, 0},
  {"macu.l", 2,  0x48,  mul_reg_reg_imm, 0},

  {"macs.bb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.bw", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.bp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.bl", 2,  0x48,  mul_reg_opr_opr, 0},

  {"macs.wb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.ww", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.wp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.wl", 2,  0x48,  mul_reg_opr_opr, 0},

  {"macs.pb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.pw", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.pp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.pl", 2,  0x48,  mul_reg_opr_opr, 0},

  {"macs.lb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.lw", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.lp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macs.ll", 2,  0x48,  mul_reg_opr_opr, 0},

  {"macu.bb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.bw", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.bp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.bl", 2,  0x48,  mul_reg_opr_opr, 0},

  {"macu.wb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.ww", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.wp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.wl", 2,  0x48,  mul_reg_opr_opr, 0},

  {"macu.pb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.pw", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.pp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.pl", 2,  0x48,  mul_reg_opr_opr, 0},

  {"macu.lb", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.lw", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.lp", 2,  0x48,  mul_reg_opr_opr, 0},
  {"macu.ll", 2,  0x48,  mul_reg_opr_opr, 0},

  {"mods",   2,  0x38,  mul_reg_reg_reg, 0},
  {"modu",   2,  0x38,  mul_reg_reg_reg, 0},

  {"mods.b", 2,  0x38,  mul_reg_reg_opr, 0},
  {"mods.w", 2,  0x38,  mul_reg_reg_opr, 0},
  {"mods.l", 2,  0x38,  mul_reg_reg_opr, 0},

  {"modu.b", 2,  0x38,  mul_reg_reg_opr, 0},
  {"modu.w", 2,  0x38,  mul_reg_reg_opr, 0},
  {"modu.l", 2,  0x38,  mul_reg_reg_opr, 0},

  {"mods.b", 2,  0x38,  mul_reg_reg_imm, 0},
  {"mods.w", 2,  0x38,  mul_reg_reg_imm, 0},
  {"mods.l", 2,  0x38,  mul_reg_reg_imm, 0},

  {"modu.b", 2,  0x38,  mul_reg_reg_imm, 0},
  {"modu.w", 2,  0x38,  mul_reg_reg_imm, 0},
  {"modu.l", 2,  0x38,  mul_reg_reg_imm, 0},

  {"mods.bb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.bw", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.bp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.bl", 2,  0x38,  mul_reg_opr_opr, 0},

  {"mods.wb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.ww", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.wp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.wl", 2,  0x38,  mul_reg_opr_opr, 0},

  {"mods.pb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.pw", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.pp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.pl", 2,  0x38,  mul_reg_opr_opr, 0},

  {"mods.lb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.lw", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.lp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"mods.ll", 2,  0x38,  mul_reg_opr_opr, 0},

  {"modu.bb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.bw", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.bp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.bl", 2,  0x38,  mul_reg_opr_opr, 0},

  {"modu.wb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.ww", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.wp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.wl", 2,  0x38,  mul_reg_opr_opr, 0},

  {"modu.pb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.pw", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.pp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.pl", 2,  0x38,  mul_reg_opr_opr, 0},

  {"modu.lb", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.lw", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.lp", 2,  0x38,  mul_reg_opr_opr, 0},
  {"modu.ll", 2,  0x38,  mul_reg_opr_opr, 0}
};


/* Gas line assembler entry point.  */

/* This is the main entry point for the machine-dependent assembler.  str
   points to a machine-dependent instruction.  This function is supposed to
   emit the frags/bytes it assembles to.  */
void md_assemble(char *str)
{
    char name[20];
    size_t nlen;
    
    fail_line_pointer = NULL;
    
    nlen = extract_opcode_name(str, name, sizeof(name));
    
    if (nlen == 0)
    {
        as_bad(_("No instruction or missing opcode."));
        return;
    }
    
    input_line_pointer = skip_whites(str + nlen);
    
    if (try_parse_instruction(name))
        return;
    
    report_invalid_instruction(str);
}

static size_t extract_opcode_name(const char *str, char *name, size_t name_size)
{
    size_t nlen = 0;
    
    while (!is_end_of_stmt(str[nlen]) && !is_whitespace(str[nlen]))
    {
        name[nlen] = TOLOWER(str[nlen]);
        nlen++;
        gas_assert(nlen < name_size - 1);
    }
    
    name[nlen] = 0;
    return nlen;
}

static int try_parse_instruction(const char *name)
{
    size_t opcode_count = sizeof(opcodes) / sizeof(opcodes[0]);
    
    for (size_t i = 0; i < opcode_count; ++i)
    {
        const struct instruction *opc = &opcodes[i];
        if (strcmp(name, opc->name) == 0)
        {
            if (opc->parse_operands(opc))
                return 1;
        }
    }
    
    return 0;
}

static void report_invalid_instruction(const char *str)
{
    as_bad(_("Invalid instruction: \"%s\""), str);
    as_bad(_("First invalid token: \"%s\""), fail_line_pointer);
    
    while (*input_line_pointer++)
        ;
}





/* Relocation, relaxation and frag conversions.  */

/* PC-relative offsets are relative to the start of the
   next instruction.  That is, the address of the offset, plus its
   size, since the offset is always the last part of the insn.  */
long
md_pcrel_from (fixS *fixP)
{
  long ret = fixP->fx_size + fixP->fx_frag->fr_address;
  if (fixP->fx_addsy && S_IS_DEFINED (fixP->fx_addsy))
    ret += fixP->fx_where;

  return ret;
}


/* We need a port-specific relaxation function to cope with sym2 - sym1
   relative expressions with both symbols in the same segment (but not
   necessarily in the same frag as this insn), for example:
   ldab sym2-(sym1-2),pc
   sym1:
   The offset can be 5, 9 or 16 bits long.  */

long
s12z_relax_frag (segT seg ATTRIBUTE_UNUSED, fragS *fragP ATTRIBUTE_UNUSED,
		   long stretch ATTRIBUTE_UNUSED)
{
  return 0;
}

void
md_convert_frag (bfd *abfd ATTRIBUTE_UNUSED, asection *sec ATTRIBUTE_UNUSED,
                 fragS *fragP ATTRIBUTE_UNUSED)
{
}

/* On an ELF system, we can't relax a weak symbol.  The weak symbol
   can be overridden at final link time by a non weak symbol.  We can
   relax externally visible symbol because there is no shared library
   and such symbol can't be overridden (unless they are weak).  */

/* Force truly undefined symbols to their maximum size, and generally set up
   the frag list to be relaxed.  */
int
md_estimate_size_before_relax (fragS *fragP ATTRIBUTE_UNUSED, asection *segment ATTRIBUTE_UNUSED)
{
  return 0;
}


/* If while processing a fixup, a reloc really needs to be created
   then it is done here.  */
arelent *
tc_gen_reloc (asection *section, fixS *fixp)
{
  arelent *reloc;

  reloc = notes_alloc (sizeof (arelent));
  reloc->sym_ptr_ptr = notes_alloc (sizeof (asymbol *));
  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;
  reloc->howto = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  
  if (reloc->howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
		    _("Relocation %d is not supported by object file format."),
		    (int) fixp->fx_r_type);
      return NULL;
    }

  reloc->addend = (section->flags & SEC_CODE) ? fixp->fx_addnumber : fixp->fx_offset;

  return reloc;
}

/* See whether we need to force a relocation into the output file.  */
int
tc_s12z_force_relocation (fixS *fixP)
{
  return generic_force_reloc (fixP);
}

/* Here we decide which fixups can be adjusted to make them relative
   to the beginning of the section instead of the symbol.  Basically
   we need to make sure that the linker relaxation is done
   correctly, so in some cases we force the original symbol to be
   used.  */
bool
tc_s12z_fix_adjustable (fixS *fixP ATTRIBUTE_UNUSED)
{
  return true;
}

void
md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  long value = *valP;

  if (fixP->fx_addsy == NULL)
    fixP->fx_done = 1;

  if (fixP->fx_subsy != NULL)
    as_bad_subtract (fixP);

  char *where = fixP->fx_frag->fr_literal + fixP->fx_where;

  apply_relocation_fix(fixP, value, where);
}

static void
apply_relocation_fix(fixS *fixP, long value, char *where)
{
  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_8:
      apply_8bit_reloc(value, where);
      break;
    case BFD_RELOC_16:
      apply_16bit_reloc(value, where);
      break;
    case BFD_RELOC_24:
      apply_24bit_reloc(value, where);
      break;
    case BFD_RELOC_S12Z_OPR:
      apply_s12z_opr_reloc(fixP, value, where);
      break;
    case BFD_RELOC_32:
      apply_32bit_reloc(value, where);
      break;
    case BFD_RELOC_16_PCREL:
      apply_16bit_pcrel_reloc(fixP, value, where);
      break;
    default:
      as_fatal (_("Line %d: unknown relocation type: 0x%x."),
                fixP->fx_line, fixP->fx_r_type);
    }
}

static void
apply_8bit_reloc(long value, char *where)
{
  where[0] = value;
}

static void
apply_16bit_reloc(long value, char *where)
{
  bfd_putb16 (value, where);
}

static void
apply_24bit_reloc(long value, char *where)
{
  bfd_putb24 (value, where);
}

static void
apply_32bit_reloc(long value, char *where)
{
  bfd_putb32 (value, where);
}

static void
apply_s12z_opr_reloc(fixS *fixP, long value, char *where)
{
  switch (fixP->fx_size)
    {
    case 3:
      apply_24bit_reloc(value, where);
      break;
    case 2:
      apply_16bit_reloc(value, where);
      break;
    default:
      abort ();
    }
}

#define PCREL_16BIT_MIN -0x4000
#define PCREL_16BIT_MAX 0x3FFF
#define PCREL_16BIT_MASK 0x8000

static void
apply_16bit_pcrel_reloc(fixS *fixP, long value, char *where)
{
  if (value < PCREL_16BIT_MIN || value > PCREL_16BIT_MAX)
    as_bad_where (fixP->fx_file, fixP->fx_line,
                  _("Value out of 16-bit range."));

  bfd_putb16 (value | PCREL_16BIT_MASK, where);
}

/* Set the ELF specific flags.  */
void
s12z_elf_final_processing (void)
{
}
