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
static long
s12z_strtol(const char *str, char **endptr)
{
  if (str == NULL)
    {
      if (endptr)
        *endptr = NULL;
      return 0L;
    }

  const char *start = str;
  const char *p = str;

  bool negative = false;
  if (*p == '-')
    {
      negative = true;
      ++p;
    }
  else if (*p == '+')
    {
      ++p;
    }

  int base = 0;
  if (literal_prefix_dollar_hex && (*p == '$'))
    {
      base = 16;
      ++p;
    }

  char *local_end = NULL;
  long result = strtol(p, endptr ? &local_end : NULL, base);

  if (endptr)
    {
      if (local_end == p)
        *endptr = (char *) start;
      else
        *endptr = local_end;
    }

  if (negative)
    result = -result;

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
const char *s12z_arch_format(void)
{
    static const char format[] = "elf32-s12z";
    return format;
}

enum bfd_architecture s12z_arch(void)
{
    return bfd_arch_s12z;
}

int s12z_mach(void)
{
    return 0;
}

/* Listing header selected according to cpu.  */
static const char S12Z_LISTING_HEADER[] = "S12Z GAS ";

const char *
s12z_listing_header(void)
{
  return S12Z_LISTING_HEADER;
}

void
md_show_usage (FILE *stream)
{
  if (stream == NULL)
    return;

  const char *msgs[] = {
    _("\ns12z options:\n"),
    _("  -mreg-prefix=PREFIX     set a prefix used to indicate register names (default none)\n"),
    _("  -mdollar-hex            the prefix '$' instead of '0x' is used to indicate literal hexadecimal constants\n")
  };

  for (size_t i = 0; i < sizeof(msgs) / sizeof(msgs[0]); ++i)
    {
      if (fputs (msgs[i], stream) == EOF)
        break;
    }
}

void
s12z_print_statistics (FILE *file)
{
    (void)file;
}

int
md_parse_option(int c, const char *arg)
{
  switch (c)
    {
    case OPTION_REG_PREFIX:
      if (arg == NULL)
        return 0;
      register_prefix = xstrdup(arg);
      return 1;

    case OPTION_DOLLAR_HEX:
      literal_prefix_dollar_hex = true;
      return 1;

    default:
      return 0;
    }
}

symbolS *
md_undefined_symbol (char *name ATTRIBUTE_UNUSED)
{
  return NULL;
}

#include <stdbool.h>

const char *
md_atof(int type, char *literal, int *size)
{
    return ieee_md_atof(type, literal, size, true);
}

#include <limits.h>

valueT
md_section_align (asection *seg, valueT addr)
{
  if (seg == NULL)
    return addr;

  int align = bfd_section_alignment (seg);
  if (align <= 0)
    return addr;

  const int bits = (int)(sizeof (valueT) * CHAR_BIT);
  if (align >= bits)
    align = bits - 1;

  const valueT mask = (((valueT) 1) << (unsigned) align) - (valueT) 1;
  return (addr + mask) & ~mask;
}

void md_begin(void)
{
}

void s12z_init_after_args(void)
{
    if (!flag_traditional_format) {
        return;
    }
    literal_prefix_dollar_hex = true;
}

/* Builtin help.  */


static char *skip_whites(char *p)
{
    if (p == NULL) {
        return NULL;
    }

    while (*p != '\0' && is_whitespace((unsigned char)*p)) {
        p++;
    }

    return p;
}



/* Start a new insn that contains at least 'size' bytes.  Record the
   line information of that insn in the dwarf2 debug sections.  */
static char *
s12z_new_insn (int size)
{
  if (size < 0)
    return NULL;

  char *f = frag_more (size);
  if (f == NULL)
    return NULL;

  dwarf2_emit_insn (size);

  return f;
}



static bool lex_reg_name (uint16_t which, int *reg);

static bool
lex_constant(long *v)
{
  char *p;
  char *end;
  int dummy;

  if (v == NULL) {
    errno = EINVAL;
    return false;
  }

  p = input_line_pointer;
  if (p == NULL || *p == '\0') {
    errno = 0;
    return false;
  }

  if (lex_reg_name(~0, &dummy)) {
    input_line_pointer = p;
    return false;
  }

  input_line_pointer = p;

  errno = 0;
  end = NULL;
  *v = s12z_strtol(p, &end);
  if (errno == 0 && end != NULL && end != p) {
    input_line_pointer = end;
    return true;
  }

  return false;
}

static bool
lex_match (char x)
{
  if (input_line_pointer == NULL)
    return false;

  if (*input_line_pointer != x)
    return false;

  input_line_pointer++;
  return true;
}


static bool
lex_expression (expressionS *exp)
{
  char *saved_input_line_pointer = input_line_pointer;
  int reg_dummy;
  exp->X_op = O_absent;

  if (lex_match ('#') || lex_reg_name (~0, &reg_dummy))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_input_line_pointer;
      return false;
    }

  expression (exp);
  if (exp->X_op != O_absent)
    return true;

  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_input_line_pointer;
  return false;
}

/* Immediate operand.
   If EXP_O is non-null, then a symbolic expression is permitted,
   in which case, EXP_O will be populated with the parsed expression.
 */
static bool
lex_imm(long *v, expressionS *exp_o)
{
  char *start = input_line_pointer;
  expressionS exp;

  if (v == NULL || input_line_pointer == NULL)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = start;
      return false;
    }

  if (*input_line_pointer != '#')
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = start;
      return false;
    }

  input_line_pointer++;

  if (!lex_expression(&exp))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = start;
      return false;
    }

  if (exp.X_op != O_constant)
    {
      if (exp_o == NULL)
        as_bad(_("A non-constant expression is not permitted here"));
      else
        *exp_o = exp;
    }

  *v = exp.X_add_number;
  return true;
}

/* Short mmediate operand */
static bool
lex_imm_e4(long *val)
{
  char *saved_ilp = input_line_pointer;

  if (val == NULL)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }

  if (!lex_imm(val, NULL))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }

  long v = *val;
  if (v == -1 || (v > 0 && v <= 15))
    {
      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}

static bool
lex_match_string(const char *s)
{
  if (s == NULL || input_line_pointer == NULL)
    return false;

  char *p = input_line_pointer;
  while (*p != '\0' && !is_whitespace(*p) && !is_end_of_stmt(*p))
    p++;

  size_t len = (size_t)(p - input_line_pointer);
  size_t s_len = strlen(s);
  if (len != s_len)
    return false;

  if (strncasecmp(s, input_line_pointer, len) == 0)
    {
      input_line_pointer = p;
      return true;
    }

  return false;
}

/* Parse a register name.
   WHICH is a ORwise combination of the registers which are accepted.
   ~0 accepts all.
   On success, REG will be filled with the index of the register which
   was successfully scanned.
*/
static bool
lex_reg_name(uint16_t which, int *reg)
{
  if (reg == NULL)
    return false;

  char *p = input_line_pointer;
  if (p == NULL)
    return false;

  if (register_prefix)
    {
      size_t prefix_len = strlen(register_prefix);
      if (prefix_len != 0)
        {
          if (strncmp(register_prefix, p, prefix_len) == 0)
            p += prefix_len;
          else
            return false;
        }
    }

  char *start_of_reg_name = p;

  while ((*p >= 'a' && *p <= 'z')
         || (*p >= '0' && *p <= '9')
         || (*p >= 'A' && *p <= 'Z'))
    {
      p++;
    }

  size_t len = (size_t)(p - start_of_reg_name);

  if (len == 0)
    return false;

  for (int i = 0; i < S12Z_N_REGISTERS; ++i)
    {
      gas_assert(registers[i].name);
      const char *name = registers[i].name;
      size_t name_len = strlen(name);

      if (name_len == len && strncasecmp(name, start_of_reg_name, len) == 0)
        {
          unsigned bit_width = (unsigned)(sizeof(which) * 8u);
          if (i < (int)bit_width)
            {
              uint32_t mask = (uint32_t)1u << i;
              if ((mask & (uint32_t)which) != 0u)
                {
                  input_line_pointer = p;
                  *reg = i;
                  return true;
                }
            }
        }
    }

  return false;
}

static bool
lex_force_match(char x)
{
  if (input_line_pointer == NULL || *input_line_pointer != x)
    {
      as_bad(_("Expecting '%c'"), x);
      return false;
    }

  input_line_pointer++;
  return true;
}

static void write_be_bytes_from_long(uint8_t *buffer, int start_index, int byte_count, long value)
{
  for (int i = 0; i < byte_count; ++i)
    {
      int shift = 8 * (byte_count - i - 1);
      buffer[start_index + i] = (uint8_t)((value >> shift) & 0xFF);
    }
}

static void write_be_bytes_from_u32(uint8_t *buffer, int start_index, int byte_count, unsigned long value)
{
  for (int i = 0; i < byte_count; ++i)
    {
      int shift = 8 * (byte_count - i - 1);
      buffer[start_index + i] = (uint8_t)((value >> shift) & 0xFF);
    }
}

static bool
lex_opr (uint8_t *buffer, int *n_bytes, expressionS *exp, bool immediate_ok)
{
  char *ilp = input_line_pointer;
  int reg;
  long imm;

  exp->X_op = O_absent;
  *n_bytes = 0;
  buffer[0] = 0;

  if (lex_imm_e4 (&imm))
    {
      if (!immediate_ok)
        {
          as_bad (_("An immediate value in a source operand is inappropriate"));
          return false;
        }
      buffer[0] = (uint8_t)(0x70 | (imm > 0 ? (imm & 0xFF) : 0));
      *n_bytes = 1;
      return true;
    }
  else if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      buffer[0] = (uint8_t)(0xb8 | reg);
      *n_bytes = 1;
      return true;
    }
  else if (lex_match ('['))
    {
      if (lex_expression (exp))
        {
          long c = exp->X_add_number;
          if (lex_match (','))
            {
              if (lex_reg_name (REG_BIT_XYSP, &reg))
                {
                  if (c >= -256 && c <= 255)
                    {
                      *n_bytes = 2;
                      buffer[0] = (uint8_t)(0xc4 | ((reg - REG_X) << 4) | (c < 0 ? 0x01 : 0));
                      write_be_bytes_from_long(buffer, 1, 1, c);
                    }
                  else
                    {
                      *n_bytes = 4;
                      buffer[0] = (uint8_t)(0xc6 | ((reg - REG_X) << 4) | (c < 0 ? 0x01 : 0));
                      write_be_bytes_from_long(buffer, 1, 3, c);
                    }
                }
              else
                {
                  as_bad (_("Bad operand for constant offset"));
                  goto fail;
                }
            }
          else
            {
              *n_bytes = 4;
              buffer[0] = 0xfe;
              write_be_bytes_from_long(buffer, 1, 3, c);
            }
        }
      else if (lex_reg_name (REG_BIT_Dn, &reg))
        {
          if (!lex_force_match (','))
            goto fail;

          int reg2;
          if (lex_reg_name (REG_BIT_XY, &reg2))
            {
              *n_bytes = 1;
              buffer[0] = (uint8_t)(0xc8 | ((reg2 - REG_X) << 4) | reg);
            }
          else
            {
              as_bad (_("Invalid operand for register offset"));
              goto fail;
            }
        }
      else
        {
          goto fail;
        }

      if (!lex_force_match (']'))
        goto fail;
      return true;
    }
  else if (lex_match ('('))
    {
      long c;
      if (lex_constant (&c))
        {
          if (!lex_force_match (','))
            goto fail;

          int reg2;
          if (lex_reg_name (REG_BIT_XYSP, &reg2))
            {
              if (reg2 != REG_P && c >= 0 && c <= 15)
                {
                  *n_bytes = 1;
                  buffer[0] = (uint8_t)(0x40 | ((reg2 - REG_X) << 4) | (c & 0x0F));
                }
              else if (c >= -256 && c <= 255)
                {
                  *n_bytes = 2;
                  buffer[0] = (uint8_t)(0xc0 | ((reg2 - REG_X) << 4) | (c < 0 ? 0x01 : 0));
                  buffer[1] = (uint8_t)(c & 0xFF);
                }
              else
                {
                  *n_bytes = 4;
                  buffer[0] = (uint8_t)(0xc2 | ((reg2 - REG_X) << 4));
                  write_be_bytes_from_long(buffer, 1, 3, c);
                }
            }
          else if (lex_reg_name (REG_BIT_Dn, &reg2))
            {
              if (c >= -1 * (1L << 17) && c < ((1L << 17) - 1))
                {
                  *n_bytes = 3;
                  buffer[0] = (uint8_t)(0x80 | reg2 | (((c >> 16) & 0x03) << 4));
                  write_be_bytes_from_long(buffer, 1, 2, c);
                }
              else
                {
                  *n_bytes = 4;
                  buffer[0] = (uint8_t)(0xe8 | reg2);
                  write_be_bytes_from_long(buffer, 1, 3, c);
                }
            }
          else
            {
              as_bad (_("Bad operand for constant offset"));
              goto fail;
            }
        }
      else if (lex_reg_name (REG_BIT_Dn, &reg))
        {
          if (lex_match (','))
            {
              int reg2;
              if (lex_reg_name (REG_BIT_XYS, &reg2))
                {
                  *n_bytes = 1;
                  buffer[0] = (uint8_t)(0x88 | ((reg2 - REG_X) << 4) | reg);
                }
              else
                {
                  as_bad (_("Invalid operand for register offset"));
                  goto fail;
                }
            }
          else
            {
              goto fail;
            }
        }
      else if (lex_reg_name (REG_BIT_XYS, &reg))
        {
          if (lex_match ('-'))
            {
              if (reg == REG_S)
                {
                  as_bad (_("Invalid register for postdecrement operation"));
                  goto fail;
                }
              *n_bytes = 1;
              if (reg == REG_X)
                buffer[0] = 0xc7;
              else if (reg == REG_Y)
                buffer[0] = 0xd7;
            }
          else if (lex_match ('+'))
            {
              *n_bytes = 1;
              if (reg == REG_X)
                buffer[0] = 0xe7;
              else if (reg == REG_Y)
                buffer[0] = 0xf7;
              else if (reg == REG_S)
                buffer[0] = 0xff;
            }
          else
            {
              goto fail;
            }
        }
      else if (lex_match ('+'))
        {
          if (lex_reg_name (REG_BIT_XY, &reg))
            {
              *n_bytes = 1;
              if (reg == REG_X)
                buffer[0] = 0xe3;
              else if (reg == REG_Y)
                buffer[0] = 0xf3;
            }
          else
            {
              as_bad (_("Invalid register for preincrement operation"));
              goto fail;
            }
        }
      else if (lex_match ('-'))
        {
          if (lex_reg_name (REG_BIT_XYS, &reg))
            {
              *n_bytes = 1;
              if (reg == REG_X)
                buffer[0] = 0xc3;
              else if (reg == REG_Y)
                buffer[0] = 0xd3;
              else if (reg == REG_S)
                buffer[0] = 0xfb;
            }
          else
            {
              as_bad (_("Invalid register for predecrement operation"));
              goto fail;
            }
        }
      else
        {
          goto fail;
        }

      if (!lex_match (')'))
        goto fail;
      return true;
    }
  else if (lex_expression (exp))
    {
      buffer[0] = 0xfa;
      *n_bytes = 4;
      buffer[1] = 0;
      buffer[2] = 0;
      buffer[3] = 0;
      if (exp->X_op == O_constant)
        {
          valueT value = exp->X_add_number;

          if (value < (0x1U << 14))
            {
              *n_bytes = 2;
              buffer[0] = (uint8_t)((value >> 8) & 0xFF);
              buffer[1] = (uint8_t)(value & 0xFF);
            }
          else if (value < (0x1U << 19))
            {
              buffer[0] = 0xf8;
              if (value & (0x1U << 17))
                buffer[0] |= 0x04;
              if (value & (0x1U << 16))
                buffer[0] |= 0x01;
              *n_bytes = 3;
              write_be_bytes_from_u32(buffer, 1, 2, (unsigned long)value);
            }
          else
            {
              *n_bytes = 4;
              buffer[0] = 0xfa;
              write_be_bytes_from_u32(buffer, 1, 3, (unsigned long)value);
            }
        }
      return true;
    }

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
lex_offset(long *val)
{
  char *p = input_line_pointer;
  char *end;

  if (*p != '*')
    return false;
  p++;

  if (*p != '+' && *p != '-')
    return false;

  bool negative = (*p == '-');
  p++;

  errno = 0;
  long parsed = s12z_strtol(p, &end);
  if (errno != 0)
    return false;

  input_line_pointer = end;
  *val = negative ? -parsed : parsed;
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

static bool
no_operands(const struct instruction *insn)
{
  if (insn == NULL)
    {
      as_bad(_("Internal error: null instruction"));
      return false;
    }

  if (input_line_pointer == NULL || *input_line_pointer != '\0')
    {
      as_bad(_("Garbage at end of instruction"));
      return false;
    }

  char *buf = s12z_new_insn(insn->page);
  if (buf == NULL)
    {
      as_bad(_("Out of memory"));
      return false;
    }

  char *p = buf;

  if (insn->page == 2)
    {
      number_to_chars_bigendian(p, PAGE2_PREBYTE, 1);
      p++;
    }

  number_to_chars_bigendian(p, insn->opc, 1);

  return true;
}


static void
emit_reloc(expressionS *exp, char *f, int size, enum bfd_reloc_code_real reloc)
{
    if (exp == NULL) {
        return;
    }
    if (exp->X_op == O_absent || exp->X_op == O_constant) {
        return;
    }
    if (frag_now == NULL || f == NULL || frag_now->fr_literal == NULL) {
        return;
    }
    if (size <= 0) {
        return;
    }

    ptrdiff_t diff = f - frag_now->fr_literal;
    int where = (int) diff;
    if ((ptrdiff_t) where != diff) {
        return;
    }

    fixS *fix = fix_new_exp(frag_now, where, size, exp, false, reloc);
    if (fix == NULL) {
        return;
    }

    fix->fx_addnumber = 0x00;
}

/* Emit the code for an OPR address mode operand */
static char *
emit_opr(char *f, const uint8_t *buffer, int n_bytes, expressionS *exp)
{
  int i;
  char *out = f;
  const int reloc_size = 3;

  if (out == NULL || buffer == NULL || n_bytes <= 0)
    return out;

  number_to_chars_bigendian(out, buffer[0], 1);
  out++;

  emit_reloc(exp, out, reloc_size, BFD_RELOC_S12Z_OPR);

  for (i = 1; i < n_bytes; ++i)
    {
      number_to_chars_bigendian(out, buffer[i], 1);
      out++;
    }

  return out;
}

/* Emit the code for a 24 bit direct address operand */
static char *
emit_ext24 (char *buffer, long value)
{
  enum { EXT24_BYTES = 3 };

  if (buffer == NULL)
    return NULL;

  number_to_chars_bigendian (buffer, value, EXT24_BYTES);

  return buffer + EXT24_BYTES;
}

static bool
opr (const struct instruction *insn)
{
  if (insn == NULL)
    return false;

  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp;

  if (!lex_opr(buffer, &n_bytes, &exp, false))
    return false;

  const uint8_t ext24_prefix = 0xFA;
  const bool use_ext24 = (exp.X_op == O_constant && buffer[0] == ext24_prefix && insn->alt_opc != 0);

  char *f = s12z_new_insn(use_ext24 ? 4 : (n_bytes + 1));
  if (f == NULL)
    return false;

  number_to_chars_bigendian(f, use_ext24 ? insn->alt_opc : insn->opc, 1);
  f++;

  if (use_ext24)
    {
      gas_assert(insn->page == 1);
      emit_ext24(f, exp.X_add_number);
    }
  else
    {
      emit_opr(f, buffer, n_bytes, &exp);
    }

  return true;
}

/* Parse a 15 bit offset, as an expression.
   LONG_DISPLACEMENT will be set to true if the offset is wider than 7 bits.
   */
static bool
lex_15_bit_offset (bool *long_displacement, expressionS *exp)
{
  char *ilp = input_line_pointer;
  const long max15 = 0x3FFF;
  const long min15 = -0x4000;
  const long short_max = 63;
  const long short_min = -64;
  long val = 0;
  bool have_value = false;

  if (long_displacement == NULL || exp == NULL)
    {
      as_fatal (_("internal error: null pointer passed to lex_15_bit_offset"));
      return false;
    }

  if (lex_offset (&val))
    {
      exp->X_op = O_absent;
      exp->X_add_number = val;
      have_value = true;
    }
  else if (lex_expression (exp))
    {
      if (exp->X_op == O_constant)
        {
          val = exp->X_add_number;
          have_value = true;
        }
      else
        {
          *long_displacement = true;
          return true;
        }
    }
  else
    {
      exp->X_op = O_absent;
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  if (!have_value)
    {
    fail_line:
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  if (val > max15 || val < min15)
    {
      as_fatal (_("Offset is outside of 15 bit range"));
      return false;
    }

  *long_displacement = (val > short_max || val < short_min);
  return true;
}

static void
emit_15_bit_offset(char *f, int where, expressionS *exp)
{
  gas_assert(exp);
  if (!exp)
    return;

  if (exp->X_op != O_absent && exp->X_op != O_constant)
    {
      exp->X_add_number += where;

      long offset_in_frag = f - frag_now->fr_literal;
      fixS *fix = fix_new_exp(frag_now,
                              offset_in_frag,
                              2,
                              exp,
                              true,
                              BFD_RELOC_16_PCREL);
      if (fix)
        fix->fx_addnumber = where - 2;
      return;
    }

  long val = exp->X_add_number;
  const long min_short_disp = -64;
  const long max_short_disp = 63;
  bool long_displacement = (val > max_short_disp || val < min_short_disp);

  if (long_displacement)
    val |= 0x8000;
  else
    val &= 0x7F;

  int byte_count = long_displacement ? 2 : 1;
  number_to_chars_bigendian(f, val, byte_count);
}

static bool
rel(const struct instruction *insn)
{
  if (insn == NULL)
    return false;

  bool long_displacement = false;
  expressionS exp;
  if (!lex_15_bit_offset(&long_displacement, &exp))
    return false;

  int size = long_displacement ? 3 : 2;
  char *buf = s12z_new_insn(size);
  if (buf == NULL)
    return false;

  number_to_chars_bigendian(buf, insn->opc, 1);
  buf += 1;
  emit_15_bit_offset(buf, 3, &exp);
  return true;
}

static bool
reg_inh (const struct instruction *insn)
{
  int reg;
  char *f;

  if (!insn)
    return false;

  if (!lex_reg_name (REG_BIT_Dn, &reg))
    return false;

  f = s12z_new_insn (insn->page);
  if (!f)
    return false;

  if (insn->page == 2)
    {
      number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
      f += 1;
    }

  number_to_chars_bigendian (f, insn->opc + reg, 1);
  return true;
}


/* Special case for CLR X and CLR Y */
static bool
clr_xy (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  int reg = 0;
  const int len = 1;

  if (!lex_reg_name (REG_BIT_XY, &reg))
    return false;

  char *buf = s12z_new_insn (len);
  if (buf == NULL)
    return false;

  unsigned char opcode = (unsigned char)(0x9a + (reg - REG_X));
  number_to_chars_bigendian (buf, opcode, len);
  return true;
}

/* Some instructions have a suffix like ".l", ".b", ".w" etc
   which indicates the size of the operands. */
static int
size_from_suffix(const struct instruction *insn, int idx)
{
  if (insn == NULL || insn->name == NULL)
    return -3;

  const char *dot = strchr(insn->name, '.');
  if (dot == NULL)
    return -3;

  if (idx < 0)
    as_fatal(_("Bad size"));

  const char *suffix = dot + 1;
  size_t slen = strlen(suffix);
  if ((size_t)idx >= slen)
    as_fatal(_("Bad size"));

  switch (suffix[idx])
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
      as_fatal(_("Bad size"));
    }

  return -2;
}

static bool
mul_reg_reg_reg (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd, Dj, Dk;
  char *f;
  const char *name;
  const char *dot;
  char suffix = '\0';
  uint8_t mb;
  uint8_t opc_byte;

  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (REG_BIT_Dn, &Dj))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (REG_BIT_Dn, &Dk))
    goto fail;

  f = s12z_new_insn (insn->page + 1);
  if (f == NULL)
    {
      as_fatal (_("out of memory"));
      return false;
    }

  if (insn->page == 2)
    {
      number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
      f += 1;
    }

  opc_byte = (uint8_t) (insn->opc + Dd);
  number_to_chars_bigendian (f, opc_byte, 1);
  f += 1;

  name = insn->name;
  if (name != NULL)
    {
      dot = strchr (name, '.');
      if (dot != NULL && dot > name)
        suffix = dot[-1];
      else
        {
          size_t len = strlen (name);
          if (len > 0)
            suffix = name[len - 1];
        }
    }

  switch (suffix)
    {
    case 's':
      mb = 0x80;
      break;
    case 'u':
      mb = 0x00;
      break;
    default:
      as_fatal (_("BAD MUL"));
      return false;
    }

  mb |= (uint8_t) ((Dj & 0x07) << 3);
  mb |= (uint8_t) (Dk & 0x07);

  number_to_chars_bigendian (f, mb, 1);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool
mul_reg_reg_imm (const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  int Dd;
  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match (','))
    goto fail;

  int Dj;
  if (!lex_reg_name (REG_BIT_Dn, &Dj))
    goto fail;

  if (!lex_match (','))
    goto fail;

  long imm;
  if (!lex_imm (&imm, NULL))
    goto fail;

  int size = size_from_suffix (insn, 0);
  if (size <= 0)
    as_fatal (_("BAD MUL"));

  int len = insn->page + 1 + size;
  char *buf = s12z_new_insn (len);
  char *ptr = buf;

  if (insn->page == 2)
    {
      number_to_chars_bigendian (ptr, PAGE2_PREBYTE, 1);
      ptr += 1;
    }

  number_to_chars_bigendian (ptr, insn->opc + Dd, 1);
  ptr += 1;

  uint8_t mb = 0x44;
  const char *name = insn->name;
  const char *dot = strchrnul (name, '.');
  if (dot == name)
    as_fatal (_("BAD MUL"));

  switch (dot[-1])
    {
    case 's':
      mb |= 0x80;
      break;
    case 'u':
      break;
    default:
      as_fatal (_("BAD MUL"));
      break;
    }

  mb |= (uint8_t)((Dj & 0x7) << 3);
  mb |= (uint8_t)(size - 1);

  number_to_chars_bigendian (ptr, mb, 1);
  ptr += 1;

  number_to_chars_bigendian (ptr, imm, size);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}


static bool
mul_reg_reg_opr(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  int Dd;
  if (!lex_reg_name(REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match(','))
    goto fail;

  int Dj;
  if (!lex_reg_name(REG_BIT_Dn, &Dj))
    goto fail;

  if (!lex_match(','))
    goto fail;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  if (!lex_opr(buffer, &n_bytes, &exp, true))
    goto fail;

  int size = size_from_suffix(insn, 0);

  char *f = s12z_new_insn(insn->page + 1 + n_bytes);
  if (insn->page == 2)
    {
      number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
      f++;
    }

  number_to_chars_bigendian(f, insn->opc + Dd, 1);
  f++;

  uint8_t mb = 0x40;
  const char *name = insn->name;
  const char *dot = strchrnul(name, '.');
  char prev = (dot > name) ? dot[-1] : '\0';

  if (prev == 's')
    {
      mb |= 0x80;
    }
  else if (prev == 'u')
    {
      /* unsigned, no flag change */
    }
  else
    {
      as_fatal(_("BAD MUL"));
    }

  mb |= (uint8_t)(Dj << 3);
  mb |= (uint8_t)(size - 1);

  number_to_chars_bigendian(f, mb, 1);
  f++;

  emit_opr(f, buffer, n_bytes, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}

static bool
mul_reg_opr_opr (const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  int Dd;
  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match (','))
    goto fail;

  uint8_t buffer1[4];
  int n_bytes1;
  expressionS exp1;
  if (!lex_opr (buffer1, &n_bytes1, &exp1, false))
    goto fail;

  if (!lex_match (','))
    goto fail;

  uint8_t buffer2[4];
  int n_bytes2;
  expressionS exp2;
  if (!lex_opr (buffer2, &n_bytes2, &exp2, false))
    goto fail;

  int size1 = size_from_suffix (insn, 0);
  int size2 = size_from_suffix (insn, 1);

  char *f = s12z_new_insn (insn->page + 1 + n_bytes1 + n_bytes2);
  if (insn->page == 2)
    {
      number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
      f += 1;
    }

  number_to_chars_bigendian (f, insn->opc + Dd, 1);
  f += 1;

  uint8_t mb = 0x42;
  const char *dot = strchrnul (insn->name, '.');
  if (dot <= insn->name)
    as_fatal (_("BAD MUL"));
  switch (dot[-1])
    {
    case 's':
      mb |= 0x80;
      break;
    case 'u':
      break;
    default:
      as_fatal (_("BAD MUL"));
      break;
    }

  mb |= (uint8_t)((size1 - 1) << 4);
  mb |= (uint8_t)((size2 - 1) << 2);
  number_to_chars_bigendian (f, mb, 1);
  f += 1;

  f = emit_opr (f, buffer1, n_bytes1, &exp1);
  f = emit_opr (f, buffer2, n_bytes2, &exp2);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
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
  if (reg_bits == NULL)
    return false;

  while (lex_match (','))
    {
      int reg;
      if (!lex_reg_name (grp, &reg))
        return false;
      if (reg < 0 || reg >= 16)
        return false;
      *reg_bits |= (uint16_t)(1u << (unsigned)reg);
    }

  return true;
}

static bool
psh_pull(const struct instruction *insn)
{
  const uint8_t pull_flag = 0x80u;
  const uint8_t grp1_flag = 0x40u;
  uint8_t pb = (strcmp("pul", insn->name) == 0) ? pull_flag : 0x00u;

  if (lex_match_string("all16b"))
    {
      pb |= grp1_flag;
    }
  else if (lex_match_string("all"))
    {
    }
  else
    {
      int reg1;
      if (!lex_reg_name(REG_BIT_GRP1 | REG_BIT_GRP0, &reg1))
        {
          fail_line_pointer = input_line_pointer;
          return false;
        }

      uint16_t admitted_group = 0u;
      uint16_t reg_bits = (uint16_t)(1u << reg1);

      if ((reg_bits & REG_BIT_GRP1) != 0u)
        {
          admitted_group = REG_BIT_GRP1;
        }
      else if ((reg_bits & REG_BIT_GRP0) != 0u)
        {
          admitted_group = REG_BIT_GRP0;
        }

      if (!lex_reg_list(admitted_group, &reg_bits))
        {
          fail_line_pointer = input_line_pointer;
          return false;
        }

      if ((reg_bits & REG_BIT_GRP1) != 0u)
        {
          pb |= grp1_flag;
        }

      for (int i = 0; i < 16; ++i)
        {
          if ((reg_bits & (uint16_t)(1u << i)) != 0u)
            {
              pb |= reg_map[i];
            }
        }
    }

  char *f = s12z_new_insn(2);
  if (f == NULL)
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }
  number_to_chars_bigendian(f, insn->opc, 1);
  number_to_chars_bigendian(f + 1, pb, 1);
  return true;
}


static bool
tfr(const struct instruction *insn)
{
  if (insn == NULL || insn->name == NULL)
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  int reg1;
  if (!lex_reg_name(~0, &reg1))
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  if (!lex_match(','))
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  int reg2;
  if (!lex_reg_name(~0, &reg2))
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  bool is_ext = (strcasecmp("sex", insn->name) == 0) || (strcasecmp("zex", insn->name) == 0);
  if (is_ext)
  {
    if (registers[reg2].bytes <= registers[reg1].bytes)
      as_warn(_("Source register for %s is no larger than the destination register"), insn->name);
    else if (reg1 == reg2)
      as_warn(_("The destination and source registers are identical"));
  }
  else if (reg1 == reg2)
  {
    as_warn(_("The destination and source registers are identical"));
  }

  char *f = s12z_new_insn(1 + insn->page);
  if (f == NULL)
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  if (insn->page == 2)
  {
    number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
    f += 1;
  }

  number_to_chars_bigendian(f, insn->opc, 1);
  f += 1;

  number_to_chars_bigendian(f, (reg1 << 4) | reg2, 1);

  return true;
}

static bool
imm8 (const struct instruction *insn)
{
  const long min_imm = -128;
  const long max_imm = 127;

  if (insn == NULL)
    {
      as_bad (_("Invalid instruction"));
      return false;
    }

  long imm;
  if (!lex_imm (&imm, NULL))
    return false;

  if (imm > max_imm || imm < min_imm)
    {
      as_bad (_("Immediate value %ld is out of range for instruction %s"),
              imm, insn->name);
    }

  char *buf = s12z_new_insn (2);
  if (buf == NULL)
    {
      as_bad (_("Failed to allocate instruction buffer"));
      return false;
    }

  unsigned long opc_byte = ((unsigned long) insn->opc) & 0xFFUL;
  unsigned long imm_byte = ((unsigned long) imm) & 0xFFUL;

  number_to_chars_bigendian (buf, opc_byte, 1);
  buf++;
  number_to_chars_bigendian (buf, imm_byte, 1);

  return true;
}

static bool
reg_imm (const struct instruction *insn, int allowed_reg)
{
  char *saved_ilp = input_line_pointer;
  int reg;
  long imm;
  int size;
  int total_len;
  char *f;

  if (!lex_reg_name(allowed_reg, &reg))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }

  if (!lex_force_match(','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }

  if (!lex_imm(&imm, NULL))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }

  size = registers[reg].bytes;
  if (size < 0)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }

  total_len = insn->page + size;
  f = s12z_new_insn(total_len);
  if (f == NULL)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }

  if (insn->page == 2)
    {
      number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
      f += 1;
    }

  number_to_chars_bigendian(f, insn->opc + reg, 1);
  f += 1;

  number_to_chars_bigendian(f, imm, size);
  return true;
}


static inline bool regd_imm(const struct instruction *insn)
{
    return reg_imm(insn, REG_BIT_Dn);
}

static bool regdxy_imm(const struct instruction *insn)
{
    const int mask = REG_BIT_Dn | REG_BIT_XY;
    return reg_imm(insn, mask);
}


#include <limits.h>

static inline unsigned int bitmask_single(unsigned int pos)
{
    const unsigned int bit_count = (unsigned int)(sizeof(unsigned int) * CHAR_BIT);
    if (pos >= bit_count) {
        return 0u;
    }
    return 1u << pos;
}

static bool
regs_imm(const struct instruction *insn)
{
    return reg_imm(insn, bitmask_single(REG_S));
}

static bool
trap_imm (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  long imm = -1;
  char *f;

  (void)insn;

  if (!lex_imm(&imm, NULL))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  if (imm < 0x92 || imm > 0xFF ||
      (imm >= 0xA0 && imm <= 0xA7) ||
      (imm >= 0xB0 && imm <= 0xB7))
    {
      as_bad(_("trap value %ld is not valid"), imm);
      return false;
    }

  f = s12z_new_insn(2);
  if (f == NULL)
    {
      as_bad(_("internal error: failed to allocate instruction buffer"));
      return false;
    }

  number_to_chars_bigendian(f, (unsigned long)PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f + 1, (unsigned long)(imm & 0xFF), 1);
  return true;
}



/* Special one byte instruction CMP X, Y */
static bool
regx_regy (const struct instruction *insn)
{
  int reg;

  if (insn == NULL)
    return false;

  if (!lex_reg_name (1u << REG_X, &reg))
    return false;

  if (!lex_force_match (','))
    return false;

  if (!lex_reg_name (1u << REG_Y, &reg))
    return false;

  char *f = s12z_new_insn (1);
  if (f == NULL)
    return false;

  number_to_chars_bigendian (f, insn->opc, 1);
  return true;
}

/* Special one byte instruction SUB D6, X, Y */
static bool
regd6_regx_regy(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;
  int reg;
  unsigned int masks[3] = {
    (0x1U << REG_D6),
    (0x1U << REG_X),
    (0x1U << REG_Y)
  };

  if (insn == NULL) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  for (int i = 0; i < 3; ++i) {
    if (!lex_reg_name(masks[i], &reg) || (i < 2 && !lex_match(','))) {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_ilp;
      return false;
    }
  }

  char *f = s12z_new_insn(1);
  if (f == NULL) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  number_to_chars_bigendian(f, insn->opc, 1);
  return true;
}

/* Special one byte instruction SUB D6, Y, X */
static bool
regd6_regy_regx(const struct instruction *insn)
{
  if (insn == NULL)
  {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  char *saved_input = input_line_pointer;
  int reg;

  if (lex_reg_name(0x1U << REG_D6, &reg) &&
      lex_match(',') &&
      lex_reg_name(0x1U << REG_Y, &reg) &&
      lex_match(',') &&
      lex_reg_name(0x1U << REG_X, &reg))
  {
    char *buf = s12z_new_insn(1);
    if (buf == NULL)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_input;
      return false;
    }

    number_to_chars_bigendian(buf, insn->opc, 1);
    (void)reg;
    return true;
  }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_input;
  return false;
}

static bool
reg_opr(const struct instruction *insn, int allowed_regs, bool immediate_ok)
{
  char *saved_ilp = input_line_pointer;
  int reg;

  if (!lex_reg_name(allowed_regs, &reg)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  if (!lex_force_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_opr(buffer, &n_bytes, &exp, immediate_ok)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  if (exp.X_op == O_constant && buffer[0] == 0xFA && insn->alt_opc != 0) {
    char *f = s12z_new_insn(4);
    gas_assert(insn->page == 1);
    number_to_chars_bigendian(f++, insn->alt_opc + reg, 1);
    emit_ext24(f, exp.X_add_number);
    return true;
  }

  {
    char *f = s12z_new_insn(n_bytes + insn->page);
    if (insn->page == 2)
      number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, insn->opc + reg, 1);
    emit_opr(f, buffer, n_bytes, &exp);
  }

  return true;
}


static bool
regdxy_opr_dest (const struct instruction *insn)
{
  if (insn == NULL)
    return false;

  return reg_opr (insn, (REG_BIT_Dn | REG_BIT_XY), false);
}

#include <assert.h>
static bool regdxy_opr_src(const struct instruction *insn)
{
    assert(insn != NULL);
    return reg_opr(insn, REG_BIT_Dn | REG_BIT_XY, true);
}


static bool
regd_opr (const struct instruction *insn)
{
  if (insn == NULL)
    return false;

  return reg_opr (insn, REG_BIT_Dn, true);
}


/* OP0: S; OP1: destination OPR */
static bool regs_opr_dest(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    const unsigned int mask = (1u << REG_S);
    return reg_opr(insn, mask, false);
}

/* OP0: S; OP1: source OPR */
static bool regs_opr_src(const struct instruction *insn)
{
    if (insn == NULL)
        return false;

    const unsigned mask = 1u << REG_S;
    return reg_opr(insn, mask, true);
}

static bool
imm_opr(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;
  long imm = 0;
  expressionS exp0;
  exp0.X_op = O_absent;

  if (!lex_imm(&imm, size_from_suffix(insn, 0) > 1 ? &exp0 : NULL))
    goto fail;

  if (!lex_match(','))
    goto fail;

  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp1;
  if (!lex_opr(buffer, &n_bytes, &exp1, false))
    goto fail;

  if (n_bytes < 0 || n_bytes > (int)sizeof(buffer))
    goto fail;

  int size = size_from_suffix(insn, 0);
  char *f = s12z_new_insn(1 + n_bytes + size);
  if (f == NULL)
    goto fail;

  number_to_chars_bigendian(f, insn->opc, 1);
  f += 1;

  emit_reloc(&exp0, f, size, size == 4 ? BFD_RELOC_32 : BFD_RELOC_S12Z_OPR);

  unsigned long uimm = (unsigned long) imm;
  for (int i = 0; i < size; ++i)
  {
    int shift = CHAR_BIT * (size - i - 1);
    number_to_chars_bigendian(f + i, (uimm >> shift) & 0xFFUL, 1);
  }
  f += size;

  emit_opr(f, buffer, n_bytes, &exp1);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}

static bool
opr_opr(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  uint8_t buffer1[4];
  int n_bytes1 = 0;
  expressionS exp1;
  uint8_t buffer2[4];
  int n_bytes2 = 0;
  expressionS exp2;
  bool success = false;

  if (!lex_opr(buffer1, &n_bytes1, &exp1, false))
    goto cleanup;
  if (n_bytes1 < 0 || n_bytes1 > (int)sizeof(buffer1))
    goto cleanup;

  if (!lex_match(','))
    goto cleanup;

  if (!lex_opr(buffer2, &n_bytes2, &exp2, false))
    goto cleanup;
  if (n_bytes2 < 0 || n_bytes2 > (int)sizeof(buffer2))
    goto cleanup;

  {
    int total = 1 + n_bytes1 + n_bytes2;
    if (total <= 0)
      goto cleanup;

    char *f = s12z_new_insn(total);
    if (f == NULL)
      goto cleanup;

    number_to_chars_bigendian(f, insn->opc, 1);
    f += 1;

    f = emit_opr(f, buffer1, n_bytes1, &exp1);
    f = emit_opr(f, buffer2, n_bytes2, &exp2);
  }

  success = true;

cleanup:
  if (!success)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
    }
  return success;
}

static bool
reg67sxy_opr(const struct instruction *insn)
{
  if (insn == NULL)
    return false;

  int reg;
  if (!lex_reg_name(REG_BIT_XYS | (0x1U << REG_D6) | (0x1U << REG_D7), &reg))
    return false;

  if (!lex_match(','))
    return false;

  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp;
  if (!lex_opr(buffer, &n_bytes, &exp, false))
    return false;

  if (n_bytes < 0 || n_bytes > (int)sizeof(buffer))
    return false;

  int total_size = 1 + n_bytes;
  char *out_ptr = s12z_new_insn(total_size);
  if (out_ptr == NULL)
    return false;

  int opcode = insn->opc + reg - REG_D6;
  number_to_chars_bigendian(out_ptr, opcode, 1);
  out_ptr += 1;
  emit_opr(out_ptr, buffer, n_bytes, &exp);

  return true;
}

static bool rotate(const struct instruction *insn, short dir)
{
  if (insn == NULL)
    return false;

  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp;

  if (!lex_opr(buffer, &n_bytes, &exp, false))
    return false;

  if (n_bytes < 0 || n_bytes > (INT_MAX - 2))
    return false;

  int total_len = n_bytes + 2;
  char *f = s12z_new_insn(total_len);
  if (f == NULL)
    return false;

  number_to_chars_bigendian(f++, insn->opc, 1);

  int size = size_from_suffix(insn, 0);
  if (size < 0)
    size = 1;

  uint8_t sb = 0x24u;
  sb |= (uint8_t)(size - 1);
  if (dir != 0)
    sb |= 0x40u;
  number_to_chars_bigendian(f++, sb, 1);

  emit_opr(f, buffer, n_bytes, &exp);

  return true;
}

static bool rol(const struct instruction *insn)
{
    return rotate(insn, 1);
}

static bool ror(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return rotate(insn, 0);
}


/* Shift instruction with a register operand and an immediate #1 or #2
   left = 1; right = 0;
   logical = 0; arithmetic = 1;
*/
static bool
lex_shift_reg_imm1(const struct instruction *insn, short type, short dir)
{
  const char *const_ilp = input_line_pointer;
  char *ilp = input_line_pointer;
  char *failp = NULL;
  bool ok = true;

  do
    {
      int reg_index;
      long imm = -1;

      if (!lex_reg_name(REG_BIT_Dn, &reg_index))
        {
          failp = input_line_pointer;
          ok = false;
          break;
        }

      if (!lex_match(','))
        {
          failp = input_line_pointer;
          ok = false;
          break;
        }

      if (!lex_imm(&imm, NULL))
        {
          failp = input_line_pointer;
          ok = false;
          break;
        }

      if (imm != 1 && imm != 2)
        {
          failp = input_line_pointer;
          ok = false;
          break;
        }

      input_line_pointer = ilp;

      uint8_t buffer[4];
      int n_bytes;
      expressionS exp;

      if (!lex_opr(buffer, &n_bytes, &exp, false))
        {
          failp = input_line_pointer;
          ok = false;
          break;
        }

      gas_assert(n_bytes == 1);
      if (n_bytes != 1)
        {
          failp = input_line_pointer;
          ok = false;
          break;
        }

      const uint8_t base = 0x34;
      uint8_t sb = base;
      sb |= (uint8_t)((dir & 0x01) << 6);
      sb |= (uint8_t)((type & 0x01) << 7);
      if (imm == 2)
        sb |= 0x08;

      char *f = s12z_new_insn(3);
      if (f == NULL)
        {
          failp = (char *)const_ilp;
          ok = false;
          break;
        }

      number_to_chars_bigendian(f++, insn->opc, 1);
      number_to_chars_bigendian(f++, sb, 1);
      emit_opr(f, buffer, n_bytes, &exp);
    }
  while (0);

  if (!ok)
    {
      fail_line_pointer = failp ? failp : input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  return true;
}

/* Shift instruction with a register operand.
   left = 1; right = 0;
   logical = 0; arithmetic = 1; */
static bool
lex_shift_reg (const struct instruction *insn, short type, short dir)
{
  int Dd, Ds, Dn;
  long imm;
  const uint8_t SB_INIT = 0x10;
  const uint8_t REG_EXT_BASE = 0xb8;
  const uint8_t IMM_EXT_BASE = 0x70;

  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (REG_BIT_Dn, &Ds))
    goto fail;

  if (!lex_match (','))
    goto fail;

  uint8_t sb = SB_INIT;
  sb |= (uint8_t) Ds;
  sb |= (uint8_t) ((dir & 0x01) << 6);
  sb |= (uint8_t) ((type & 0x01) << 7);

  if (lex_reg_name (REG_BIT_Dn, &Dn))
    {
      char *f = s12z_new_insn (3);
      if (!f)
        goto fail;
      number_to_chars_bigendian (f++, (uint8_t) (insn->opc | Dd), 1);
      number_to_chars_bigendian (f++, sb, 1);
      number_to_chars_bigendian (f++, (uint8_t) (REG_EXT_BASE | Dn), 1);
      return true;
    }

  if (lex_imm (&imm, NULL))
    {
      if (imm < 0 || imm > 31)
        {
          as_bad (_("Shift value should be in the range [0,31]"));
          goto fail;
        }

      int n_bytes = 3;
      uint8_t sb_local = sb;

      if (imm == 1 || imm == 2)
        {
          n_bytes = 2;
          sb_local = (uint8_t) (sb_local & (uint8_t) ~SB_INIT);
        }
      else
        {
          sb_local |= (uint8_t) (((unsigned long) imm & 0x01UL) << 3);
        }

      char *f = s12z_new_insn (n_bytes);
      if (!f)
        goto fail;

      number_to_chars_bigendian (f++, (uint8_t) (insn->opc | Dd), 1);
      number_to_chars_bigendian (f++, sb_local, 1);

      if (n_bytes > 2)
        {
          number_to_chars_bigendian (f++, (uint8_t) (IMM_EXT_BASE | ((unsigned long) imm >> 1)), 1);
        }

      return true;
    }

fail:
  fail_line_pointer = input_line_pointer;
  return false;
}

static void
impute_shift_dir_and_type(const struct instruction *insn, short *type, short *dir)
{
  if (!insn || !insn->name || !type || !dir)
    {
      as_fatal (_("Bad shift mode"));
      return;
    }

  *dir = -1;
  *type = -1;

  switch (insn->name[0])
    {
    case 'l':
      *type = 0;
      break;
    case 'a':
      *type = 1;
      break;
    default:
      as_fatal (_("Bad shift mode"));
      return;
    }

  const char *name = insn->name;
  if (name[0] == '\0' || name[1] == '\0' || name[2] == '\0')
    {
      as_fatal (_("Bad shift *direction"));
      return;
    }

  switch (name[2])
    {
    case 'l':
      *dir = 1;
      break;
    case 'r':
      *dir = 0;
      break;
    default:
      as_fatal (_("Bad shift *direction"));
      break;
    }
}

/* Shift instruction with a OPR operand */
static bool
shift_two_operand(const struct instruction *insn)
{
  uint8_t sb = 0x34;
  char *saved_ilp = input_line_pointer;

  short dir = -1;
  short type = -1;
  impute_shift_dir_and_type(insn, &type, &dir);
  sb |= (uint8_t)((unsigned)dir << 6);
  sb |= (uint8_t)((unsigned)type << 7);

  int size = size_from_suffix(insn, 0);
  sb |= (uint8_t)(size - 1);

  uint8_t buffer[4];
  int opr_bytes = 0;
  expressionS exp;
  long imm = -1;

  bool ok = false;
  do {
    if (!lex_opr(buffer, &opr_bytes, &exp, false))
      break;

    if (!lex_match(','))
      break;

    if (!lex_imm(&imm, NULL))
      break;

    if (imm != 1 && imm != 2)
      break;

    if (imm == 2)
      sb |= 0x08;

    char *f = s12z_new_insn(2 + opr_bytes);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, sb, 1);
    emit_opr(f, buffer, opr_bytes, &exp);

    ok = true;
  } while (0);

  if (!ok) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  return true;
}

/* Shift instruction with a OPR operand */
static bool
shift_opr_imm(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  short dir = 0;
  short type = 0;
  impute_shift_dir_and_type(insn, &type, &dir);

  int Dd = 0;
  if (!lex_reg_name(REG_BIT_Dn, &Dd))
    goto parse_fail;

  if (!lex_match(','))
    goto parse_fail;

  int total_bytes = 2;

  uint8_t opr1_buf[4];
  int opr1_len = 0;
  expressionS opr1_exp;
  if (!lex_opr(opr1_buf, &opr1_len, &opr1_exp, false))
    goto parse_fail;

  total_bytes += opr1_len;

  if (!lex_match(','))
    goto parse_fail;

  uint8_t opr2_buf[4];
  int opr2_len = 0;
  expressionS opr2_exp;

  long imm = 0;
  bool has_immediate = lex_imm(&imm, NULL);

  if (!has_immediate)
    {
      if (!lex_opr(opr2_buf, &opr2_len, &opr2_exp, false))
        goto parse_fail;
    }

  uint8_t sb = 0x20;

  int sz = size_from_suffix(insn, 0);
  if (sz != -1)
    sb |= (uint8_t)(sz - 1);

  sb |= (uint8_t)((dir & 0x03) << 6);
  sb |= (uint8_t)((type & 0x01) << 7);

  if (has_immediate)
    {
      if (imm == 1 || imm == 2)
        {
          if (imm == 2)
            sb |= 0x08;
        }
      else
        {
          total_bytes++;
          sb |= 0x10;
          if ((imm & 1L) != 0)
            sb |= 0x08;
        }
    }
  else
    {
      total_bytes += opr2_len;
      sb |= 0x10;
    }

  char *out = s12z_new_insn(total_bytes);
  if (out == NULL)
    return false;

  number_to_chars_bigendian(out++, insn->opc | Dd, 1);
  number_to_chars_bigendian(out++, sb, 1);
  out = emit_opr(out, opr1_buf, opr1_len, &opr1_exp);

  if (has_immediate)
    {
      if (imm != 1 && imm != 2)
        {
          uint8_t enc = (uint8_t)(0x70 | ((unsigned long)imm >> 1));
          number_to_chars_bigendian(out++, enc, 1);
        }
    }
  else
    {
      out = emit_opr(out, opr2_buf, opr2_len, &opr2_exp);
    }

  return true;

parse_fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}

/* Shift instruction with a register operand */
static bool shift_reg(const struct instruction *insn)
{
    if (insn == NULL)
        return false;

    short dir = -1;
    short type = -1;

    impute_shift_dir_and_type(insn, &type, &dir);
    return lex_shift_reg_imm1(insn, type, dir) || lex_shift_reg(insn, type, dir);
}

static bool bm_regd_imm(const struct instruction *insn)
{
  if (insn == NULL)
    return false;

  char *saved_lp = input_line_pointer;
  int Di = 0;

  if (!lex_reg_name(REG_BIT_Dn, &Di)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_lp;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_lp;
    return false;
  }

  long imm = 0;
  if (!lex_imm(&imm, NULL)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_lp;
    return false;
  }

  uint8_t bm = (uint8_t)(((uint32_t)imm << 3) | (uint32_t)Di);

  char *buf = s12z_new_insn(2);
  if (buf == NULL) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_lp;
    return false;
  }

  number_to_chars_bigendian(buf, insn->opc, 1);
  number_to_chars_bigendian(buf + 1, bm, 1);

  return true;
}

static bool
bm_opr_reg(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  uint8_t buffer[4];
  int n_opr_bytes = 0;
  expressionS exp;

  if (!lex_opr(buffer, &n_opr_bytes, &exp, false))
    goto fail;

  if (n_opr_bytes < 0 || n_opr_bytes > (int)sizeof(buffer))
    goto fail;

  if (!lex_match(','))
    goto fail;

  int Dn = 0;
  if (!lex_reg_name(REG_BIT_Dn, &Dn))
    goto fail;

  int size = size_from_suffix(insn, 0);
  if (size < 1)
    goto fail;

  uint8_t bm = (uint8_t)((Dn << 4) | (((size - 1) << 2) & 0x0C) | 0x81);

  char *f = s12z_new_insn(2 + n_opr_bytes);
  if (f == NULL)
    goto fail;

  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
  emit_opr(f, buffer, n_opr_bytes, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}


static bool
bm_opr_imm(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  uint8_t buffer[4];
  int n_opr_bytes = 0;

  expressionS exp = (expressionS){0};
  if (!lex_opr(buffer, &n_opr_bytes, &exp, false))
    goto fail;

  if (!lex_match(','))
    goto fail;

  long imm = 0;
  if (!lex_imm(&imm, NULL))
    goto fail;

  int size = size_from_suffix(insn, 0);
  if (imm < 0 || imm >= (long)(size * 8))
    {
      as_bad(_("Immediate operand %ld is inappropriate for size of instruction"), imm);
      goto fail;
    }

  uint8_t bm = 0x80;
  switch (size)
    {
    case 2:
      bm |= 0x02;
      break;
    case 4:
      bm |= 0x08;
      break;
    default:
      break;
    }
  bm |= (uint8_t)(((unsigned long)imm & 0x07UL) << 4);
  bm |= (uint8_t)((unsigned long)imm >> 3);

  char *f = s12z_new_insn(2 + n_opr_bytes);
  if (!f)
    goto fail;

  number_to_chars_bigendian(f, insn->opc, 1);
  number_to_chars_bigendian(f + 1, bm, 1);
  emit_opr(f + 2, buffer, n_opr_bytes, &exp);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}


static bool
bm_regd_reg(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  if (!insn) {
    fail_line_pointer = saved_ilp;
    input_line_pointer = saved_ilp;
    return false;
  }

  int di = 0;
  if (!lex_reg_name(REG_BIT_Dn, &di)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  int dn = 0;
  if (!lex_reg_name(REG_BIT_Dn, &dn)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
    return false;
  }

  uint8_t bm = (uint8_t)(((unsigned)dn & 0x0F) << 4);
  bm |= (uint8_t)0x81;

  uint8_t xb = (uint8_t)(((unsigned)di & 0x0F) | 0xB8);

  char *f = s12z_new_insn(3);
  if (f == NULL) {
    fail_line_pointer = saved_ilp;
    input_line_pointer = saved_ilp;
    return false;
  }

  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
  number_to_chars_bigendian(f++, xb, 1);

  return true;
}





static bool
bf_reg_opr_imm(const struct instruction *insn, short ie)
{
  char *saved_input = input_line_pointer;
  bool success = false;

  do {
    int Dd = 0;
    if (!lex_reg_name(REG_BIT_Dn, &Dd))
      break;

    if (!lex_match(','))
      break;

    uint8_t buffer[4];
    int n_bytes = 0;
    expressionS exp;
    if (!lex_opr(buffer, &n_bytes, &exp, false))
      break;

    if (!lex_match(','))
      break;

    long width = 0;
    if (!lex_imm(&width, NULL))
      break;

    if (width < 0 || width > 31) {
      as_bad(_("Invalid width value for %s"), insn->name);
      break;
    }

    if (!lex_match(':'))
      break;

    long offset = 0;
    if (!lex_constant(&offset))
      break;

    if (offset < 0 || offset > 31) {
      as_bad(_("Invalid offset value for %s"), insn->name);
      break;
    }

    uint8_t i1 = (uint8_t)((width << 5) | offset);

    int size = size_from_suffix(insn, 0);
    uint8_t bb = ie ? 0x80 : 0x00;
    bb |= 0x60;
    bb |= (uint8_t)((size - 1) << 2);
    bb |= (uint8_t)(width >> 3);

    char *f = s12z_new_insn(4 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, (uint8_t)(0x08 | Dd), 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);

    emit_opr(f, buffer, n_bytes, &exp);

    success = true;
  } while (0);

  if (!success) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input;
  }

  return success;
}


static bool
bf_opr_reg_imm(const struct instruction *insn, short ie)
{
  char *ilp = input_line_pointer;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_opr(buffer, &n_bytes, &exp, false)) { fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }
  if (!lex_match(',')) { fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }

  int Ds = 0;
  if (!lex_reg_name(REG_BIT_Dn, &Ds)) { fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }
  if (!lex_match(',')) { fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }

  long width;
  if (!lex_imm(&width, NULL)) { fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }
  if (width < 0 || width > 31) { as_bad(_("Invalid width value for %s"), insn->name); fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }

  if (!lex_match(':')) { fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }

  long offset;
  if (!lex_constant(&offset)) { fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }
  if (offset < 0 || offset > 31) { as_bad(_("Invalid offset value for %s"), insn->name); fail_line_pointer = input_line_pointer; input_line_pointer = ilp; return false; }

  uint8_t i1 = (uint8_t)(((unsigned long)width << 5) | (unsigned long)offset);

  int size = size_from_suffix(insn, 0);
  uint8_t bb = (uint8_t)((ie ? 0x80 : 0x00) | 0x70 | ((size - 1) << 2) | ((unsigned long)width >> 3));

  char *f = s12z_new_insn(4 + n_bytes);
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, (uint8_t)(0x08 | Ds), 1);
  number_to_chars_bigendian(f++, bb, 1);
  number_to_chars_bigendian(f++, i1, 1);

  emit_opr(f, buffer, n_bytes, &exp);
  return true;
}



static bool
bf_reg_reg_imm(const struct instruction *insn, short ie)
{
  char *const saved_lp = input_line_pointer;
  int Dd = 0;
  int Ds = 0;
  long width = 0;
  long offset = 0;

  if (!lex_reg_name(REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match(','))
    goto fail;

  if (!lex_reg_name(REG_BIT_Dn, &Ds))
    goto fail;

  if (!lex_match(','))
    goto fail;

  if (!lex_imm(&width, NULL))
    goto fail;

  if (width < 0 || width > 31)
    {
      as_bad(_("Invalid width value for %s"), insn->name);
      goto fail;
    }

  if (!lex_match(':'))
    goto fail;

  if (!lex_constant(&offset))
    goto fail;

  if (offset < 0 || offset > 31)
    {
      as_bad(_("Invalid offset value for %s"), insn->name);
      goto fail;
    }

  uint8_t bb = (ie ? 0x80u : 0x00u)
             | 0x20u
             | (uint8_t)(((unsigned)Ds & 0x07u) << 2)
             | (uint8_t)(((unsigned)width >> 3) & 0x03u);

  uint8_t i1 = (uint8_t)(((unsigned)width & 0x1Fu) << 5)
             | (uint8_t)((unsigned)offset & 0x1Fu);

  char *f = s12z_new_insn(4);
  if (!f)
    {
      as_bad(_("out of memory"));
      goto fail;
    }

  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, (uint8_t)(0x08u | ((unsigned)Dd & 0x07u)), 1);
  number_to_chars_bigendian(f++, bb, 1);
  number_to_chars_bigendian(f++, i1, 1);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_lp;
  return false;
}

static bool
bf_reg_reg_reg (const struct instruction *insn ATTRIBUTE_UNUSED, short ie)
{
  char *const start = input_line_pointer;

  int Dd = 0;
  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto parse_fail;

  if (!lex_match (','))
    goto parse_fail;

  int Ds = 0;
  if (!lex_reg_name (REG_BIT_Dn, &Ds))
    goto parse_fail;

  if (!lex_match (','))
    goto parse_fail;

  const unsigned int dp_allowed =
      (0x01u << REG_D2) |
      (0x01u << REG_D3) |
      (0x01u << REG_D4) |
      (0x01u << REG_D5);

  int Dp = 0;
  if (!lex_reg_name (dp_allowed, &Dp))
    goto parse_fail;

  uint8_t bb = ie ? 0x80u : 0x00u;
  bb = (uint8_t)(bb | ((unsigned int) Ds << 2) | (unsigned int) Dp);

  char *f = s12z_new_insn (3);
  if (f == NULL)
    goto gen_fail;

  number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian (f++, (unsigned int)(0x08u | (unsigned int) Dd), 1);
  number_to_chars_bigendian (f++, bb, 1);

  return true;

parse_fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = start;
  return false;

gen_fail:
  fail_line_pointer = start;
  input_line_pointer = start;
  return false;
}

static bool
bf_opr_reg_reg(const struct instruction *insn, short ie)
{
  char *saved_ilp = input_line_pointer;
  bool ok = false;

  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp;
  int Ds = 0;
  int Dp = 0;
  int size = 0;

  do
  {
    if (!lex_opr(buffer, &n_bytes, &exp, false))
      break;

    if (n_bytes < 0 || n_bytes > (int) sizeof(buffer))
      break;

    if (!lex_match(','))
      break;

    if (!lex_reg_name(REG_BIT_Dn, &Ds))
      break;

    if (!lex_match(','))
      break;

    unsigned allowedDp = (0x01u << REG_D2) |
                         (0x01u << REG_D3) |
                         (0x01u << REG_D4) |
                         (0x01u << REG_D5);

    if (!lex_reg_name(allowedDp, &Dp))
      break;

    size = size_from_suffix(insn, 0);
    if (size < 1 || size > 4)
      break;

    uint8_t bb = (uint8_t)((ie ? 0x80 : 0x00) | 0x50 | (unsigned) Dp | (unsigned) ((size - 1) << 2));

    char *f = s12z_new_insn(3 + n_bytes);
    if (f == NULL)
      break;

    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, (uint8_t)(0x08 | Ds), 1);
    number_to_chars_bigendian(f++, bb, 1);

    emit_opr(f, buffer, n_bytes, &exp);

    ok = true;
  }
  while (0);

  if (!ok)
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ilp;
  }

  return ok;
}


static bool
bf_reg_opr_reg(const struct instruction *insn, short ie)
{
  char *saved_input_line_pointer = input_line_pointer;

  do
  {
    int dst_reg = 0;
    if (!lex_reg_name(REG_BIT_Dn, &dst_reg))
      break;

    if (!lex_match(','))
      break;

    uint8_t buffer[4];
    int n_bytes = 0;
    expressionS exp;
    if (!lex_opr(buffer, &n_bytes, &exp, false))
      break;
    if (n_bytes < 0 || n_bytes > (int)sizeof(buffer))
      break;

    if (!lex_match(','))
      break;

    int pair_reg = 0;
    if (!lex_reg_name((0x01u << REG_D2) |
                      (0x01u << REG_D3) |
                      (0x01u << REG_D4) |
                      (0x01u << REG_D5),
                      &pair_reg))
      break;

    int size = size_from_suffix(insn, 0);
    if (size < 1 || size > 4)
      break;

    uint8_t bb = (ie ? 0x80u : 0x00u);
    bb |= 0x40u;
    bb |= (uint8_t)pair_reg;
    bb |= (uint8_t)((size - 1) << 2);

    int total_len = 3 + n_bytes;
    if (total_len < 3)
      break;

    char *out = s12z_new_insn(total_len);
    if (out == NULL)
      break;

    number_to_chars_bigendian(out++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(out++, 0x08 | dst_reg, 1);
    number_to_chars_bigendian(out++, bb, 1);

    emit_opr(out, buffer, n_bytes, &exp);

    return true;
  }
  while (0);

  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_input_line_pointer;
  return false;
}



static inline bool bfe_reg_reg_reg(const struct instruction *insn)
{
    return bf_reg_reg_reg(insn, 0);
}

static bool
bfi_reg_reg_reg (const struct instruction *insn)
{
  enum { BF_MODE_INSERT = 1 };
  return bf_reg_reg_reg (insn, BF_MODE_INSERT);
}

static bool bfe_reg_reg_imm(const struct instruction *insn)
{
    return bf_reg_reg_imm(insn, 0) != 0;
}

static inline bool bfi_reg_reg_imm(const struct instruction *insn)
{
    return bf_reg_reg_imm(insn, 1);
}


static inline bool bfe_reg_opr_reg(const struct instruction *insn)
{
    return bf_reg_opr_reg(insn, 0);
}

static inline bool bfi_reg_opr_reg(const struct instruction *insn)
{
    return bf_reg_opr_reg(insn, 1);
}


static inline bool bfe_opr_reg_reg(const struct instruction *insn)
{
    return bf_opr_reg_reg(insn, 0);
}

static bool bfi_opr_reg_reg(const struct instruction *insn)
{
    const int bfi_flag = 1;
    return bf_opr_reg_reg(insn, bfi_flag);
}

static bool bfe_reg_opr_imm(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return bf_reg_opr_imm(insn, 0);
}

static bool bfi_reg_opr_imm(const struct instruction *insn)
{
    return bf_reg_opr_imm(insn, true);
}

static bool bfe_opr_reg_imm(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return bf_opr_reg_imm(insn, 0);
}

static bool
bfi_opr_reg_imm(const struct instruction *insn)
{
    enum { IMMEDIATE_FLAG = 1 };
    return bf_opr_reg_imm(insn, IMMEDIATE_FLAG);
}




static bool
tb_reg_rel(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  if (insn == NULL || insn->name == NULL || insn->name[0] == '\0' || insn->name[1] == '\0')
    goto fail;

  int reg;
  if (!lex_reg_name(REG_BIT_Dn | REG_BIT_XY, &reg))
    goto fail;

  if (!lex_match(','))
    goto fail;

  bool long_displacement = false;
  expressionS exp;
  if (!lex_15_bit_offset(&long_displacement, &exp))
    goto fail;

  uint8_t lb = 0x00;
  if (reg == REG_X || reg == REG_Y)
    lb |= 0x08;
  else
    lb |= (uint8_t) reg;

  if (reg == REG_Y)
    lb |= 0x01;

  uint8_t cond = 0x00;
  if (startswith(insn->name + 2, "eq"))
    cond = 0x01;
  else if (startswith(insn->name + 2, "pl"))
    cond = 0x02;
  else if (startswith(insn->name + 2, "mi"))
    cond = 0x03;
  else if (startswith(insn->name + 2, "gt"))
    cond = 0x04;
  else if (startswith(insn->name + 2, "le"))
    cond = 0x05;
  lb |= (uint8_t) (cond << 4);

  switch (insn->name[0])
    {
    case 'd':
      lb |= 0x80;
      break;
    case 't':
      break;
    default:
      gas_assert(0);
      break;
    }

  int insn_size = long_displacement ? 4 : 3;
  char *f = s12z_new_insn(insn_size);
  if (f == NULL)
    goto fail;

  number_to_chars_bigendian(f, insn->opc, 1);
  f++;
  number_to_chars_bigendian(f, lb, 1);
  f++;

  emit_15_bit_offset(f, 4, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}


static bool
tb_opr_rel(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  if (insn == NULL || insn->name == NULL)
    goto fail;

  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp;
  if (!lex_opr(buffer, &n_bytes, &exp, false))
    goto fail;

  if (!lex_match(','))
    goto fail;

  bool long_displacement = false;
  expressionS exp2;
  if (!lex_15_bit_offset(&long_displacement, &exp2))
    goto fail;

  uint8_t lb = 0x0C;
  const char *name = insn->name;

  if (name[2] != '\0' && name[3] != '\0')
    {
      uint8_t cond = 0xFF;
      switch (name[2])
        {
        case 'n':
          if (name[3] == 'e') cond = 0x00;
          break;
        case 'e':
          if (name[3] == 'q') cond = 0x01;
          break;
        case 'p':
          if (name[3] == 'l') cond = 0x02;
          break;
        case 'm':
          if (name[3] == 'i') cond = 0x03;
          break;
        case 'g':
          if (name[3] == 't') cond = 0x04;
          break;
        case 'l':
          if (name[3] == 'e') cond = 0x05;
          break;
        default:
          break;
        }
      if (cond != 0xFF)
        lb |= (uint8_t)(cond << 4);
    }

  switch (name[0])
    {
    case 'd':
      lb |= 0x80;
      break;
    case 't':
      break;
    default:
      gas_assert(0);
      break;
    }

  int size = size_from_suffix(insn, 0);
  gas_assert(size >= 1 && size <= 4);
  lb |= (uint8_t)(size - 1);

  int total_len = n_bytes + (long_displacement ? 4 : 3);
  char *f = s12z_new_insn(total_len);
  if (f == NULL)
    goto fail;

  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, lb, 1);

  f = emit_opr(f, buffer, n_bytes, &exp);
  if (f == NULL)
    goto fail;

  emit_15_bit_offset(f, n_bytes + 4, &exp2);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}




static bool
test_br_reg_reg_rel(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  int regs[2] = {0, 0};
  for (int i = 0; i < 2; ++i)
    {
      if (!lex_reg_name(REG_BIT_Dn, &regs[i]))
        goto fail;
      if (!lex_match(','))
        goto fail;
    }

  bool long_displacement;
  expressionS exp;
  if (!lex_15_bit_offset(&long_displacement, &exp))
    goto fail;

  const uint8_t base_bm = 0x81U;
  const uint8_t base_xb = 0xB8U;

  const uint8_t bm = (uint8_t)(base_bm | (uint8_t)((regs[1] & 0x0F) << 4));
  const uint8_t xb = (uint8_t)(base_xb | (uint8_t)(regs[0] & 0x0F));

  char *f = s12z_new_insn(long_displacement ? 5 : 4);
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
  number_to_chars_bigendian(f++, xb, 1);

  emit_15_bit_offset(f, 5, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}

static bool
test_br_opr_reg_rel(const struct instruction *insn)
{
  char *saved_ilp = input_line_pointer;

  uint8_t opr_buf[4];
  int opr_len = 0;
  expressionS opr_exp;
  if (!lex_opr(opr_buf, &opr_len, &opr_exp, false))
    goto fail;

  if (!lex_match(','))
    goto fail;

  int reg_dn = 0;
  if (!lex_reg_name(REG_BIT_Dn, &reg_dn))
    goto fail;

  if (!lex_match(','))
    goto fail;

  int size = size_from_suffix(insn, 0);
  if (size < 1 || size > 4)
    goto fail;

  bool long_disp = false;
  expressionS disp_exp;
  if (!lex_15_bit_offset(&long_disp, &disp_exp))
    goto fail;

  int total_len = opr_len + (long_disp ? 4 : 3);

  uint8_t bm = 0x81U;
  bm |= (uint8_t)(reg_dn << 4);
  bm |= (uint8_t)((size - 1) << 2);

  char *out = s12z_new_insn(total_len);
  if (out == NULL)
    goto fail;

  number_to_chars_bigendian(out++, insn->opc, 1);
  number_to_chars_bigendian(out++, bm, 1);
  out = emit_opr(out, opr_buf, opr_len, &opr_exp);
  emit_15_bit_offset(out, total_len, &disp_exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}


static bool
test_br_opr_imm_rel(const struct instruction *insn)
{
  char *const saved_ilp = input_line_pointer;

  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp;

  if (!lex_opr(buffer, &n_bytes, &exp, false))
    goto fail;

  if (!lex_match(','))
    goto fail;

  long imm = 0;
  if (!lex_imm(&imm, NULL))
    goto fail;

  if (imm < 0 || imm > 31)
    goto fail;

  if (!lex_match(','))
    goto fail;

  bool long_displacement = false;
  expressionS exp2;
  if (!lex_15_bit_offset(&long_displacement, &exp2))
    goto fail;

  const int size = size_from_suffix(insn, 0);

  uint8_t bm = 0x80u;
  bm |= (uint8_t)(((imm & 0x07) << 4) | ((imm >> 3) & 0x03));
  if (size == 4)
    bm |= 0x08u;
  else if (size == 2)
    bm |= 0x02u;

  const int insn_len = n_bytes + (long_displacement ? 4 : 3);
  char *f = s12z_new_insn(insn_len);
  if (f == NULL)
    goto fail;

  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);
  f = emit_opr(f, buffer, n_bytes, &exp);

  emit_15_bit_offset(f, n_bytes + 4, &exp2);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_ilp;
  return false;
}


static bool
test_br_reg_imm_rel(const struct instruction *insn)
{
  char *saved_input_line_pointer = input_line_pointer;

  int reg_index = 0;
  if (!lex_reg_name(REG_BIT_Dn, &reg_index))
    goto fail;

  if (!lex_match(','))
    goto fail;

  long imm = 0;
  if (!lex_imm(&imm, NULL))
    goto fail;

  if (imm < 0 || imm > 31)
    goto fail;

  if (!lex_match(','))
    goto fail;

  bool long_displacement = false;
  expressionS exp;
  if (!lex_15_bit_offset(&long_displacement, &exp))
    goto fail;

  uint8_t bm = (uint8_t)((reg_index & 0x07) | (((uint8_t)(imm & 0x1F)) << 3));

  int insn_len = long_displacement ? 4 : 3;
  char *buf = s12z_new_insn(insn_len);
  if (buf == NULL)
    goto fail;

  number_to_chars_bigendian(buf, insn->opc, 1);
  number_to_chars_bigendian(buf + 1, bm, 1);

  emit_15_bit_offset(buf + 2, 4, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_input_line_pointer;
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
void
md_assemble(char *str)
{
  char name[20];
  size_t nlen = 0;
  char *op_end;

  fail_line_pointer = NULL;

  if (str == NULL)
    {
      as_bad(_("No instruction or missing opcode."));
      return;
    }

  op_end = str;
  while (!is_end_of_stmt(*op_end) && !is_whitespace(*op_end))
    {
      if (nlen < sizeof(name) - 1)
        {
          name[nlen++] = TOLOWER(*op_end);
        }
      op_end++;
    }
  name[nlen] = 0;

  if (nlen == 0)
    {
      as_bad(_("No instruction or missing opcode."));
      return;
    }

  input_line_pointer = skip_whites(op_end);

  size_t i;
  const size_t opcode_count = sizeof(opcodes) / sizeof(opcodes[0]);
  for (i = 0; i < opcode_count; ++i)
    {
      const struct instruction *opc = opcodes + i;
      if (strcmp(name, opc->name) == 0)
        {
          if (opc->parse_operands(opc))
            return;
        }
    }

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
md_pcrel_from(fixS *fixP)
{
  if (fixP == NULL || fixP->fx_frag == NULL)
    return 0;

  long ret = (long) fixP->fx_size + (long) fixP->fx_frag->fr_address;

  if (fixP->fx_addsy != NULL && S_IS_DEFINED(fixP->fx_addsy))
    ret += (long) fixP->fx_where;

  return ret;
}


/* We need a port-specific relaxation function to cope with sym2 - sym1
   relative expressions with both symbols in the same segment (but not
   necessarily in the same frag as this insn), for example:
   ldab sym2-(sym1-2),pc
   sym1:
   The offset can be 5, 9 or 16 bits long.  */

long
s12z_relax_frag (segT seg ATTRIBUTE_UNUSED, fragS *fragP ATTRIBUTE_UNUSED, long stretch ATTRIBUTE_UNUSED)
{
  (void) seg;
  (void) fragP;
  (void) stretch;
  return 0L;
}

void md_convert_frag(bfd *abfd, asection *sec, fragS *fragP)
{
    (void)abfd;
    (void)sec;
    (void)fragP;
}

/* On an ELF system, we can't relax a weak symbol.  The weak symbol
   can be overridden at final link time by a non weak symbol.  We can
   relax externally visible symbol because there is no shared library
   and such symbol can't be overridden (unless they are weak).  */

/* Force truly undefined symbols to their maximum size, and generally set up
   the frag list to be relaxed.  */
int md_estimate_size_before_relax(fragS *fragP, asection *segment)
{
    (void)fragP;
    (void)segment;
    return 0;
}


/* If while processing a fixup, a reloc really needs to be created
   then it is done here.  */
arelent *
tc_gen_reloc (asection *section, fixS *fixp)
{
  arelent *reloc;
  asymbol **sym_ptr;
  asymbol *sym;
  void *howto;

  if (section == NULL || fixp == NULL || fixp->fx_frag == NULL)
    return NULL;

  sym = symbol_get_bfdsym (fixp->fx_addsy);
  howto = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  if (howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
                    _("Relocation %d is not supported by object file format."),
                    (int) fixp->fx_r_type);
      return NULL;
    }

  reloc = notes_alloc (sizeof (*reloc));
  if (reloc == NULL)
    return NULL;

  sym_ptr = notes_alloc (sizeof (*sym_ptr));
  if (sym_ptr == NULL)
    return NULL;

  *sym_ptr = sym;
  reloc->sym_ptr_ptr = sym_ptr;
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;
  reloc->howto = howto;
  reloc->addend = (section->flags & SEC_CODE) ? fixp->fx_addnumber : fixp->fx_offset;

  return reloc;
}

/* See whether we need to force a relocation into the output file.  */
#include <assert.h>

int tc_s12z_force_relocation(fixS *fixP)
{
    assert(fixP != NULL);
    return generic_force_reloc(fixP);
}

/* Here we decide which fixups can be adjusted to make them relative
   to the beginning of the section instead of the symbol.  Basically
   we need to make sure that the linker relaxation is done
   correctly, so in some cases we force the original symbol to be
   used.  */
bool
tc_s12z_fix_adjustable(fixS *fixP ATTRIBUTE_UNUSED)
{
  (void)fixP;
  return true;
}

void
md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  if (fixP == NULL || valP == NULL)
    {
      as_fatal (_("Invalid arguments to md_apply_fix."));
      return;
    }

  valueT value = *valP;

  if (fixP->fx_addsy == NULL)
    fixP->fx_done = 1;

  if (fixP->fx_subsy != NULL)
    as_bad_subtract (fixP);

  if (fixP->fx_frag == NULL || fixP->fx_frag->fr_literal == NULL)
    {
      as_fatal (_("Line %d: invalid fragment for relocation."), fixP->fx_line);
      return;
    }

  char *where = fixP->fx_frag->fr_literal + fixP->fx_where;

  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_8:
      where[0] = (char) value;
      break;

    case BFD_RELOC_16:
      bfd_putb16 (value, where);
      break;

    case BFD_RELOC_24:
      bfd_putb24 (value, where);
      break;

    case BFD_RELOC_S12Z_OPR:
      if (fixP->fx_size == 3)
        {
          bfd_putb24 (value, where);
        }
      else if (fixP->fx_size == 2)
        {
          bfd_putb16 (value, where);
        }
      else
        {
          as_fatal (_("Line %d: invalid operand size: %u."),
                    fixP->fx_line, (unsigned) fixP->fx_size);
        }
      break;

    case BFD_RELOC_32:
      bfd_putb32 (value, where);
      break;

    case BFD_RELOC_16_PCREL:
      {
        long svalue = (long) value;
        if (svalue < -0x4000 || svalue > 0x3FFF)
          as_bad_where (fixP->fx_file, fixP->fx_line,
                        _("Value out of 16-bit range."));
        bfd_putb16 ((value | 0x8000), where);
      }
      break;

    default:
      as_fatal (_("Line %d: unknown relocation type: 0x%x."),
                fixP->fx_line, fixP->fx_r_type);
      break;
    }
}

/* Set the ELF specific flags.  */
void s12z_elf_final_processing(void)
{
}
