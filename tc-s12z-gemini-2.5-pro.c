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
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>

/* Forward declaration of a global variable assumed to exist. */
extern bool literal_prefix_dollar_hex;

static long
s12z_strtol (const char *str, char **endptr)
{
  const char *p = str;
  bool negative = false;

  if (endptr)
    {
      *endptr = (char *) str;
    }

  if (*p == '-')
    {
      negative = true;
      p++;
    }
  else if (*p == '+')
    {
      p++;
    }

  if (literal_prefix_dollar_hex && *p == '$')
    {
      const char *num_start = p + 1;
      char *local_endptr;

      errno = 0;
      unsigned long val = strtoul (num_start, &local_endptr, 16);

      if (local_endptr == num_start)
        {
          return 0;
        }

      if (endptr)
        {
          *endptr = local_endptr;
        }

      unsigned long limit =
        negative ? ((unsigned long) LONG_MAX + 1) : (unsigned long) LONG_MAX;

      if (val > limit)
        {
          errno = ERANGE;
          return negative ? LONG_MIN : LONG_MAX;
        }

      return negative ? -(long) val : (long) val;
    }

  return strtol (str, endptr, 0);
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
    return "elf32-s12z";
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
static const char * const S12Z_HEADER = "S12Z GAS ";

const char *s12z_listing_header(void)
{
    return S12Z_HEADER;
}

void
md_show_usage (FILE *stream)
{
  if (stream == NULL)
    {
      return;
    }

  fputs (_("\ns12z options:\n"
           "  -mreg-prefix=PREFIX     set a prefix used to indicate register names (default none)\n"
           "  -mdollar-hex            the prefix '$' instead of '0x' is used to indicate literal hexadecimal constants\n"),
         stream);
}

void
s12z_print_statistics (FILE *file)
{
  (void) file;
}

int
md_parse_option (int c, const char *arg)
{
  switch (c)
    {
    case OPTION_REG_PREFIX:
      if (arg == NULL)
        {
          return 0;
        }
      register_prefix = xstrdup (arg);
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

const char *
md_atof (int type, const char *litP, int *sizeP)
{
  return ieee_md_atof (type, litP, sizeP, true);
}

valueT
md_section_align (asection *seg, valueT addr)
{
  int p2align = bfd_section_alignment (seg);

  if (p2align < 0 || (unsigned int)p2align >= (sizeof (valueT) * 8))
    {
      return addr;
    }

  valueT alignment = (valueT)1 << p2align;
  valueT mask = alignment - 1;

  return (addr + mask) & ~mask;
}

void md_begin(void)
{
    /* This function is intentionally left empty. */
}

void
s12z_init_after_args (void)
{
  literal_prefix_dollar_hex = flag_traditional_format;
}

/* Builtin help.  */


static char *skip_whites(char *p)
{
    if (!p) {
        return NULL;
    }

    while (isspace((unsigned char)*p)) {
        p++;
    }

    return p;
}



/* Start a new insn that contains at least 'size' bytes.  Record the
   line information of that insn in the dwarf2 debug sections.  */
#include <assert.h>

static char *
s12z_new_insn (int size)
{
  assert (size > 0);

  char *insn_buffer = frag_more (size);

  dwarf2_emit_insn (size);

  return insn_buffer;
}



static bool lex_reg_name (uint16_t which, int *reg);

static bool
lex_constant (long *v)
{
  char * const p = input_line_pointer;

  int unused_reg_id;
  if (lex_reg_name (~0, &unused_reg_id))
    {
      input_line_pointer = p;
      return false;
    }

  char *end = NULL;
  errno = 0;
  long value = s12z_strtol (p, &end);

  if (errno == 0 && end != p)
    {
      input_line_pointer = end;
      *v = value;
      return true;
    }

  return false;
}

static bool
lex_match (char x)
{
  if (input_line_pointer && *input_line_pointer == x)
  {
    input_line_pointer++;
    return true;
  }
  return false;
}


static bool
lex_expression (expressionS *exp)
{
  char * const initial_pointer = input_line_pointer;
  bool is_expression = false;
  int dummy;

  exp->X_op = O_absent;

  if (!lex_match ('#') && !lex_reg_name (~0, &dummy))
  {
    expression (exp);
    is_expression = (exp->X_op != O_absent);
  }

  if (!is_expression)
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_pointer;
  }

  return is_expression;
}

/* Immediate operand.
   If EXP_O is non-null, then a symbolic expression is permitted,
   in which case, EXP_O will be populated with the parsed expression.
 */
static bool
lex_imm (long *v, expressionS *exp_o)
{
  char * const initial_pointer = input_line_pointer;

  if (*input_line_pointer != '#')
    {
      fail_line_pointer = initial_pointer;
      return false;
    }

  input_line_pointer++;

  expressionS exp;
  if (!lex_expression (&exp))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_pointer;
      return false;
    }

  if (exp.X_op != O_constant)
    {
      if (exp_o)
        {
          *exp_o = exp;
        }
      else
        {
          as_bad (_("A non-constant expression is not permitted here"));
          fail_line_pointer = initial_pointer;
          input_line_pointer = initial_pointer;
          return false;
        }
    }

  *v = exp.X_add_number;
  return true;
}

/* Short mmediate operand */
static bool
lex_imm_e4 (long *val)
{
  char *ilp = input_line_pointer;

  if (lex_imm (val, NULL) && ((*val == -1) || (*val > 0 && *val <= 15)))
    {
      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
lex_match_string (const char *s)
{
  if (!input_line_pointer || !s)
    {
      return false;
    }

  const size_t len = strlen (s);

  if (strncasecmp (s, input_line_pointer, len) != 0)
    {
      return false;
    }

  const char next_char = input_line_pointer[len];
  if (!is_whitespace (next_char) && !is_end_of_stmt (next_char))
    {
      return false;
    }

  input_line_pointer += len;
  return true;
}

/* Parse a register name.
   WHICH is a ORwise combination of the registers which are accepted.
   ~0 accepts all.
   On success, REG will be filled with the index of the register which
   was successfully scanned.
*/
static bool
lex_reg_name (uint16_t which, int *reg)
{
  char *p = input_line_pointer;

  if (!p)
    {
      return false;
    }

  if (register_prefix)
    {
      size_t prefix_len = strlen (register_prefix);
      if (strncmp (register_prefix, p, prefix_len) != 0)
        {
          return false;
        }
      p += prefix_len;
    }

  char *start_of_reg_name = p;
  while (isalnum ((unsigned char) *p))
    {
      p++;
    }

  size_t len = p - start_of_reg_name;
  if (len == 0)
    {
      return false;
    }

  for (int i = 0; i < S12Z_N_REGISTERS; ++i)
    {
      gas_assert (registers[i].name);

      if (len != strlen (registers[i].name)
          || strncasecmp (registers[i].name, start_of_reg_name, len) != 0)
        {
          continue;
        }

      if ((1U << i) & which)
        {
          input_line_pointer = p;
          *reg = i;
          return true;
        }
    }

  return false;
}

static bool
lex_force_match (char x)
{
  if (*input_line_pointer != x)
    {
      as_bad (_("Expecting '%c'"), x);
      return false;
    }

  input_line_pointer++;
  return true;
}

static void
write_be_value (uint8_t * buffer, long value, int size)
{
  for (int i = 0; i < size; ++i)
    {
      buffer[i] = (uint8_t) (value >> (8 * (size - 1 - i)));
    }
}

static bool
lex_opr_immediate (uint8_t * buffer, int *n_bytes, bool immediate_ok)
{
  long imm;
  if (!lex_imm_e4 (&imm))
    {
      return false;
    }

  if (!immediate_ok)
    {
      as_bad (_("An immediate value in a source operand is inappropriate"));
      return false;
    }

  buffer[0] = 0x70;
  if (imm > 0)
    {
      buffer[0] |= (uint8_t) imm;
    }

  *n_bytes = 1;
  return true;
}

static bool
lex_opr_register_direct (uint8_t * buffer, int *n_bytes)
{
  int reg;
  if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      buffer[0] = 0xb8 | (uint8_t) reg;
      *n_bytes = 1;
      return true;
    }
  return false;
}

static bool
handle_bracket_operand (uint8_t * buffer, int *n_bytes, expressionS * exp)
{
  int reg;
  if (lex_expression (exp))
    {
      long c = exp->X_add_number;
      if (lex_match (','))
	{
	  if (!lex_reg_name (REG_BIT_XYSP, &reg))
	    {
	      as_bad (_("Bad operand for constant offset"));
	      return false;
	    }

	  if (c <= 255 && c >= -256)
	    {
	      *n_bytes = 2;
	      buffer[0] = 0xc4;
	      write_be_value (&buffer[1], c, 1);
	    }
	  else
	    {
	      *n_bytes = 4;
	      buffer[0] = 0xc6;
	      write_be_value (&buffer[1], c, 3);
	    }
	  buffer[0] |= (reg - REG_X) << 4;
	  if (c < 0)
	    {
	      buffer[0] |= 0x01;
	    }
	}
      else
	{
	  *n_bytes = 4;
	  buffer[0] = 0xfe;
	  write_be_value (&buffer[1], c, 3);
	}
    }
  else if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      int reg2;
      if (!lex_force_match (',')
	  || !lex_reg_name (REG_BIT_XY, &reg2))
	{
	  as_bad (_("Invalid operand for register offset"));
	  return false;
	}
      *n_bytes = 1;
      buffer[0] = 0xc8 | reg | ((reg2 - REG_X) << 4);
    }
  else
    {
      return false;
    }
  return true;
}

static bool
lex_opr_indexed_bracket (uint8_t * buffer, int *n_bytes, expressionS * exp)
{
  if (!lex_match ('['))
    {
      return false;
    }

  if (!handle_bracket_operand (buffer, n_bytes, exp))
    {
      return false;
    }

  return lex_force_match (']');
}

static bool
handle_paren_const_offset (uint8_t * buffer, int *n_bytes, long c)
{
  int reg;
  if (!lex_force_match (','))
    return false;

  if (lex_reg_name (REG_BIT_XYSP, &reg))
    {
      if (reg != REG_P && c >= 0 && c <= 15)
	{
	  *n_bytes = 1;
	  buffer[0] = 0x40 | ((reg - REG_X) << 4) | (uint8_t) c;
	}
      else if (c >= -256 && c <= 255)
	{
	  *n_bytes = 2;
	  buffer[0] = 0xc0 | ((reg - REG_X) << 4);
	  if (c < 0)
	    buffer[0] |= 0x01;
	  buffer[1] = (uint8_t) c;
	}
      else
	{
	  *n_bytes = 4;
	  buffer[0] = 0xc2 | ((reg - REG_X) << 4);
	  write_be_value (&buffer[1], c, 3);
	}
      return true;
    }
  if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      if (c >= -(1L << 17) && c < (1L << 17))
	{
	  *n_bytes = 3;
	  buffer[0] = 0x80 | (uint8_t) reg | (uint8_t) (((c >> 16) & 0x03) << 4);
	  write_be_value (&buffer[1], c, 2);
	}
      else
	{
	  *n_bytes = 4;
	  buffer[0] = 0xe8 | (uint8_t) reg;
	  write_be_value (&buffer[1], c, 3);
	}
      return true;
    }
  as_bad (_("Bad operand for constant offset"));
  return false;
}

static bool
handle_paren_operand (uint8_t * buffer, int *n_bytes)
{
  long c;
  int reg;
  if (lex_constant (&c))
    {
      return handle_paren_const_offset (buffer, n_bytes, c);
    }
  if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      int reg2;
      if (lex_match (',') && lex_reg_name (REG_BIT_XYS, &reg2))
	{
	  *n_bytes = 1;
	  buffer[0] = 0x88 | ((reg2 - REG_X) << 4) | (uint8_t) reg;
	  return true;
	}
      as_bad (_("Invalid operand for register offset"));
      return false;
    }
  if (lex_reg_name (REG_BIT_XYS, &reg))
    {
      if (lex_match ('-'))
	{
	  if (reg == REG_S)
	    {
	      as_bad (_("Invalid register for postdecrement operation"));
	      return false;
	    }
	  *n_bytes = 1;
	  buffer[0] = (reg == REG_X) ? 0xc7 : 0xd7;
	  return true;
	}
      if (lex_match ('+'))
	{
	  *n_bytes = 1;
	  if (reg == REG_X) buffer[0] = 0xe7;
	  else if (reg == REG_Y) buffer[0] = 0xf7;
	  else if (reg == REG_S) buffer[0] = 0xff;
	  return true;
	}
      return false;
    }
  if (lex_match ('+'))
    {
      if (!lex_reg_name (REG_BIT_XY, &reg))
	{
	  as_bad (_("Invalid register for preincrement operation"));
	  return false;
	}
      *n_bytes = 1;
      buffer[0] = (reg == REG_X) ? 0xe3 : 0xf3;
      return true;
    }
  if (lex_match ('-'))
    {
      if (!lex_reg_name (REG_BIT_XYS, &reg))
	{
	  as_bad (_("Invalid register for predecrement operation"));
	  return false;
	}
      *n_bytes = 1;
      if (reg == REG_X) buffer[0] = 0xc3;
      else if (reg == REG_Y) buffer[0] = 0xd3;
      else if (reg == REG_S) buffer[0] = 0xfb;
      return true;
    }
  return false;
}

static bool
lex_opr_indexed_paren (uint8_t * buffer, int *n_bytes)
{
  char *ilp_before_paren = input_line_pointer;
  if (!lex_match ('('))
    {
      return false;
    }
  if (!handle_paren_operand (buffer, n_bytes))
    {
      input_line_pointer = ilp_before_paren;
      return false;
    }

  if (!lex_match (')'))
    {
      input_line_pointer = ilp_before_paren;
      return false;
    }
  return true;
}

static bool
lex_opr_absolute (uint8_t * buffer, int *n_bytes, expressionS * exp)
{
  if (!lex_expression (exp))
    {
      return false;
    }

  if (exp->X_op == O_constant)
    {
      valueT value = exp->X_add_number;
      if (value < (1U << 14))
	{
	  *n_bytes = 2;
	  buffer[0] = (uint8_t) (value >> 8);
	  buffer[1] = (uint8_t) value;
	}
      else if (value < (1U << 19))
	{
	  *n_bytes = 3;
	  buffer[0] = 0xf8;
	  if (value & (1U << 17)) buffer[0] |= 0x04;
	  if (value & (1U << 16)) buffer[0] |= 0x01;
	  write_be_value (&buffer[1], value, 2);
	}
      else
	{
	  *n_bytes = 4;
	  buffer[0] = 0xfa;
	  write_be_value (&buffer[1], value, 3);
	}
    }
  else
    {
      *n_bytes = 4;
      buffer[0] = 0xfa;
      write_be_value (&buffer[1], 0, 3);
    }
  return true;
}

static bool
lex_opr (uint8_t * buffer, int *n_bytes, expressionS * exp,
	 bool immediate_ok)
{
  char *ilp = input_line_pointer;
  exp->X_op = O_absent;
  *n_bytes = 0;
  buffer[0] = 0;

  if (lex_opr_immediate (buffer, n_bytes, immediate_ok))
    return true;
  input_line_pointer = ilp;

  if (lex_opr_register_direct (buffer, n_bytes))
    return true;
  input_line_pointer = ilp;

  if (lex_opr_indexed_bracket (buffer, n_bytes, exp))
    return true;
  input_line_pointer = ilp;

  if (lex_opr_indexed_paren (buffer, n_bytes))
    return true;
  input_line_pointer = ilp;

  if (lex_opr_absolute (buffer, n_bytes, exp))
    return true;

  fail_line_pointer = ilp;
  input_line_pointer = ilp;
  return false;
}

static bool
lex_offset (long *val)
{
  char *p = input_line_pointer;

  if (*p != '*')
    {
      return false;
    }
  p++;

  const char sign = *p;
  if (sign != '+' && sign != '-')
    {
      return false;
    }
  p++;

  char *end = NULL;
  errno = 0;
  long parsed_val = s12z_strtol (p, &end);

  if (errno != 0 || end == p)
    {
      return false;
    }

  *val = (sign == '-') ? -parsed_val : parsed_val;
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

static bool
no_operands (const struct instruction *insn)
{
  if (*input_line_pointer != '\0')
  {
    as_bad (_("Garbage at end of instruction"));
    return false;
  }

  char *f = s12z_new_insn (insn->page);
  if (!f)
  {
    return false;
  }

  if (insn->page == 2)
  {
    number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
    f++;
  }

  number_to_chars_bigendian (f, insn->opc, 1);

  return true;
}


static void
emit_reloc (expressionS *exp, char *f, int size, enum bfd_reloc_code_real reloc)
{
  if (exp->X_op == O_absent || exp->X_op == O_constant)
    {
      return;
    }

  fixS *fix = fix_new_exp (frag_now,
                           f - frag_now->fr_literal,
                           size,
                           exp,
                           false,
                           reloc);
  if (fix)
    {
      fix->fx_addnumber = 0;
    }
}

/* Emit the code for an OPR address mode operand */
static char *
emit_opr (char *f, const uint8_t *buffer, int n_bytes, expressionS *exp)
{
  if (!f || !buffer || n_bytes <= 0)
    {
      return f;
    }

  number_to_chars_bigendian (f, buffer[0], 1);
  f++;

  if (exp)
    {
      emit_reloc (exp, f, 3, BFD_RELOC_S12Z_OPR);
    }

  for (int i = 1; i < n_bytes; i++)
    {
      number_to_chars_bigendian (f, buffer[i], 1);
      f++;
    }

  return f;
}

/* Emit the code for a 24 bit direct address operand */
static char *
emit_ext24 (char *buffer, long value)
{
  const int EXT24_BYTE_COUNT = 3;

  assert(buffer != NULL);
  number_to_chars_bigendian (buffer, value, EXT24_BYTE_COUNT);

  return buffer + EXT24_BYTE_COUNT;
}

static bool
opr (const struct instruction *insn)
{
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_opr (buffer, &n_bytes, &exp, false))
    {
      return false;
    }

  const bool use_ext24_encoding = (exp.X_op == O_constant
				   && buffer[0] == 0xFA
				   && insn->alt_opc != 0);

  if (use_ext24_encoding)
    {
      gas_assert (insn->page == 1);
      char *f = s12z_new_insn (4);
      number_to_chars_bigendian (f, insn->alt_opc, 1);
      emit_ext24 (f + 1, exp.X_add_number);
    }
  else
    {
      char *f = s12z_new_insn ((size_t) n_bytes + 1);
      number_to_chars_bigendian (f, insn->opc, 1);
      emit_opr (f + 1, buffer, n_bytes, &exp);
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
  long val;

  if (lex_offset (&val))
    {
      exp->X_op = O_absent;
      exp->X_add_number = val;
    }
  else if (lex_expression (exp))
    {
      if (exp->X_op == O_constant)
	{
	  val = exp->X_add_number;
	}
      else
	{
	  /* A symbolic expression must be assumed to be a long displacement. */
	  *long_displacement = true;
	  return true;
	}
    }
  else
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      exp->X_op = O_absent;
      return false;
    }

  if (val > 0x3FFF || val < -0x4000)
    {
      as_fatal (_("Offset is outside of 15 bit range"));
      return false;
    }

  *long_displacement = (val > 63 || val < -64);

  return true;
}

static void
emit_15_bit_offset (char *f, int where, expressionS *exp)
{
  gas_assert (exp);

  if (exp->X_op != O_absent && exp->X_op != O_constant)
    {
      const int reloc_size_bytes = 2;
      exp->X_add_number += where;
      fixS *fix = fix_new_exp (frag_now,
                   f - frag_now->fr_literal,
                   reloc_size_bytes,
                   exp,
                   true,
                   BFD_RELOC_16_PCREL);
      fix->fx_addnumber = where - reloc_size_bytes;
    }
  else
    {
      const long value = exp->X_add_number;
      const int max_short_offset = 63;
      const int min_short_offset = -64;

      if (value > max_short_offset || value < min_short_offset)
        {
          const long long_disp_flag = 0x8000;
          const int long_disp_size = 2;
          number_to_chars_bigendian (f, value | long_disp_flag, long_disp_size);
        }
      else
        {
          const int short_disp_mask = 0x7F;
          const int short_disp_size = 1;
          number_to_chars_bigendian (f, value & short_disp_mask, short_disp_size);
        }
    }
}

static bool
assemble_relative_insn (const struct instruction *insn)
{
  bool long_displacement;
  expressionS exp;

  if (!lex_15_bit_offset (&long_displacement, &exp))
    {
      return false;
    }

  const size_t opcode_size = 1;
  const size_t insn_size = long_displacement ? 3 : 2;
  char * const buffer = s12z_new_insn (insn_size);

  number_to_chars_bigendian (buffer, insn->opc, opcode_size);

  const size_t offset_size = insn_size - opcode_size;
  emit_15_bit_offset (buffer + opcode_size, offset_size, &exp);

  return true;
}

static bool
reg_inh (const struct instruction *insn)
{
  int reg;
  if (!lex_reg_name (REG_BIT_Dn, &reg))
    {
      return false;
    }

  char *p_insn = s12z_new_insn (insn->page);
  if (!p_insn)
    {
      return false;
    }

  if (insn->page == 2)
    {
      number_to_chars_bigendian (p_insn, PAGE2_PREBYTE, 1);
      p_insn++;
    }

  number_to_chars_bigendian (p_insn, insn->opc + reg, 1);
  return true;
}


/* Special case for CLR X and CLR Y */
static bool
clr_xy (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  int reg;
  if (!lex_reg_name (REG_BIT_XY, &reg))
    {
      return false;
    }

  char *f = s12z_new_insn (1);
  if (!f)
    {
      return false;
    }

  const unsigned int base_opcode = 0x9a;
  unsigned int opcode = base_opcode + (reg - REG_X);
  number_to_chars_bigendian (f, opcode, 1);

  return true;
}

/* Some instructions have a suffix like ".l", ".b", ".w" etc
   which indicates the size of the operands. */
static int
size_from_suffix (const struct instruction *insn, int idx)
{
  if (insn == NULL || insn->name == NULL || idx < 0)
    {
      return -3;
    }

  const char *dot = strchr (insn->name, '.');
  if (dot == NULL)
    {
      return -3;
    }

  const char *suffix = dot + 1;
  if (strlen (suffix) <= (size_t) idx)
    {
      as_fatal (_("Bad size"));
      return -2;
    }

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
      as_fatal (_("Bad size"));
      return -2;
    }
}

static bool
mul_reg_reg_reg (const struct instruction *insn)
{
  char * const ilp = input_line_pointer;
  int Dd, Dj, Dk;

  if (!lex_reg_name (REG_BIT_Dn, &Dd) ||
      !lex_match (',') ||
      !lex_reg_name (REG_BIT_Dn, &Dj) ||
      !lex_match (',') ||
      !lex_reg_name (REG_BIT_Dn, &Dk))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  const char *dot = strchrnul (insn->name, '.');
  if (*dot == '\0' || dot == insn->name)
    {
      as_fatal (_("BAD MUL"));
      return false; /* Not reachable if as_fatal exits. */
    }

  uint8_t mb;
  switch (dot[-1])
    {
    case 's':
      mb = 0x80;
      break;
    case 'u':
      mb = 0x00;
      break;
    default:
      as_fatal (_("BAD MUL"));
      return false; /* Not reachable if as_fatal exits. */
    }

  char *f = s12z_new_insn (insn->page + 1);
  if (!f)
    {
      return false;
    }

  if (insn->page == 2)
    {
      number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
      f++;
    }

  number_to_chars_bigendian (f, (uint8_t) (insn->opc + Dd), 1);
  f++;

  mb |= (uint8_t) (Dj << 3);
  mb |= (uint8_t) Dk;

  number_to_chars_bigendian (f, mb, 1);

  return true;
}


static bool
mul_reg_reg_imm (const struct instruction *insn)
{
  char * const ilp = input_line_pointer;

  int Dd, Dj;
  long imm;

  if (!lex_reg_name (REG_BIT_Dn, &Dd) ||
      !lex_match (',') ||
      !lex_reg_name (REG_BIT_Dn, &Dj) ||
      !lex_match (',') ||
      !lex_imm (&imm, NULL))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  int size = size_from_suffix (insn, 0);
  char *f = s12z_new_insn (insn->page + 1 + size);
  char *p = f;

  if (insn->page == 2)
    {
      number_to_chars_bigendian (p, PAGE2_PREBYTE, 1);
      p++;
    }

  number_to_chars_bigendian (p, (uint8_t) (insn->opc + Dd), 1);
  p++;

  uint8_t mb = 0x44;
  const char *suffix_ptr = strchrnul (insn->name, '.');

  if (suffix_ptr == insn->name)
    {
      as_fatal (_("BAD MUL"));
    }

  switch (suffix_ptr[-1])
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

  mb |= (uint8_t) (Dj << 3);
  mb |= (uint8_t) (size - 1);

  number_to_chars_bigendian (p, mb, 1);
  p++;

  number_to_chars_bigendian (p, imm, size);

  return true;
}


static bool
mul_reg_reg_opr (const struct instruction *insn)
{
  char * const ilp = input_line_pointer;
  int Dd, Dj;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_reg_name (REG_BIT_Dn, &Dd)
      || !lex_match (',')
      || !lex_reg_name (REG_BIT_Dn, &Dj)
      || !lex_match (',')
      || !lex_opr (buffer, &n_bytes, &exp, true))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  const int size = size_from_suffix (insn, 0);
  char *f = s12z_new_insn (insn->page + 1 + n_bytes);

  if (insn->page == 2)
    {
      number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
    }

  number_to_chars_bigendian (f++, insn->opc + Dd, 1);

  const char * const dot = strchrnul (insn->name, '.');
  const char suffix = (dot > insn->name) ? dot[-1] : '\0';

  uint8_t sign_bit = 0;
  if (suffix == 's')
    {
      sign_bit = 0x80;
    }
  else if (suffix != 'u')
    {
      as_fatal (_("BAD MUL"));
      return false;
    }

  const uint8_t base_op = 0x40;
  const uint8_t reg_bits = (uint8_t) (Dj << 3);
  const uint8_t size_bits = (uint8_t) (size - 1);
  const uint8_t mb = base_op | sign_bit | reg_bits | size_bits;

  number_to_chars_bigendian (f++, mb, 1);

  emit_opr (f, buffer, n_bytes, &exp);

  return true;
}

static bool
mul_reg_opr_opr (const struct instruction *insn)
{
  char * const initial_ilp = input_line_pointer;

  int Dd;
  uint8_t buffer1[4];
  int n_bytes1;
  expressionS exp1;
  uint8_t buffer2[4];
  int n_bytes2;
  expressionS exp2;

  if (!lex_reg_name (REG_BIT_Dn, &Dd)
      || !lex_match (',')
      || !lex_opr (buffer1, &n_bytes1, &exp1, false)
      || !lex_match (',')
      || !lex_opr (buffer2, &n_bytes2, &exp2, false))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_ilp;
      return false;
    }

  const int size1 = size_from_suffix (insn, 0);
  const int size2 = size_from_suffix (insn, 1);
  const size_t instruction_size = (size_t) insn->page + 1 + n_bytes1 + n_bytes2;

  char *p = s12z_new_insn (instruction_size);
  if (!p)
    {
      as_fatal (_("memory allocation failed for instruction"));
      return false;
    }

  if (insn->page == 2)
    {
      number_to_chars_bigendian (p, PAGE2_PREBYTE, 1);
      p++;
    }

  number_to_chars_bigendian (p, insn->opc + Dd, 1);
  p++;

  uint8_t sign_bit;
  const char * const dot = strchrnul (insn->name, '.');
  if (dot == insn->name)
    {
      as_fatal (_("BAD MUL: Missing or invalid instruction suffix"));
    }

  switch (dot[-1])
    {
    case 's':
      sign_bit = 0x80;
      break;
    case 'u':
      sign_bit = 0x00;
      break;
    default:
      as_fatal (_("BAD MUL: Invalid instruction suffix"));
    }

  const uint8_t mb = 0x42 | sign_bit | ((uint8_t) (size1 - 1) << 4) | ((uint8_t) (size2 - 1) << 2);
  number_to_chars_bigendian (p, mb, 1);
  p++;

  p = emit_opr (p, buffer1, n_bytes1, &exp1);
  p = emit_opr (p, buffer2, n_bytes2, &exp2);

  return true;
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
	{
	  return false;
	}
      *reg_bits |= (0x1u << reg);
    }

  return true;
}

static bool
parse_register_list_operand (uint16_t *out_reg_bits)
{
  int first_reg;
  if (!lex_reg_name (REG_BIT_GRP1 | REG_BIT_GRP0, &first_reg))
    {
      return false;
    }

  uint16_t temp_reg_bits = 1U << first_reg;
  uint16_t admitted_group;

  if ((temp_reg_bits & REG_BIT_GRP1) != 0)
    {
      admitted_group = REG_BIT_GRP1;
    }
  else
    {
      admitted_group = REG_BIT_GRP0;
    }

  if (lex_reg_list (admitted_group, &temp_reg_bits))
    {
      *out_reg_bits = temp_reg_bits;
      return true;
    }

  return false;
}

static bool
psh_pull (const struct instruction *insn)
{
  uint8_t pb = (0 == strcmp ("pul", insn->name)) ? 0x80 : 0x00;

  if (lex_match_string ("all16b"))
    {
      pb |= 0x40;
    }
  else if (!lex_match_string ("all"))
    {
      uint16_t reg_bits;
      if (!parse_register_list_operand (&reg_bits))
        {
          fail_line_pointer = input_line_pointer;
          return false;
        }

      if ((reg_bits & REG_BIT_GRP1) != 0)
        {
          pb |= 0x40;
        }

      for (int i = 0; i < 16; ++i)
        {
          if ((reg_bits & (1U << i)) != 0)
            {
              pb |= reg_map[i];
            }
        }
    }

  char *f = s12z_new_insn (2);
  if (!f)
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  number_to_chars_bigendian (f, insn->opc, 1);
  number_to_chars_bigendian (f + 1, pb, 1);
  return true;
}


static bool
tfr (const struct instruction *insn)
{
  int reg1;
  int reg2;
  const int any_register_mask = ~0;

  if (!lex_reg_name (any_register_mask, &reg1)
      || !lex_match (',')
      || !lex_reg_name (any_register_mask, &reg2))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  const bool is_extension_insn = (strcasecmp ("sex", insn->name) == 0)
                                 || (strcasecmp ("zex", insn->name) == 0);

  if (is_extension_insn && (registers[reg2].bytes <= registers[reg1].bytes))
    {
      as_warn (_("Source register for %s is no larger than the destination register"),
               insn->name);
    }
  else if (reg1 == reg2)
    {
      as_warn (_("The destination and source registers are identical"));
    }

  char *f = s12z_new_insn (1 + insn->page);
  if (insn->page == 2)
    {
      number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
    }

  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, (unsigned char) ((reg1 << 4) | reg2), 1);

  return true;
}

static bool
imm8 (const struct instruction *insn)
{
  long imm;
  if (!lex_imm (&imm, NULL))
    {
      return false;
    }

  if (imm < -128 || imm > 127)
    {
      as_bad (_("Immediate value %ld is out of range for instruction %s"),
              imm, insn->name);
      return false;
    }

  char *f = s12z_new_insn (2);
  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f, (unsigned char) imm, 1);

  return true;
}

static bool
reg_imm (const struct instruction *insn, int allowed_reg)
{
  char *ilp = input_line_pointer;
  int reg;
  long imm;

  if (lex_reg_name (allowed_reg, &reg)
      && lex_force_match (',')
      && lex_imm (&imm, NULL))
    {
      short size = registers[reg].bytes;
      char *f = s12z_new_insn (insn->page + size);

      if (insn->page == 2)
        {
          number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
          f++;
        }

      number_to_chars_bigendian (f, insn->opc + reg, 1);
      f++;

      number_to_chars_bigendian (f, imm, size);
      f += size;

      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool
regd_imm (const struct instruction *insn)
{
  return insn && reg_imm (insn, REG_BIT_Dn);
}

static bool
regdxy_imm (const struct instruction *insn)
{
  if (!insn)
    {
      return false;
    }
  return reg_imm (insn, REG_BIT_Dn | REG_BIT_XY);
}


static const unsigned int REG_S_FLAG = 1U << REG_S;

static bool
regs_imm (const struct instruction *insn)
{
  if (!insn)
    {
      return false;
    }
  return reg_imm (insn, REG_S_FLAG);
}

static bool
is_valid_trap_value (long value)
{
  if (value < 0x92 || value > 0xFF)
    {
      return false;
    }

  if ((value >= 0xA0 && value <= 0xA7) || (value >= 0xB0 && value <= 0xB7))
    {
      return false;
    }

  return true;
}

static bool
trap_imm (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  long imm;
  if (!lex_imm (&imm, NULL))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  if (!is_valid_trap_value (imm))
    {
      as_bad (_("trap value %ld is not valid"), imm);
      return false;
    }

  char *f = s12z_new_insn (2);
  number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian (f + 1, (unsigned char) imm, 1);

  return true;
}



/* Special one byte instruction CMP X, Y */
static bool
regx_regy (const struct instruction *insn)
{
  int dummy_reg;

  if (!lex_reg_name (0x1U << REG_X, &dummy_reg)
      || !lex_force_match (',')
      || !lex_reg_name (0x1U << REG_Y, &dummy_reg))
    {
      return false;
    }

  char *opcode_buffer = s12z_new_insn (1);
  if (!opcode_buffer)
    {
      return false;
    }

  number_to_chars_bigendian (opcode_buffer, insn->opc, 1);
  return true;
}

/* Special one byte instruction SUB D6, X, Y */
static bool
regd6_regx_regy (const struct instruction *insn)
{
  char * const ilp = input_line_pointer;
  int reg;

  if (lex_reg_name (0x1U << REG_D6, &reg) &&
      lex_match (',') &&
      lex_reg_name (0x1U << REG_X, &reg) &&
      lex_match (',') &&
      lex_reg_name (0x1U << REG_Y, &reg))
    {
      char *f = s12z_new_insn (1);
      number_to_chars_bigendian (f, insn->opc, 1);
      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

/* Special one byte instruction SUB D6, Y, X */
static bool
regd6_regy_regx (const struct instruction *insn)
{
  char * const saved_line_pointer = input_line_pointer;
  int reg;

  if (lex_reg_name (0x1U << REG_D6, &reg) &&
      lex_match (',') &&
      lex_reg_name (0x1U << REG_Y, &reg) &&
      lex_match (',') &&
      lex_reg_name (0x1U << REG_X, &reg))
    {
      char *f = s12z_new_insn (1);
      number_to_chars_bigendian (f, insn->opc, 1);
      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_line_pointer;
  return false;
}

static bool
reg_opr (const struct instruction *insn, int allowed_regs,
	 bool immediate_ok)
{
  char * const ilp = input_line_pointer;
  int reg;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_reg_name (allowed_regs, &reg)
      || !lex_force_match (',')
      || !lex_opr (buffer, &n_bytes, &exp, immediate_ok))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  const bool use_ext24_encoding = (exp.X_op == O_constant
				   && buffer[0] == 0xFA
				   && insn->alt_opc != 0);

  if (use_ext24_encoding)
    {
      char *f = s12z_new_insn (4);
      gas_assert (insn->page == 1);
      number_to_chars_bigendian (f, insn->alt_opc + reg, 1);
      f += 1;
      emit_ext24 (f, exp.X_add_number);
    }
  else
    {
      char *f = s12z_new_insn (n_bytes + insn->page);
      if (insn->page == 2)
	{
	  number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
	  f += 1;
	}
      number_to_chars_bigendian (f, insn->opc + reg, 1);
      f += 1;
      emit_opr (f, buffer, n_bytes, &exp);
    }

  return true;
}


static bool
is_dest_operand_d_or_xy_reg(const struct instruction *insn)
{
    if (!insn) {
        return false;
    }

    const int register_mask = REG_BIT_Dn | REG_BIT_XY;
    const bool is_source_operand = false;

    return reg_opr(insn, register_mask, is_source_operand);
}

static bool
regdxy_opr_src (const struct instruction *insn)
{
  const unsigned int allowed_registers = REG_BIT_Dn | REG_BIT_XY;
  const bool is_source_operand = true;

  return reg_opr (insn, allowed_registers, is_source_operand);
}


static inline bool regd_opr(const struct instruction *insn)
{
    if (!insn)
    {
        return false;
    }
    return reg_opr(insn, REG_BIT_Dn, true);
}


/* OP0: S; OP1: destination OPR */
static bool
regs_opr_dest(const struct instruction *insn)
{
    const unsigned int reg_s_mask = 1U << REG_S;
    const bool is_source_operand = false;

    return reg_opr(insn, reg_s_mask, is_source_operand);
}

/* OP0: S; OP1: source OPR */
static bool
regs_opr_src (const struct instruction *insn)
{
  if (!insn)
    {
      return false;
    }

  const unsigned int source_register_flag = 1U << REG_S;
  return reg_opr (insn, source_register_flag, true);
}

static bool
imm_opr (const struct instruction *insn)
{
  char *const ilp = input_line_pointer;
  long imm;
  expressionS exp0 = { .X_op = O_absent };
  const int size = size_from_suffix (insn, 0);

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp1 = {0};

  if (lex_imm (&imm, size > 1 ? &exp0 : NULL)
      && lex_match (',')
      && lex_opr (buffer, &n_bytes, &exp1, false))
    {
      char *f = s12z_new_insn (1 + n_bytes + size);

      number_to_chars_bigendian (f, insn->opc, 1);
      f += 1;

      emit_reloc (&exp0, f, size, size == 4 ? BFD_RELOC_32 : BFD_RELOC_S12Z_OPR);
      number_to_chars_bigendian (f, imm, size);
      f += size;

      emit_opr (f, buffer, n_bytes, &exp1);

      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
opr_opr (const struct instruction *insn)
{
  char * const initial_ilp = input_line_pointer;

  uint8_t buffer1[4];
  int n_bytes1;
  expressionS exp1;

  uint8_t buffer2[4];
  int n_bytes2;
  expressionS exp2;

  if (lex_opr (buffer1, &n_bytes1, &exp1, false)
      && lex_match (',')
      && lex_opr (buffer2, &n_bytes2, &exp2, false))
    {
      const size_t opc_size = 1;
      char *f = s12z_new_insn (opc_size + n_bytes1 + n_bytes2);

      number_to_chars_bigendian (f, insn->opc, opc_size);
      f += opc_size;

      f = emit_opr (f, buffer1, n_bytes1, &exp1);
      (void) emit_opr (f, buffer2, n_bytes2, &exp2);

      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = initial_ilp;
  return false;
}

static bool
reg67sxy_opr  (const struct instruction *insn)
{
  int reg;
  if (!lex_reg_name (REG_BIT_XYS | (0x1U << REG_D6) | (0x1U << REG_D7), &reg))
    return false;

  if (!lex_match (','))
    return false;

  uint8_t operand_buffer[4];
  int operand_n_bytes;
  expressionS exp;
  if (!lex_opr (operand_buffer, &operand_n_bytes, &exp, false))
    return false;

  const int total_bytes = 1 + operand_n_bytes;
  char * const instruction_buffer = s12z_new_insn (total_bytes);
  if (!instruction_buffer)
    return false;

  const unsigned int opcode = insn->opc + reg - REG_D6;
  number_to_chars_bigendian (instruction_buffer, opcode, 1);
  emit_opr (instruction_buffer + 1, operand_buffer, operand_n_bytes, &exp);

  return true;
}

static bool
rotate(const struct instruction *insn, short dir)
{
    uint8_t operand_buffer[4];
    int num_operand_bytes;
    expressionS expression;

    if (!lex_opr(operand_buffer, &num_operand_bytes, &expression, false))
    {
        return false;
    }

    const int header_size = 2;
    char *const instruction_buffer = s12z_new_insn(num_operand_bytes + header_size);
    if (!instruction_buffer)
    {
        return false;
    }

    int size = size_from_suffix(insn, 0);
    if (size < 0)
    {
        size = 1;
    }

    uint8_t sb = 0x24 | (uint8_t)(size - 1);
    if (dir)
    {
        sb |= 0x40;
    }

    char *write_ptr = instruction_buffer;
    number_to_chars_bigendian(write_ptr, insn->opc, 1);
    write_ptr += 1;
    number_to_chars_bigendian(write_ptr, sb, 1);
    write_ptr += 1;
    emit_opr(write_ptr, operand_buffer, num_operand_bytes, &expression);

    return true;
}

static inline bool rol(const struct instruction *insn)
{
    return rotate(insn, 1);
}

static bool
ror (const struct instruction *insn)
{
  return insn && rotate (insn, 0);
}


/* Shift instruction with a register operand and an immediate #1 or #2
   left = 1; right = 0;
   logical = 0; arithmetic = 1;
*/
static bool
lex_shift_reg_imm1 (const struct instruction *insn, short type, short dir)
{
  const char * const initial_pointer = input_line_pointer;
  long imm = -1;
  int reg_num;

  if (!lex_reg_name (REG_BIT_Dn, &reg_num) || !lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_pointer;
      return false;
    }

  if (!lex_imm (&imm, NULL) || (imm != 1 && imm != 2))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_pointer;
      return false;
    }

  input_line_pointer = initial_pointer;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  if (!lex_opr (buffer, &n_bytes, &exp, false))
    {
      input_line_pointer = initial_pointer;
      return false;
    }

  gas_assert (n_bytes == 1);

  uint8_t sb = 0x34;
  sb |= (uint8_t) dir << 6;
  sb |= (uint8_t) type << 7;
  if (imm == 2)
    {
      sb |= 0x08;
    }

  char *f = s12z_new_insn (3);
  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, sb, 1);
  emit_opr (f, buffer, n_bytes, &exp);

  return true;
}

/* Shift instruction with a register operand.
   left = 1; right = 0;
   logical = 0; arithmetic = 1; */
static bool
lex_shift_reg (const struct instruction *insn, short type, short dir)
{
  int Dd, Ds;
  if (!lex_reg_name (REG_BIT_Dn, &Dd)
      || !lex_match (',')
      || !lex_reg_name (REG_BIT_Dn, &Ds)
      || !lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  const uint8_t SHIFT_DIR_SHIFT = 6;
  const uint8_t SHIFT_TYPE_SHIFT = 7;
  const uint8_t common_sb_bits = (dir << SHIFT_DIR_SHIFT) | (type << SHIFT_TYPE_SHIFT) | Ds;

  int Dn;
  if (lex_reg_name (REG_BIT_Dn, &Dn))
    {
      const uint8_t SB_REG_MODE_FLAG = 0x10;
      const uint8_t XB_REG_MODE_BASE = 0xb8;

      char *f = s12z_new_insn (3);
      uint8_t sb = SB_REG_MODE_FLAG | common_sb_bits;
      uint8_t xb = XB_REG_MODE_BASE | Dn;

      number_to_chars_bigendian (f++, insn->opc | Dd, 1);
      number_to_chars_bigendian (f++, sb, 1);
      number_to_chars_bigendian (f, xb, 1);
      return true;
    }

  long imm;
  if (lex_imm (&imm, NULL))
    {
      const long MAX_SHIFT_IMM = 31;
      if (imm < 0 || imm > MAX_SHIFT_IMM)
	{
	  as_bad (_("Shift value should be in the range [0,31]"));
	  fail_line_pointer = input_line_pointer;
	  return false;
	}

      int n_bytes;
      uint8_t sb = common_sb_bits;

      if (imm == 1 || imm == 2)
	{
	  n_bytes = 2;
	}
      else
	{
	  const uint8_t SB_IMM_MODE_FLAG = 0x10;
	  const uint8_t SB_IMM_LSB_SHIFT = 3;
	  n_bytes = 3;
	  sb |= SB_IMM_MODE_FLAG;
	  sb |= (imm & 1) << SB_IMM_LSB_SHIFT;
	}

      char *f = s12z_new_insn (n_bytes);
      number_to_chars_bigendian (f++, insn->opc | Dd, 1);
      number_to_chars_bigendian (f++, sb, 1);

      if (n_bytes > 2)
	{
	  const uint8_t XB_IMM_MODE_BASE = 0x70;
	  uint8_t xb = XB_IMM_MODE_BASE | (imm >> 1);
	  number_to_chars_bigendian (f, xb, 1);
	}

      return true;
    }

  fail_line_pointer = input_line_pointer;
  return false;
}

#include <string.h>

static void
impute_shift_dir_and_type (const struct instruction *insn, short *type, short *dir)
{
  if (!insn || !insn->name || strlen (insn->name) < 3)
    {
      as_fatal (_("Malformed instruction name"));
    }

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
    }

  switch (insn->name[2])
    {
    case 'l':
      *dir = 1;
      break;
    case 'r':
      *dir = 0;
      break;
    default:
      as_fatal (_("Bad shift direction"));
    }
}

/* Shift instruction with a OPR operand */
static bool
shift_two_operand (const struct instruction *insn)
{
  char * const ilp = input_line_pointer;
  bool success = false;
  uint8_t sb = 0x34;
  uint8_t buffer[4];
  int n_opr_bytes = 0;
  expressionS exp;

  do
    {
      short dir = -1;
      short type = -1;
      impute_shift_dir_and_type (insn, &type, &dir);
      sb |= dir << 6;
      sb |= type << 7;

      int size = size_from_suffix (insn, 0);
      sb |= size - 1;

      if (!lex_opr (buffer, &n_opr_bytes, &exp, false))
        break;

      if (!lex_match (','))
        break;

      long imm = -1;
      if (!lex_imm (&imm, NULL))
        break;

      if (imm < 1 || imm > 2)
        break;

      if (imm == 2)
        sb |= 0x08;

      success = true;
    }
  while (0);

  if (success)
    {
      char *f = s12z_new_insn (2 + n_opr_bytes);
      number_to_chars_bigendian (f++, insn->opc, 1);
      number_to_chars_bigendian (f++, sb, 1);
      emit_opr (f, buffer, n_opr_bytes, &exp);
    }
  else
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
    }

  return success;
}

/* Shift instruction with a OPR operand */
static bool
shift_opr_imm (const struct instruction *insn)
{
  char *const saved_input_pointer = input_line_pointer;

  const uint8_t SB_BASE = 0x20;
  const uint8_t SB_IMM_FLAG_BIT3 = 0x08;
  const uint8_t SB_NON_REG_OPERAND = 0x10;
  const int DIR_SHIFT = 6;
  const int TYPE_SHIFT = 7;
  const uint8_t IMM_ENCODE_BASE = 0x70;
  const int IMM_ENCODE_SHIFT = 1;

  short dir = -1;
  short type = -1;
  impute_shift_dir_and_type (insn, &type, &dir);

  int dest_reg;
  if (!lex_reg_name (REG_BIT_Dn, &dest_reg) || !lex_match (','))
    goto fail;

  uint8_t first_operand_buf[4];
  int first_operand_size;
  expressionS first_operand_expr;
  if (!lex_opr (first_operand_buf, &first_operand_size, &first_operand_expr, false)
      || !lex_match (','))
    goto fail;

  long immediate_val;
  bool is_immediate = lex_imm (&immediate_val, NULL);

  uint8_t second_operand_buf[4];
  int second_operand_size = 0;
  expressionS second_operand_expr;
  if (!is_immediate
      && !lex_opr (second_operand_buf, &second_operand_size, &second_operand_expr, false))
    goto fail;

  int instruction_size = 2 + first_operand_size;
  uint8_t status_byte = SB_BASE;
  int size_suffix = size_from_suffix (insn, 0);
  if (size_suffix != -1)
    status_byte |= size_suffix - 1;

  status_byte |= (uint8_t) (dir << DIR_SHIFT);
  status_byte |= (uint8_t) (type << TYPE_SHIFT);

  bool is_special_imm = is_immediate && (immediate_val == 1 || immediate_val == 2);

  if (is_immediate)
    {
      if (is_special_imm)
        {
          if (immediate_val == 2)
            status_byte |= SB_IMM_FLAG_BIT3;
        }
      else
        {
          instruction_size++;
          status_byte |= SB_NON_REG_OPERAND;
          if (immediate_val % 2)
            status_byte |= SB_IMM_FLAG_BIT3;
        }
    }
  else
    {
      instruction_size += second_operand_size;
      status_byte |= SB_NON_REG_OPERAND;
    }

  char *out_buffer = s12z_new_insn (instruction_size);
  number_to_chars_bigendian (out_buffer++, insn->opc | dest_reg, 1);
  number_to_chars_bigendian (out_buffer++, status_byte, 1);
  out_buffer = emit_opr (out_buffer, first_operand_buf, first_operand_size, &first_operand_expr);

  if (is_immediate)
    {
      if (!is_special_imm)
        {
          uint8_t imm_byte = IMM_ENCODE_BASE | (uint8_t) (immediate_val >> IMM_ENCODE_SHIFT);
          number_to_chars_bigendian (out_buffer++, imm_byte, 1);
        }
    }
  else
    {
      emit_opr (out_buffer, second_operand_buf, second_operand_size, &second_operand_expr);
    }

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_input_pointer;
  return false;
}

/* Shift instruction with a register operand */
static bool
shift_reg (const struct instruction *insn)
{
  short dir = -1;
  short type = -1;

  impute_shift_dir_and_type (insn, &type, &dir);

  return lex_shift_reg_imm1 (insn, type, dir)
         || lex_shift_reg (insn, type, dir);
}

static bool
bm_regd_imm (const struct instruction *insn)
{
  char *const original_line_pointer = input_line_pointer;
  int Di;
  long imm;

  if (lex_reg_name (REG_BIT_Dn, &Di)
      && lex_match (',')
      && lex_imm (&imm, NULL))
    {
      uint8_t bm = (uint8_t) ((imm << 3) | Di);
      char *f = s12z_new_insn (2);
      number_to_chars_bigendian (f++, insn->opc, 1);
      number_to_chars_bigendian (f, bm, 1);
      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = original_line_pointer;
  return false;
}

static bool
bm_opr_reg(const struct instruction *insn)
{
    char * const ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;
    int Dn = 0;

    bool success = lex_opr(buffer, &n_opr_bytes, &exp, false)
                   && lex_match(',')
                   && lex_reg_name(REG_BIT_Dn, &Dn);

    if (!success)
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    const int size = size_from_suffix(insn, 0);
    const uint8_t bm = (uint8_t)((Dn << 4) | ((size - 1) << 2) | 0x81);

    char *f = s12z_new_insn(2 + n_opr_bytes);
    number_to_chars_bigendian(f, insn->opc, 1);
    number_to_chars_bigendian(f + 1, bm, 1);
    emit_opr(f + 2, buffer, n_opr_bytes, &exp);

    return true;
}


static bool
bm_opr_imm(const struct instruction *insn)
{
    char *const original_ilp = input_line_pointer;
    bool success = false;

    do
    {
        uint8_t buffer[4];
        int n_opr_bytes;
        expressionS exp;
        if (!lex_opr(buffer, &n_opr_bytes, &exp, false))
        {
            break;
        }

        if (!lex_match(','))
        {
            break;
        }

        long imm;
        if (!lex_imm(&imm, NULL))
        {
            break;
        }

        const int size = size_from_suffix(insn, 0);
        const long max_bit_index = (long)size * 8;

        if (imm < 0 || imm >= max_bit_index)
        {
            as_bad(_("Immediate operand %ld is inappropriate for size of instruction"), imm);
            break;
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

        bm |= (uint8_t)((imm & 0x07) << 4);
        bm |= (uint8_t)(imm >> 3);

        char *p = s12z_new_insn(2 + n_opr_bytes);
        number_to_chars_bigendian(p++, insn->opc, 1);
        number_to_chars_bigendian(p++, bm, 1);
        emit_opr(p, buffer, n_opr_bytes, &exp);

        success = true;
    } while (0);

    if (!success)
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_ilp;
    }

    return success;
}


static bool
bm_regd_reg (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Di = 0;
  int Dn = 0;

  if (!lex_reg_name (REG_BIT_Dn, &Di) || !lex_match (',') || !lex_reg_name (REG_BIT_Dn, &Dn))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  uint8_t bm = (uint8_t) ((Dn << 4) | 0x81);
  uint8_t xb = (uint8_t) (Di | 0xb8);

  char *f = s12z_new_insn (3);
  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, bm, 1);
  number_to_chars_bigendian (f++, xb, 1);

  return true;
}





static bool
bf_reg_opr_imm (const struct instruction *insn, short ie)
{
  char *const ilp = input_line_pointer;
  bool success = false;

  do
    {
      int Dd;
      if (!lex_reg_name (REG_BIT_Dn, &Dd))
        break;

      if (!lex_match (','))
        break;

      uint8_t buffer[4];
      int n_bytes;
      expressionS exp;
      if (!lex_opr (buffer, &n_bytes, &exp, false))
        break;

      if (!lex_match (','))
        break;

      long width;
      if (!lex_imm (&width, NULL))
        break;

      if (width < 0 || width > 31)
        {
          as_bad (_("Invalid width value for %s"), insn->name);
          break;
        }

      if (!lex_match (':'))
        break;

      long offset;
      if (!lex_constant (&offset))
        break;

      if (offset < 0 || offset > 31)
        {
          as_bad (_("Invalid offset value for %s"), insn->name);
          break;
        }

      uint8_t i1 = (uint8_t) (((uint8_t) width << 5) | (uint8_t) offset);

      int size = size_from_suffix (insn, 0);
      uint8_t bb = ie ? 0x80 : 0x00;
      bb |= 0x60;
      bb |= (uint8_t) ((size - 1) << 2);
      bb |= (uint8_t) (width >> 3);

      char *f = s12z_new_insn (4 + n_bytes);
      number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
      number_to_chars_bigendian (f++, (uint8_t) (0x08 | Dd), 1);
      number_to_chars_bigendian (f++, bb, 1);
      number_to_chars_bigendian (f++, i1, 1);

      emit_opr (f, buffer, n_bytes, &exp);

      success = true;
    }
  while (0);

  if (!success)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
    }

  return success;
}


static bool
bf_opr_reg_imm (const struct instruction *insn, short ie)
{
  char *const ilp = input_line_pointer;

  const long MAX_BITFIELD_PARAM = 31;
  const uint8_t WIDTH_I1_SHIFT = 5;
  const uint8_t WIDTH_BB_SHIFT = 3;
  const uint8_t IE_FLAG = 0x80;
  const uint8_t OPCODE_GROUP = 0x70;
  const uint8_t SIZE_SHIFT = 2;
  const uint8_t DS_REG_FLAG = 0x08;
  const int INSN_FIXED_LEN = 4;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  if (!lex_opr (buffer, &n_bytes, &exp, false))
    goto fail;

  if (!lex_match (','))
    goto fail;

  int Ds = 0;
  if (!lex_reg_name (REG_BIT_Dn, &Ds))
    goto fail;

  if (!lex_match (','))
    goto fail;

  long width;
  if (!lex_imm (&width, NULL))
    goto fail;

  if (width < 0 || width > MAX_BITFIELD_PARAM)
    {
      as_bad (_("Invalid width value for %s"), insn->name);
      goto fail;
    }

  if (!lex_match (':'))
    goto fail;

  long offset;
  if (!lex_constant (&offset))
    goto fail;

  if (offset < 0 || offset > MAX_BITFIELD_PARAM)
    {
      as_bad (_("Invalid offset value for %s"), insn->name);
      goto fail;
    }

  const uint8_t i1 = (uint8_t) ((width << WIDTH_I1_SHIFT) | offset);
  const int size = size_from_suffix (insn, 0);

  uint8_t bb = ie ? IE_FLAG : 0x00;
  bb |= OPCODE_GROUP;
  bb |= (uint8_t) ((size - 1) << SIZE_SHIFT);
  bb |= (uint8_t) (width >> WIDTH_BB_SHIFT);

  char *f = s12z_new_insn (INSN_FIXED_LEN + n_bytes);
  number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian (f++, (uint8_t) (DS_REG_FLAG | Ds), 1);
  number_to_chars_bigendian (f++, bb, 1);
  number_to_chars_bigendian (f++, i1, 1);

  emit_opr (f, buffer, n_bytes, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}



static bool
bf_reg_reg_imm (const struct instruction *insn, short ie)
{
  char * const original_ilp = input_line_pointer;
  bool success = false;

  do
    {
      int Dd = 0;
      if (!lex_reg_name (REG_BIT_Dn, &Dd))
        {
          break;
        }

      if (!lex_match (','))
        {
          break;
        }

      int Ds = 0;
      if (!lex_reg_name (REG_BIT_Dn, &Ds))
        {
          break;
        }

      if (!lex_match (','))
        {
          break;
        }

      long width;
      if (!lex_imm (&width, NULL))
        {
          break;
        }

      const long max_bitfield_val = 31;
      if (width < 0 || width > max_bitfield_val)
        {
          as_bad (_("Invalid width value for %s"), insn->name);
          break;
        }

      if (!lex_match (':'))
        {
          break;
        }

      long offset;
      if (!lex_constant (&offset))
        {
          break;
        }

      if (offset < 0 || offset > max_bitfield_val)
        {
          as_bad (_("Invalid offset value for %s"), insn->name);
          break;
        }

      const uint8_t opcode_base = 0x08;
      const uint8_t opcode_ie_flag = 0x80;
      const uint8_t opcode_format_flag = 0x20;

      uint8_t byte_1_op = opcode_base | (uint8_t) Dd;
      uint8_t byte_2_op = (ie ? opcode_ie_flag : 0)
                        | opcode_format_flag
                        | ((uint8_t) Ds << 2)
                        | (uint8_t) (width >> 3);
      uint8_t byte_3_op = ((uint8_t) width << 5) | (uint8_t) offset;

      char *buffer = s12z_new_insn (4);
      number_to_chars_bigendian (buffer++, PAGE2_PREBYTE, 1);
      number_to_chars_bigendian (buffer++, byte_1_op, 1);
      number_to_chars_bigendian (buffer++, byte_2_op, 1);
      number_to_chars_bigendian (buffer, byte_3_op, 1);

      success = true;
    }
  while (0);

  if (!success)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = original_ilp;
    }

  return success;
}

static bool
bf_reg_reg_reg (const struct instruction *insn ATTRIBUTE_UNUSED, short ie)
{
  static const unsigned int ALLOWED_DP_REGS =
    (0x01u << REG_D2) | (0x01u << REG_D3) |
    (0x01u << REG_D4) | (0x01u << REG_D5);

  char *const ilp = input_line_pointer;
  int Dd = 0;
  int Ds = 0;
  int Dp = 0;

  if (lex_reg_name (REG_BIT_Dn, &Dd) &&
      lex_match (',') &&
      lex_reg_name (REG_BIT_Dn, &Ds) &&
      lex_match (',') &&
      lex_reg_name (ALLOWED_DP_REGS, &Dp))
    {
      const uint8_t byte1 = 0x08 | (uint8_t) Dd;
      const uint8_t byte2 = (ie ? 0x80 : 0x00) | (uint8_t) (Ds << 2) | (uint8_t) Dp;

      char *f = s12z_new_insn (3);
      number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
      number_to_chars_bigendian (f++, byte1, 1);
      number_to_chars_bigendian (f++, byte2, 1);

      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
bf_opr_reg_reg (const struct instruction *insn, short ie)
{
  char *const initial_line_pointer = input_line_pointer;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  int Ds;
  int Dp;

  const unsigned int valid_dp_regs = (0x01u << REG_D2) |
                                     (0x01u << REG_D3) |
                                     (0x01u << REG_D4) |
                                     (0x01u << REG_D5);

  if (!lex_opr (buffer, &n_bytes, &exp, false) ||
      !lex_match (',') ||
      !lex_reg_name (REG_BIT_Dn, &Ds) ||
      !lex_match (',') ||
      !lex_reg_name (valid_dp_regs, &Dp))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_line_pointer;
      return false;
    }

  const int size = size_from_suffix (insn, 0);
  const uint8_t ie_field = ie ? 0x80 : 0x00;
  const uint8_t size_field = (size - 1) << 2;
  const uint8_t base_opcode = 0x50;

  const uint8_t byte2 = 0x08 | Ds;
  const uint8_t byte3 = ie_field | base_opcode | Dp | size_field;

  char *output_ptr = s12z_new_insn (3 + n_bytes);
  number_to_chars_bigendian (output_ptr++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian (output_ptr++, byte2, 1);
  number_to_chars_bigendian (output_ptr++, byte3, 1);

  emit_opr (output_ptr, buffer, n_bytes, &exp);

  return true;
}


static bool
bf_reg_opr_reg(const struct instruction *insn, short ie)
{
    char * const original_ilp = input_line_pointer;
    bool success = false;

    do
    {
        int Dd = 0;
        if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(','))
        {
            break;
        }

        uint8_t buffer[4];
        int n_bytes;
        expressionS exp;
        if (!lex_opr(buffer, &n_bytes, &exp, false) || !lex_match(','))
        {
            break;
        }

        int Dp = 0;
        static const unsigned int DP_REG_MASK = (0x01u << REG_D2) |
                                                (0x01u << REG_D3) |
                                                (0x01u << REG_D4) |
                                                (0x01u << REG_D5);
        if (!lex_reg_name(DP_REG_MASK, &Dp))
        {
            break;
        }

        const int size = size_from_suffix(insn, 0);
        const uint8_t bb = (ie ? 0x80 : 0x00) | 0x40 | (uint8_t)Dp | (uint8_t)((size - 1) << 2);

        char *f = s12z_new_insn(3 + n_bytes);
        if (f == NULL)
        {
            break;
        }

        number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
        f++;
        number_to_chars_bigendian(f, (uint8_t)(0x08 | Dd), 1);
        f++;
        number_to_chars_bigendian(f, bb, 1);
        f++;

        emit_opr(f, buffer, n_bytes, &exp);
        success = true;
    }
    while (0);

    if (!success)
    {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_ilp;
    }

    return success;
}



static bool
bfe_reg_reg_reg(const struct instruction *insn)
{
  assert(insn);
  return bf_reg_reg_reg(insn, 0);
}

static inline bool
bfi_reg_reg_reg(const struct instruction *insn)
{
    return bf_reg_reg_reg(insn, 1);
}

static bool
bfe_reg_reg_imm(const struct instruction *insn)
{
    const int bitfield_offset = 0;
    return bf_reg_reg_imm(insn, bitfield_offset);
}

static bool bfi_reg_reg_imm(const struct instruction *insn)
{
    return bf_reg_reg_imm(insn, true);
}


static inline bool bfe_reg_opr_reg(const struct instruction *insn)
{
    return bf_reg_opr_reg(insn, 0);
}

static bool
bfi_reg_opr_reg (const struct instruction *insn)
{
  if (!insn)
    {
      return false;
    }
  return bf_reg_opr_reg (insn, true);
}


static bool
bfe_opr_reg_reg(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return bf_opr_reg_reg(insn, 0);
}

static bool
bfi_opr_reg_reg (const struct instruction *insn)
{
  return insn && bf_opr_reg_reg (insn, 1);
}

static inline bool
bfe_reg_opr_imm(const struct instruction *insn)
{
    return bf_reg_opr_imm(insn, false);
}

#include <stdbool.h>

static inline bool bfi_reg_opr_imm(const struct instruction *insn)
{
    return bf_reg_opr_imm(insn, true);
}

static inline bool
bfe_opr_reg_imm (const struct instruction *insn)
{
  assert (insn);
  return bf_opr_reg_imm (insn, false);
}

static inline bool
bfi_opr_reg_imm  (const struct instruction *insn)
{
  return bf_opr_reg_imm (insn, true);
}




static bool
tb_reg_rel (const struct instruction *insn)
{
  char * const initial_ilp = input_line_pointer;

  int reg;
  if (!lex_reg_name (REG_BIT_Dn | REG_BIT_XY, &reg))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_ilp;
      return false;
    }

  if (!lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_ilp;
      return false;
    }

  bool long_displacement;
  expressionS exp;
  if (!lex_15_bit_offset (&long_displacement, &exp))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_ilp;
      return false;
    }

  uint8_t operand_byte;
  if (reg == REG_X)
    {
      operand_byte = 0x08;
    }
  else if (reg == REG_Y)
    {
      operand_byte = 0x09;
    }
  else
    {
      operand_byte = (uint8_t) reg;
    }

  typedef struct
  {
    const char *suffix;
    uint8_t code;
  } ConditionMap;
  static const ConditionMap conditions[] = {
    {"eq", 1}, {"pl", 2}, {"mi", 3}, {"gt", 4}, {"le", 5},
  };

  uint8_t condition_code = 0;
  const char *suffix = insn->name + 2;
  for (size_t i = 0; i < sizeof (conditions) / sizeof (conditions[0]); ++i)
    {
      if (startswith (suffix, conditions[i].suffix))
        {
          condition_code = conditions[i].code;
          break;
        }
    }
  operand_byte |= (condition_code << 4);

  gas_assert (insn->name[0] == 'd' || insn->name[0] == 't');
  if (insn->name[0] == 'd')
    {
      operand_byte |= 0x80;
    }

  const int insn_size = long_displacement ? 4 : 3;
  char *f = s12z_new_insn (insn_size);
  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, operand_byte, 1);

  emit_15_bit_offset (f, 4, &exp);

  return true;
}


static bool
tb_opr_rel (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  bool success = false;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp, exp2;
  bool long_displacement;

  do
    {
      if (!lex_opr (buffer, &n_bytes, &exp, false))
        {
          break;
        }

      if (!lex_match (','))
        {
          break;
        }

      if (!lex_15_bit_offset (&long_displacement, &exp2))
        {
          break;
        }

      uint8_t lb = 0x0C;

      static const struct
      {
        const char *suffix;
        uint8_t code;
      } condition_map[] = {
          {"ne", 0x00}, {"eq", 0x01}, {"pl", 0x02},
          {"mi", 0x03}, {"gt", 0x04}, {"le", 0x05}
      };

      const char *suffix = insn->name + 2;
      for (size_t i = 0; i < sizeof (condition_map) / sizeof (condition_map[0]); ++i)
        {
          if (startswith (suffix, condition_map[i].suffix))
            {
              lb |= (uint8_t) (condition_map[i].code << 4);
              break;
            }
        }

      if (insn->name[0] == 'd')
        {
          lb |= 0x80;
        }
      else
        {
          gas_assert (insn->name[0] == 't');
        }

      int size = size_from_suffix (insn, 0);
      lb |= (uint8_t) (size - 1);

      char *f = s12z_new_insn (n_bytes + (long_displacement ? 4 : 3));
      number_to_chars_bigendian (f++, insn->opc, 1);
      number_to_chars_bigendian (f++, lb, 1);
      f = emit_opr (f, buffer, n_bytes, &exp);

      emit_15_bit_offset (f, n_bytes + 4, &exp2);

      success = true;
    }
  while (0);

  if (!success)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
    }

  return success;
}




static bool
test_br_reg_reg_rel (const struct instruction *insn)
{
  char * const ilp = input_line_pointer;
  int Di = 0;
  int Dn = 0;
  bool long_displacement;
  expressionS exp;

  if (lex_reg_name (REG_BIT_Dn, &Di)
      && lex_match (',')
      && lex_reg_name (REG_BIT_Dn, &Dn)
      && lex_match (',')
      && lex_15_bit_offset (&long_displacement, &exp))
    {
      uint8_t bm = 0x81 | (uint8_t) (Dn << 4);
      uint8_t xb = 0xb8 | (uint8_t) Di;

      char *f = s12z_new_insn (long_displacement ? 5 : 4);
      number_to_chars_bigendian (f++, insn->opc, 1);
      number_to_chars_bigendian (f++, bm, 1);
      number_to_chars_bigendian (f++, xb, 1);

      emit_15_bit_offset (f, 5, &exp);

      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
test_br_opr_reg_rel (const struct instruction *insn)
{
  char * const saved_input_pointer = input_line_pointer;

  uint8_t operand_buffer[4];
  int operand_bytes;
  expressionS operand_exp;
  int reg_d_num = 0;
  bool long_displacement;
  expressionS offset_exp;

  if (lex_opr (operand_buffer, &operand_bytes, &operand_exp, false)
      && lex_match (',')
      && lex_reg_name (REG_BIT_Dn, &reg_d_num)
      && lex_match (',')
      && lex_15_bit_offset (&long_displacement, &offset_exp))
    {
      const uint8_t MODE_BYTE_BASE = 0x81;
      const int DN_SHIFT = 4;
      const int SIZE_SHIFT = 2;
      const int LONG_DISPLACEMENT_BYTES = 4;
      const int SHORT_DISPLACEMENT_BYTES = 3;

      uint8_t mode_byte = MODE_BYTE_BASE;
      mode_byte |= (uint8_t) reg_d_num << DN_SHIFT;

      int size = size_from_suffix (insn, 0);
      mode_byte |= (uint8_t) (size - 1) << SIZE_SHIFT;

      int displacement_bytes = long_displacement ? LONG_DISPLACEMENT_BYTES : SHORT_DISPLACEMENT_BYTES;
      int total_bytes = operand_bytes + displacement_bytes;

      char *write_ptr = s12z_new_insn (total_bytes);

      number_to_chars_bigendian (write_ptr++, insn->opc, 1);
      number_to_chars_bigendian (write_ptr++, mode_byte, 1);
      write_ptr = emit_opr (write_ptr, operand_buffer, operand_bytes, &operand_exp);

      emit_15_bit_offset (write_ptr, total_bytes, &offset_exp);

      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_input_pointer;
  return false;
}


static bool
test_br_opr_imm_rel (const struct instruction *insn)
{
  char *ilp = input_line_pointer;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  long imm;
  bool long_displacement;
  expressionS exp2;

  if (!lex_opr (buffer, &n_bytes, &exp, false)
      || !lex_match (',')
      || !lex_imm (&imm, NULL)
      || (imm < 0 || imm > 31)
      || !lex_match (',')
      || !lex_15_bit_offset (&long_displacement, &exp2))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  int size = size_from_suffix (insn, 0);

  uint8_t size_encoding = 0;
  if (size == 4)
    {
      size_encoding = 0x08;
    }
  else if (size == 2)
    {
      size_encoding = 0x02;
    }

  uint8_t imm_low_bits = (uint8_t) ((imm & 0x07) << 4);
  uint8_t imm_high_bits = (uint8_t) ((imm >> 3) & 0x03);

  uint8_t bm = 0x80 | imm_low_bits | imm_high_bits | size_encoding;

  int instruction_size = n_bytes + (long_displacement ? 4 : 3);
  char *f = s12z_new_insn (instruction_size);

  number_to_chars_bigendian (f, insn->opc, 1);
  f += 1;
  number_to_chars_bigendian (f, bm, 1);
  f += 1;

  f = emit_opr (f, buffer, n_bytes, &exp);

  emit_15_bit_offset (f, n_bytes + 4, &exp2);

  return true;
}


static bool
test_br_reg_imm_rel (const struct instruction *insn)
{
  char * const initial_pointer = input_line_pointer;
  int Di;
  long imm;
  bool long_displacement;
  expressionS exp;

  if (lex_reg_name (REG_BIT_Dn, &Di) &&
      lex_match (',') &&
      lex_imm (&imm, NULL) &&
      (imm >= 0 && imm <= 31) &&
      lex_match (',') &&
      lex_15_bit_offset (&long_displacement, &exp))
    {
      uint8_t bm = (uint8_t)Di | ((uint8_t)imm << 3);
      char *f = s12z_new_insn (long_displacement ? 4 : 3);

      number_to_chars_bigendian (f++, insn->opc, 1);
      number_to_chars_bigendian (f++, bm, 1);
      emit_15_bit_offset (f, 4, &exp);

      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = initial_pointer;
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
md_assemble (char *str)
{
  char *p = str;
  char name[20];
  size_t nlen = 0;

  fail_line_pointer = NULL;

  /* Find the opcode end and copy it to 'name' in lower case. */
  while (!is_end_of_stmt (*p) && !is_whitespace (*p))
    {
      if (nlen >= sizeof (name) - 1)
        {
          as_bad (_("Opcode is too long."));
          return;
        }
      name[nlen++] = TOLOWER (*p++);
    }
  name[nlen] = '\0';

  if (nlen == 0)
    {
      as_bad (_("No instruction or missing opcode."));
      return;
    }

  input_line_pointer = skip_whites (p);

  for (size_t i = 0; i < sizeof (opcodes) / sizeof (opcodes[0]); ++i)
    {
      const struct instruction *opc = opcodes + i;
      if (strcmp (name, opc->name) == 0)
        {
          if (opc->parse_operands (opc))
            {
              return;
            }
        }
    }

  as_bad (_("Invalid instruction: \"%s\""), str);
  as_bad (_("First invalid token: \"%s\""), fail_line_pointer);
  while (*input_line_pointer++)
    ;
}





/* Relocation, relaxation and frag conversions.  */

/* PC-relative offsets are relative to the start of the
   next instruction.  That is, the address of the offset, plus its
   size, since the offset is always the last part of the insn.  */
#include <assert.h>

long
md_pcrel_from (fixS *fixP)
{
  assert (fixP != NULL);
  assert (fixP->fx_frag != NULL);

  long ret = fixP->fx_size + fixP->fx_frag->fr_address;

  if (fixP->fx_addsy && S_IS_DEFINED (fixP->fx_addsy))
    {
      ret += fixP->fx_where;
    }

  return ret;
}


/* We need a port-specific relaxation function to cope with sym2 - sym1
   relative expressions with both symbols in the same segment (but not
   necessarily in the same frag as this insn), for example:
   ldab sym2-(sym1-2),pc
   sym1:
   The offset can be 5, 9 or 16 bits long.  */

long s12z_relax_frag(segT, fragS *, long)
{
    return 0;
}

void
md_convert_frag (bfd *abfd, asection *sec, fragS *fragP)
{
  (void) abfd;
  (void) sec;
  (void) fragP;
}

/* On an ELF system, we can't relax a weak symbol.  The weak symbol
   can be overridden at final link time by a non weak symbol.  We can
   relax externally visible symbol because there is no shared library
   and such symbol can't be overridden (unless they are weak).  */

/* Force truly undefined symbols to their maximum size, and generally set up
   the frag list to be relaxed.  */
int md_estimate_size_before_relax (fragS *fragP, asection *segment)
{
  (void) fragP;
  (void) segment;
  return 0;
}


/* If while processing a fixup, a reloc really needs to be created
   then it is done here.  */
arelent *
tc_gen_reloc (asection *section, fixS *fixp)
{
  arelent *reloc = notes_alloc (sizeof (arelent));
  if (!reloc)
    {
      return NULL;
    }

  reloc->sym_ptr_ptr = notes_alloc (sizeof (asymbol *));
  if (!reloc->sym_ptr_ptr)
    {
      return NULL;
    }

  reloc->howto = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  if (!reloc->howto)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
		    _("Relocation %d is not supported by object file format."),
		    (int) fixp->fx_r_type);
      return NULL;
    }

  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;
  reloc->addend = (section->flags & SEC_CODE)
                  ? fixp->fx_addnumber
                  : fixp->fx_offset;

  return reloc;
}

/* See whether we need to force a relocation into the output file.  */
int tc_s12z_force_relocation(fixS *fix)
{
    if (!fix)
    {
        return 1;
    }
    return generic_force_reloc(fix);
}

/* Here we decide which fixups can be adjusted to make them relative
   to the beginning of the section instead of the symbol.  Basically
   we need to make sure that the linker relaxation is done
   correctly, so in some cases we force the original symbol to be
   used.  */
#include <stdbool.h>

typedef struct fixS fixS;

// This is a forward declaration for a commonly used compiler attribute.
#ifndef ATTRIBUTE_UNUSED
#if defined(__GNUC__) || defined(__clang__)
#define ATTRIBUTE_UNUSED __attribute__((unused))
#else
#define ATTRIBUTE_UNUSED
#endif
#endif

bool tc_s12z_fix_adjustable(const fixS *fixP)
{
    (void)fixP; // Parameter is intentionally unused in this stub implementation.
    return true;
}

void
md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED)
{
  if (!fixP || !valP || !fixP->fx_frag)
    {
      as_fatal (_("Internal error: md_apply_fix called with NULL pointer."));
      return;
    }

  long value = *valP;

  if (fixP->fx_addsy == NULL)
    fixP->fx_done = 1;

  if (fixP->fx_subsy != NULL)
    as_bad_subtract (fixP);

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
          as_fatal (_("Line %d: unsupported size %d for relocation type 0x%x."),
                    fixP->fx_line, fixP->fx_size, fixP->fx_r_type);
        }
      break;
    case BFD_RELOC_32:
      bfd_putb32 (value, where);
      break;
    case BFD_RELOC_16_PCREL:
      {
        const long min_pcrel_val = -0x4000;
        const long max_pcrel_val = 0x3FFF;
        const unsigned int pcrel_flag = 0x8000;

        if (value < min_pcrel_val || value > max_pcrel_val)
          as_bad_where (fixP->fx_file, fixP->fx_line,
                        _("Value out of 16-bit range."));

        bfd_putb16 (value | pcrel_flag, where);
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
    (void)0;
}
