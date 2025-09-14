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
s12z_strtol (const char *str, char ** endptr)
{
  int base = 0;
  bool negative = false;
  long result;
  
  const char *original_str_start = str;
  const char *current_parse_pos = str;
  char *strtol_parse_end = NULL;

  if (*current_parse_pos == '-')
    {
      negative = true;
      current_parse_pos++;
    }
  else if (*current_parse_pos == '+')
    {
      current_parse_pos++;
    }

  if (literal_prefix_dollar_hex && (*current_parse_pos == '$'))
    {
      base = 16;
      current_parse_pos++;
    }

  result = strtol(current_parse_pos, &strtol_parse_end, base);

  if (endptr != NULL)
    {
      if (strtol_parse_end == current_parse_pos)
        {
          *endptr = (char *)original_str_start;
        }
      else
        {
          *endptr = strtol_parse_end;
        }
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
static const char * const S12Z_ARCH_FORMAT_STRING = "elf32-s12z";

const char *
s12z_arch_format (void)
{
  return S12Z_ARCH_FORMAT_STRING;
}

enum bfd_architecture
s12z_arch (void)
{
  return bfd_arch_s12z;
}

#define S12Z_MACH_SUCCESS 0
int
s12z_mach (void)
{
  return S12Z_MACH_SUCCESS;
}

/* Listing header selected according to cpu.  */
static const char S12Z_LISTING_HEADER_STRING[] = "S12Z GAS ";

const char *
s12z_listing_header (void)
{
  return S12Z_LISTING_HEADER_STRING;
}

void
md_show_usage (FILE *stream)
{
  if (stream == NULL) {
    return;
  }

  fputs (
    _("\ns12z options:\n"
      "  -mreg-prefix=PREFIX     set a prefix used to indicate register names (default none)\n"
      "  -mdollar-hex            the prefix '$' instead of '0x' is used to indicate literal hexadecimal constants\n"),
    stream
  );
}

void
s12z_print_statistics (FILE *)
{
}

int
md_parse_option (int c, const char *arg)
{
  switch (c)
    {
    case OPTION_REG_PREFIX:
      if (register_prefix != NULL)
        {
          free (register_prefix);
        }
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
  int align_bits = bfd_section_alignment (seg);
  valueT alignment_boundary = (valueT)1 << align_bits;
  return (addr + alignment_boundary - 1) & -alignment_boundary;
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


static char *
skip_whites(char *p)
{
  if (p == NULL) {
    return NULL;
  }

  while (isspace((unsigned char)*p)) {
    p++;
  }

  return p;
}



/* Start a new insn that contains at least 'size' bytes.  Record the
   line information of that insn in the dwarf2 debug sections.  */
static char *
s12z_new_insn (int size)
{
  if (size <= 0)
    return NULL;

  char *f = frag_more (size);

  if (f == NULL)
    return NULL;

  dwarf2_emit_insn (size);

  return f;
}



static bool lex_reg_name (uint16_t which, int *reg);

static bool
lex_constant (long *v)
{
  if (input_line_pointer == NULL)
    {
      return false;
    }

  char *current_input_pos = input_line_pointer;

  int dummy_reg_val;
  if (lex_reg_name (~0, &dummy_reg_val))
    {
      input_line_pointer = current_input_pos;
      return false;
    }

  char *parsing_end_ptr = NULL;
  errno = 0;

  *v = s12z_strtol (current_input_pos, &parsing_end_ptr);

  if (errno == 0 && parsing_end_ptr != current_input_pos)
    {
      input_line_pointer = parsing_end_ptr;
      return true;
    }

  return false;
}

static bool
lex_match (char x)
{
  if (input_line_pointer == NULL)
  {
    return false;
  }

  if (*input_line_pointer != x)
  {
    return false;
  }

  input_line_pointer++;
  return true;
}


static bool
lex_expression (expressionS *exp)
{
  char *ilp = input_line_pointer;
  int ignored_reg_value;
  bool result = false;

  exp->X_op = O_absent;

  do {
    if (lex_match ('#')) {
      break;
    }

    if (lex_reg_name (~0, &ignored_reg_value)) {
      break;
    }

    expression (exp);

    if (exp->X_op != O_absent) {
      result = true;
    }

  } while (0);

  if (!result) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
  }

  return result;
}

/* Immediate operand.
   If EXP_O is non-null, then a symbolic expression is permitted,
   in which case, EXP_O will be populated with the parsed expression.
 */
static bool
lex_imm (long *v, expressionS *exp_o)
{
  char *original_input_line_pointer = input_line_pointer;

  if (*input_line_pointer != '#')
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  input_line_pointer++;

  expressionS exp;
  if (!lex_expression (&exp))
    {
      input_line_pointer = original_input_line_pointer;
      return false;
    }

  if (exp.X_op != O_constant)
    {
      if (!exp_o)
        {
          as_bad (_("A non-constant expression is not permitted here"));
          fail_line_pointer = input_line_pointer;
          input_line_pointer = original_input_line_pointer;
          return false;
        }
      else
        {
          *exp_o = exp;
        }
    }

  *v = exp.X_add_number;
  return true;
}

/* Short mmediate operand */
static const long IMM_E4_SPECIAL_VALUE = -1L;
static const long IMM_E4_MIN_VALID = 1L;
static const long IMM_E4_MAX_VALID = 15L;

static bool
lex_imm_e4 (long *val)
{
  char *original_input_pointer = input_line_pointer;

  if (lex_imm(val, NULL)) {
    if (*val == IMM_E4_SPECIAL_VALUE || (*val >= IMM_E4_MIN_VALID && *val <= IMM_E4_MAX_VALID)) {
      return true;
    }
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_pointer;
    return false;
  }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = original_input_pointer;
  return false;
}

static bool
lex_match_string (const char *s)
{
  if (input_line_pointer == NULL || s == NULL)
    {
      return false;
    }

  const char *start_of_token = input_line_pointer;
  const char *p = start_of_token;

  while (*p != '\0' && !is_whitespace (*p) && !is_end_of_stmt (*p))
    {
      p++;
    }

  size_t token_len = p - start_of_token;
  size_t s_len = strlen (s);

  if (token_len != s_len)
    {
      return false;
    }

  if (strncasecmp (s, start_of_token, token_len) == 0)
    {
      input_line_pointer = (char *)p;
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
lex_reg_name (uint16_t which, int *reg)
{
  char *current_pos = input_line_pointer;

  if (current_pos == NULL)
    return false;

  /* Scan (and ignore) the register prefix.  */
  if (register_prefix != NULL)
    {
      size_t prefix_len = strlen(register_prefix);
      if (prefix_len > 0)
        {
          if (0 == strncmp(register_prefix, current_pos, prefix_len))
            {
              current_pos += prefix_len;
            }
          else
            {
              return false;
            }
        }
    }

  char *start_of_reg_name = current_pos;

  // Scan for alphanumeric characters, safely handling character type for isalnum
  while (isalnum((unsigned char)*current_pos))
    {
      current_pos++;
    }

  size_t reg_name_len = current_pos - start_of_reg_name;

  if (reg_name_len == 0) // No register name found
    return false;

  for (int i = 0; i < S12Z_N_REGISTERS; ++i)
    {
      gas_assert (registers[i].name); // Assertion for internal data integrity

      size_t entry_name_len = strlen(registers[i].name);

      if (reg_name_len == entry_name_len
	  && 0 == strncasecmp (registers[i].name, start_of_reg_name, reg_name_len))
	{
	  if ((0x1U << i) & which)
	    {
	      input_line_pointer = current_pos; // Update the global pointer
	      *reg = i;
	      return true;
	    }
	}
    }

  return false;
}

static bool
lex_force_match (char x)
{
  if (input_line_pointer == NULL)
    {
      as_bad (_("Internal lexer error: input stream is null."));
      return false;
    }

  if (*input_line_pointer != x)
    {
      as_bad (_("Expecting '%c' but got '%c'"), x, *input_line_pointer);
      return false;
    }

  input_line_pointer++;
  return true;
}

static bool local_lex_opr_fail(char *original_input_line_pointer);
static void write_multi_byte_value(uint8_t *buffer, int start_idx, int num_bytes, long value);
static bool handle_indexed_expr_reg(uint8_t *buffer, int *n_bytes, expressionS *exp, int reg);
static bool handle_indexed_expr_abs(uint8_t *buffer, int *n_bytes, expressionS *exp);
static bool handle_indexed_dn_xy(uint8_t *buffer, int *n_bytes, int reg_dn);
static bool parse_indexed_operand(uint8_t *buffer, int *n_bytes, expressionS *exp, char *ilp);
static bool handle_parenthesized_const_reg(uint8_t *buffer, int *n_bytes, long c, int reg);
static bool handle_parenthesized_const_dn(uint8_t *buffer, int *n_bytes, long c, int reg);
static bool handle_parenthesized_dn_reg(uint8_t *buffer, int *n_bytes, int reg_dn);
static bool handle_parenthesized_post_inc_dec(uint8_t *buffer, int *n_bytes, int reg, char op_char);
static bool handle_parenthesized_pre_inc(uint8_t *buffer, int *n_bytes, int reg);
static bool handle_parenthesized_pre_dec(uint8_t *buffer, int *n_bytes, int reg);
static bool parse_parenthesized_operand(uint8_t *buffer, int *n_bytes, expressionS *exp, char *ilp);
static bool handle_expression_operand(uint8_t *buffer, int *n_bytes, expressionS *exp);


static bool
local_lex_opr_fail(char *original_input_line_pointer)
{
  fail_line_pointer = input_line_pointer;
  input_line_pointer = original_input_line_pointer;
  return false;
}

static void
write_multi_byte_value(uint8_t *buffer, int start_idx, int num_bytes, long value)
{
  for (int i = 0; i < num_bytes; ++i)
    {
      buffer[start_idx + i] = (uint8_t)(value >> (8 * (num_bytes - 1 - i)));
    }
}

static bool
handle_indexed_expr_reg(uint8_t *buffer, int *n_bytes, expressionS *exp, int reg)
{
  long c = exp->X_add_number;

  if (c >= -256 && c <= 255)
    {
      *n_bytes = 2;
      *buffer |= 0xc4;
    }
  else
    {
      *n_bytes = 4;
      *buffer |= 0xc6;
    }

  *buffer |= (uint8_t)((reg - REG_X) << 4);

  if (c < 0)
    *buffer |= 0x01;
  
  write_multi_byte_value(buffer, 1, *n_bytes - 1, c);
  return true;
}

static bool
handle_indexed_expr_abs(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
  long c = exp->X_add_number;
  *buffer = 0xfe;
  *n_bytes = 4;
  write_multi_byte_value(buffer, 1, 3, c);
  return true;
}

static bool
handle_indexed_dn_xy(uint8_t *buffer, int *n_bytes, int reg_dn)
{
  int reg_xy;
  if (!lex_force_match (','))
    return false;

  if (lex_reg_name (REG_BIT_XY, &reg_xy))
    {
      *n_bytes = 1;
      *buffer = (uint8_t)reg_dn;
      *buffer |= (uint8_t)((reg_xy - REG_X) << 4);
      *buffer |= 0xc8;
      return true;
    }
  else
    {
      as_bad (_("Invalid operand for register offset"));
      return false;
    }
}

static bool
parse_indexed_operand(uint8_t *buffer, int *n_bytes, expressionS *exp, char *ilp)
{
  bool success = true;
  if (lex_expression(exp))
    {
      if (lex_match (','))
	{
	  int reg;
	  if (lex_reg_name (REG_BIT_XYSP, &reg))
	    {
	      success = handle_indexed_expr_reg(buffer, n_bytes, exp, reg);
	    }
	  else
	    {
	      as_bad (_("Bad operand for constant offset"));
	      success = false;
	    }
	}
      else
	{
	  success = handle_indexed_expr_abs(buffer, n_bytes, exp);
	}
    }
  else
    {
      int reg_dn;
      if (lex_reg_name (REG_BIT_Dn, &reg_dn))
	{
	  success = handle_indexed_dn_xy(buffer, n_bytes, reg_dn);
	}
      else
	{
	  success = false;
	}
    }

  if (!success)
    return local_lex_opr_fail(ilp);

  if (!lex_force_match (']'))
    return local_lex_opr_fail(ilp);
  return true;
}

static bool
handle_parenthesized_const_reg(uint8_t *buffer, int *n_bytes, long c, int reg)
{
  if (reg != REG_P && c >= 0 && c <= 15)
    {
      *n_bytes = 1;
      *buffer = 0x40;
      *buffer |= (uint8_t)((reg - REG_X) << 4);
      *buffer |= (uint8_t)c;
    }
  else if (c >= -256 && c <= 255)
    {
      *n_bytes = 2;
      *buffer = 0xc0;
      *buffer |= (uint8_t)((reg - REG_X) << 4);
      if (c < 0)
	*buffer |= 0x01;
      buffer[1] = (uint8_t)c;
    }
  else
    {
      *n_bytes = 4;
      *buffer = 0xc2;
      *buffer |= (uint8_t)((reg - REG_X) << 4);
      write_multi_byte_value(buffer, 1, 3, c);
    }
  return true;
}

static bool
handle_parenthesized_const_dn(uint8_t *buffer, int *n_bytes, long c, int reg)
{
  if (c >= -1 * (1L << 17) && c < (1L << 17))
    {
      *n_bytes = 3;
      *buffer = 0x80;
      *buffer |= (uint8_t)reg;
      *buffer |= (uint8_t)(((c >> 16) & 0x03) << 4);
      write_multi_byte_value(buffer, 1, 2, c);
    }
  else
    {
      *n_bytes = 4;
      *buffer = 0xe8;
      *buffer |= (uint8_t)reg;
      write_multi_byte_value(buffer, 1, 3, c);
    }
  return true;
}

static bool
handle_parenthesized_dn_reg(uint8_t *buffer, int *n_bytes, int reg_dn)
{
  int reg_xys;
  if (lex_reg_name (REG_BIT_XYS, &reg_xys))
    {
      *n_bytes = 1;
      *buffer = 0x88;
      *buffer |= (uint8_t)((reg_xys - REG_X) << 4);
      *buffer |= (uint8_t)reg_dn;
      return true;
    }
  else
    {
      as_bad (_("Invalid operand for register offset"));
      return false;
    }
}

static bool
handle_parenthesized_post_inc_dec(uint8_t *buffer, int *n_bytes, int reg, char op_char)
{
  if (op_char == '-')
    {
      if (reg == REG_S)
	{
	  as_bad (_("Invalid register for postdecrement operation"));
	  return false;
	}
      *n_bytes = 1;
      if (reg == REG_X) *buffer = 0xc7;
      else if (reg == REG_Y) *buffer = 0xd7;
    }
  else if (op_char == '+')
    {
      *n_bytes = 1;
      if (reg == REG_X) *buffer = 0xe7;
      else if (reg == REG_Y) *buffer = 0xf7;
      else if (reg == REG_S) *buffer = 0xff;
    }
  return true;
}

static bool
handle_parenthesized_pre_inc(uint8_t *buffer, int *n_bytes, int reg)
{
  *n_bytes = 1;
  if (reg == REG_X) *buffer = 0xe3;
  else if (reg == REG_Y) *buffer = 0xf3;
  return true;
}

static bool
handle_parenthesized_pre_dec(uint8_t *buffer, int *n_bytes, int reg)
{
  *n_bytes = 1;
  if (reg == REG_X) *buffer = 0xc3;
  else if (reg == REG_Y) *buffer = 0xd3;
  else if (reg == REG_S) *buffer = 0xfb;
  return true;
}

static bool
parse_parenthesized_operand(uint8_t *buffer, int *n_bytes, expressionS *exp, char *ilp)
{
  bool success = false;
  long c;
  int reg;

  if (lex_constant (&c))
    {
      if (!lex_force_match (','))
	return local_lex_opr_fail(ilp);
      int reg2;
      if (lex_reg_name (REG_BIT_XYSP, &reg2))
	{
	  success = handle_parenthesized_const_reg(buffer, n_bytes, c, reg2);
	}
      else if (lex_reg_name (REG_BIT_Dn, &reg2))
	{
	  success = handle_parenthesized_const_dn(buffer, n_bytes, c, reg2);
	}
      else
	{
	  as_bad (_("Bad operand for constant offset"));
	  success = false;
	}
    }
  else if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      if (lex_match (','))
	{
	  success = handle_parenthesized_dn_reg(buffer, n_bytes, reg);
	}
      else
	{
	  success = false;
	}
    }
  else if (lex_reg_name (REG_BIT_XYS, &reg))
    {
      if (lex_match ('-'))
	{
	  success = handle_parenthesized_post_inc_dec(buffer, n_bytes, reg, '-');
	}
      else if (lex_match ('+'))
	{
	  success = handle_parenthesized_post_inc_dec(buffer, n_bytes, reg, '+');
	}
      else
	{
	  success = false;
	}
    }
  else if (lex_match ('+'))
    {
      if (lex_reg_name (REG_BIT_XY, &reg))
	{
	  success = handle_parenthesized_pre_inc(buffer, n_bytes, reg);
	}
      else
	{
	  as_bad (_("Invalid register for preincrement operation"));
	  success = false;
	}
    }
  else if (lex_match ('-'))
    {
      if (lex_reg_name (REG_BIT_XYS, &reg))
	{
	  success = handle_parenthesized_pre_dec(buffer, n_bytes, reg);
	}
      else
	{
	  as_bad (_("Invalid register for predecrement operation"));
	  success = false;
	}
    }
  else
    {
      success = false;
    }

  if (!success)
    return local_lex_opr_fail(ilp);

  if (!lex_match (')'))
    return local_lex_opr_fail(ilp);
  return true;
}

static bool
handle_expression_operand(uint8_t *buffer, int *n_bytes, expressionS *exp)
{
  *buffer = 0xfa;
  *n_bytes = 4;
  buffer[1] = 0;
  buffer[2] = 0;
  buffer[3] = 0;

  if (exp->X_op == O_constant)
    {
      valueT value = exp->X_add_number;

      if (value < (0x1U << 14))
	{
	  *buffer = (uint8_t)(value >> 8);
	  *buffer |= 0x00;
	  *n_bytes = 2;
	  buffer[1] = (uint8_t)value;
	}
      else if (value < (0x1U << 19))
	{
	  *buffer = 0xf8;
	  if (value & (0x1U << 17))
		*buffer |= 0x04;
	  if (value & (0x1U << 16))
		*buffer |= 0x01;
	  *n_bytes = 3;
	  write_multi_byte_value(buffer, 1, 2, value);
	}
      else
	{
	  *buffer = 0xfa;
	  *n_bytes = 4;
	  write_multi_byte_value(buffer, 1, 3, value);
	}
    }
  return true;
}


static bool
lex_opr (uint8_t *buffer, int *n_bytes, expressionS *exp,
	 bool immediate_ok)
{
  char *ilp = input_line_pointer;
  int reg;
  long imm;

  exp->X_op = O_absent;
  *n_bytes = 0;
  *buffer = 0;

  if (lex_imm_e4 (&imm))
    {
      if (!immediate_ok)
	{
	  as_bad (_("An immediate value in a source operand is inappropriate"));
	  return local_lex_opr_fail(ilp);
	}
      *buffer = (uint8_t)(imm > 0 ? imm : 0);
      *buffer |= 0x70;
      *n_bytes = 1;
      return true;
    }
  else if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      *buffer = (uint8_t)reg;
      *buffer |= 0xb8;
      *n_bytes = 1;
      return true;
    }
  else if (lex_match ('['))
    {
      return parse_indexed_operand(buffer, n_bytes, exp, ilp);
    }
  else if (lex_match ('('))
    {
      return parse_parenthesized_operand(buffer, n_bytes, exp, ilp);
    }
  else if (lex_expression (exp))
    {
      return handle_expression_operand(buffer, n_bytes, exp);
    }

  return local_lex_opr_fail(ilp);
}

static bool
lex_offset (long *val)
{
  // Assume input_line_pointer is a globally accessible char*
  // It's a legacy system, so direct access is retained as per "without altering its external functionality".

  char *p = input_line_pointer;
  char *end = NULL;
  long parsed_val;

  // Basic validation: ensure input_line_pointer is not NULL or empty before dereferencing
  if (p == NULL || *p == '\0') {
    return false;
  }

  // Check for leading '*'
  if (*p != '*') {
    return false;
  }
  p++; // Move past '*'

  // After '*', ensure there's at least a sign character
  if (*p == '\0') {
    return false;
  }

  // Check for sign '+' or '-'
  if (*p != '+' && *p != '-') {
    return false;
  }

  bool negative = (*p == '-');
  p++; // Move past sign

  // After sign, ensure there's at least one digit
  if (*p == '\0') {
    return false;
  }

  // Clear errno before calling s12z_strtol to reliably detect errors
  errno = 0;
  parsed_val = s12z_strtol(p, &end);

  // Check for conversion errors:
  // 1. errno indicates overflow/underflow (ERANGE) or other issues.
  // 2. end == p indicates no digits were parsed (e.g., "*+abc" would parse "abc" as 0,
  //    but end would still point to 'a', meaning no numeric conversion occurred from 'p').
  if (errno != 0 || end == p) {
    return false;
  }

  // Apply the sign. s12z_strtol likely parses the absolute value since 'p' points after the sign.
  if (negative) {
    parsed_val *= -1;
  }

  // Update the output value
  *val = parsed_val;

  // Update the global input_line_pointer to reflect consumed input
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
  if (f == NULL)
    {
      as_bad (_("Failed to allocate instruction buffer."));
      return false;
    }

  if (insn->page == 2)
    number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);

  number_to_chars_bigendian (f++, insn->opc, 1);

  return true;
}


static void
emit_reloc (expressionS *exp, char *f, int size, enum bfd_reloc_code_real reloc)
{
  if (exp->X_op != O_absent && exp->X_op != O_constant)
    {
      fixS *fix = fix_new_exp (frag_now,
			       f - frag_now->fr_literal,
			       size,
			       exp,
			       false,
                               reloc);
      fix->fx_addnumber = 0x00;
    }
}

/* Emit the code for an OPR address mode operand */
#define S12Z_OPR_OPERAND_SIZE 3

static char *
emit_opr (char *f, const uint8_t *buffer, int n_bytes, expressionS *exp)
{
  if (f == NULL || buffer == NULL) {
    return NULL;
  }

  if (n_bytes <= 0) {
    return f;
  }

  number_to_chars_bigendian(f++, buffer[0], 1);

  emit_reloc(exp, f, S12Z_OPR_OPERAND_SIZE, BFD_RELOC_S12Z_OPR);

  for (int i = 1; i < n_bytes; ++i) {
    number_to_chars_bigendian(f++, buffer[i], 1);
  }

  return f;
}

/* Emit the code for a 24 bit direct address operand */
#include <stddef.h>
#include <assert.h>

#define EXT24_BYTE_COUNT 3

static char *
emit_ext24 (char *f, long v)
{
  assert(f != NULL);

  number_to_chars_bigendian (f, v, EXT24_BYTE_COUNT);

  return f + EXT24_BYTE_COUNT;
}

static inline bool
should_use_ext24_optimization(const expressionS *exp, const uint8_t *buffer, const struct instruction *insn)
{
  return exp->X_op == O_constant && buffer[0] == 0xFA && insn->alt_opc != 0;
}

static bool
opr (const struct instruction *insn)
{
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  char *instruction_buffer = NULL;

  if (!lex_opr (buffer, &n_bytes, &exp, false))
    {
      return false;
    }

  if (should_use_ext24_optimization(&exp, buffer, insn))
    {
      gas_assert (insn->page == 1);

      instruction_buffer = s12z_new_insn (4);
      if (instruction_buffer == NULL)
        {
          return false;
        }

      number_to_chars_bigendian (instruction_buffer++, insn->alt_opc, 1);
      emit_ext24 (instruction_buffer, exp.X_add_number);
    }
  else
    {
      instruction_buffer = s12z_new_insn (n_bytes + 1);
      if (instruction_buffer == NULL)
        {
          return false;
        }

      number_to_chars_bigendian (instruction_buffer++, insn->opc, 1);
      emit_opr (instruction_buffer, buffer, n_bytes, &exp);
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
  bool val_is_constant_and_parsed = false;

  exp->X_op = O_absent;
  exp->X_add_number = 0;

  if (lex_offset (&val))
    {
      exp->X_add_number = val;
      val_is_constant_and_parsed = true;
    }
  else if (lex_expression (exp))
    {
      if (exp->X_op == O_constant)
	    {
	      val = exp->X_add_number;
	      val_is_constant_and_parsed = true;
	    }
      else
	    {
	      *long_displacement = true;
	      return true;
	    }
    }
  else
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  if (val_is_constant_and_parsed)
    {
      if (val > 0x3FFF || val < -0x4000)
        {
          as_fatal (_("Offset is outside of 15 bit range"));
          return false;
        }

      *long_displacement = (val > 63 || val < -64);
    }

  return true;
}

static void
emit_15_bit_offset (char *f, int where, expressionS *exp)
{
  gas_assert (exp);

  if (exp->X_op != O_absent && exp->X_op != O_constant)
    {
      exp->X_add_number += where;
      fixS *fix = fix_new_exp (frag_now,
                               f - frag_now->fr_literal,
                               2,
                               exp,
                               true,
                               BFD_RELOC_16_PCREL);
      fix->fx_addnumber = where - 2;
    }
  else
    {
      long val = exp->X_add_number;
      bool is_long_displacement = (val > 63 || val < -64);

      if (is_long_displacement)
        {
          val |= 0x8000;
        }
      else
        {
          val &= 0x7F;
        }

      int size_to_write = is_long_displacement ? 2 : 1;
      number_to_chars_bigendian (f, val, size_to_write);
    }
}

static bool
rel(const struct instruction *insn)
{
  bool long_displacement;
  expressionS exp;

  if (!lex_15_bit_offset(&long_displacement, &exp)) {
    return false;
  }

  const size_t opcode_size_bytes = 1;
  const size_t short_insn_total_size_bytes = 2;
  const size_t long_insn_total_size_bytes = 3;

  const size_t offset_size_bytes_short = short_insn_total_size_bytes - opcode_size_bytes;
  const size_t offset_size_bytes_long = long_insn_total_size_bytes - opcode_size_bytes;

  const size_t total_instruction_size_bytes = long_displacement ? long_insn_total_size_bytes : short_insn_total_size_bytes;
  const size_t offset_size_bytes = long_displacement ? offset_size_bytes_long : offset_size_bytes_short;

  char *instruction_buffer = s12z_new_insn(total_instruction_size_bytes);
  if (instruction_buffer == NULL) {
    return false;
  }

  char *current_write_ptr = instruction_buffer;

  number_to_chars_bigendian(current_write_ptr, insn->opc, opcode_size_bytes);
  current_write_ptr += opcode_size_bytes;

  emit_15_bit_offset(current_write_ptr, offset_size_bytes, &exp);

  return true;
}

#include <stdbool.h>

#define ONE_BYTE_SIZE 1

static bool
reg_inh (const struct instruction *insn)
{
  int reg_value;

  if (!lex_reg_name (REG_BIT_Dn, &reg_value))
    {
      return false;
    }

  char *insn_buffer = s12z_new_insn (insn->page);
  if (insn_buffer == NULL)
    {
      return false;
    }

  char *current_write_ptr = insn_buffer;

  if (insn->page == 2)
    {
      number_to_chars_bigendian (current_write_ptr, PAGE2_PREBYTE, ONE_BYTE_SIZE);
      current_write_ptr += ONE_BYTE_SIZE;
    }

  number_to_chars_bigendian (current_write_ptr, insn->opc + reg_value, ONE_BYTE_SIZE);

  return true;
}


/* Special case for CLR X and CLR Y */
static bool
clr_xy (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  int reg;
  if (lex_reg_name (REG_BIT_XY, &reg))
    {
      char *instruction_buffer = s12z_new_insn (1);
      if (instruction_buffer == NULL)
        {
          return false;
        }

      unsigned char opcode_byte = (unsigned char)(0x9a + reg - REG_X);
      number_to_chars_bigendian (instruction_buffer, opcode_byte, 1);
      return true;
    }

  return false;
}

/* Some instructions have a suffix like ".l", ".b", ".w" etc
   which indicates the size of the operands. */
#include <string.h> // Required for strchr and strlen
// Assuming as_fatal and _ are defined elsewhere and accessible.
// as_fatal is assumed to be a noreturn function that terminates the program.

// Define symbolic constants for error codes to improve maintainability and readability.
#define SIZE_ERROR_INVALID_INPUT         -1
#define SIZE_ERROR_INVALID_SUFFIX_CHAR   -2
#define SIZE_ERROR_NO_DOT                -3
#define SIZE_ERROR_SUFFIX_OUT_OF_BOUNDS  -4

// Forward declaration for struct instruction if not in a header.
// Assuming it has a const char *name member.
// struct instruction {
//   const char *name;
//   // ... other members
// };


static int
size_from_suffix  (const struct instruction *insn, int idx)
{
  // 1. Input Validation: Check for NULL pointers to prevent crashes (reliability, security).
  if (insn == NULL || insn->name == NULL)
    {
      return SIZE_ERROR_INVALID_INPUT;
    }

  const char *name_str = insn->name;
  const char *dot_ptr = strchr (name_str, '.');

  // 2. Handle the case where no dot character is found (as per original logic).
  if (dot_ptr == NULL)
    {
      return SIZE_ERROR_NO_DOT;
    }

  // Calculate the pointer to the character that determines the size.
  // The original logic `dot[1 + idx]` means `*(dot_ptr + 1 + idx)`.
  // `1 + idx` is the offset from the dot character, where `idx` is an offset
  // from the first character *after* the dot.
  const char *size_char_ptr = dot_ptr + 1 + idx;

  // 3. Robustness check for out-of-bounds access for `size_char_ptr`.
  // This addresses potential buffer over-reads (reliability, security).
  // Conditions for out-of-bounds:
  // a) `idx` is negative, causing `size_char_ptr` to point before `dot_ptr + 1`
  //    (e.g., `idx = -1` means `size_char_ptr` points to the `.` itself, `idx = -2` means before `.` which is unsafe).
  // b) `size_char_ptr` points to or past the null terminator of `name_str`.
  //    `*size_char_ptr == '\0'` covers cases where `size_char_ptr` is at or beyond the end of the string.
  if (idx < 0 || *size_char_ptr == '\0')
    {
      return SIZE_ERROR_SUFFIX_OUT_OF_BOUNDS;
    }

  // Initialize `size_val` with a default error value.
  int size_val = SIZE_ERROR_INVALID_SUFFIX_CHAR;

  // 4. Determine size based on the character after the dot.
  switch (*size_char_ptr)
    {
    case 'b':
      size_val = 1;
      break;
    case 'w':
      size_val = 2;
      break;
    case 'p':
      size_val = 3;
      break;
    case 'l':
      size_val = 4;
      break;
    default:
      // Preserve the original behavior: call as_fatal for "Bad size".
      // This implies `as_fatal` is a noreturn function that terminates the program,
      // meaning execution will not proceed past this point in this specific path.
      as_fatal (_("Bad size"));
      // No `return` statement needed here, as `as_fatal` is assumed to terminate.
    };

  // Return the determined size or the default error if no match was found (and as_fatal wasn't called).
  // This return is only reached if a valid suffix character ('b','w','p','l') was found.
  return size_val;
}

static const uint8_t MUL_SIGNED_FLAG = 0x80;
static const uint8_t MUL_UNSIGNED_FLAG = 0x00;
static const unsigned int MUL_REG_SHIFT_BITS = 3;

static bool
mul_reg_reg_reg (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;

  int Dd, Dj, Dk;

  #define PARSE_OR_FAIL(parsing_expr) \
    do { \
      if (!(parsing_expr)) { \
        fail_line_pointer = input_line_pointer; \
        input_line_pointer = original_input_line_pointer; \
        return false; \
      } \
    } while (0)

  PARSE_OR_FAIL(lex_reg_name (REG_BIT_Dn, &Dd));
  PARSE_OR_FAIL(lex_match (','));
  PARSE_OR_FAIL(lex_reg_name (REG_BIT_Dn, &Dj));
  PARSE_OR_FAIL(lex_match (','));
  PARSE_OR_FAIL(lex_reg_name (REG_BIT_Dn, &Dk));

  #undef PARSE_OR_FAIL

  char *output_ptr = s12z_new_insn (insn->page + 1);

  if (insn->page == 2)
  {
    output_ptr = number_to_chars_bigendian (output_ptr, PAGE2_PREBYTE, 1);
  }

  output_ptr = number_to_chars_bigendian (output_ptr, insn->opc + Dd, 1);

  const char *dot_pos = strchr (insn->name, '.');
  uint8_t mb_flags;

  if (dot_pos == NULL || dot_pos == insn->name)
  {
    as_fatal (_("Malformed MUL instruction name: Expected format 'MUL.S' or 'MUL.U'"));
  }

  switch (*(dot_pos - 1))
  {
    case 's':
      mb_flags = MUL_SIGNED_FLAG;
      break;
    case 'u':
      mb_flags = MUL_UNSIGNED_FLAG;
      break;
    default:
      as_fatal (_("Unsupported MUL instruction type: Use '.S' for signed or '.U' for unsigned."));
      break;
  }

  mb_flags |= (uint8_t)(Dj << MUL_REG_SHIFT_BITS);
  mb_flags |= (uint8_t)Dk;

  output_ptr = number_to_chars_bigendian (output_ptr, mb_flags, 1);

  return true;
}


#define MB_BASE_VALUE        0x44
#define MB_SIGNED_MASK       0x80
#define MB_REG_SHIFT         3

static bool
mul_reg_reg_imm (const struct instruction *insn)
{
  char *original_ilp = input_line_pointer; // Store for backtracking

  int Dd;
  int Dj;
  long imm;

  // 1. Parse operands
  if (!lex_reg_name(REG_BIT_Dn, &Dd)) goto fail;
  if (!lex_match(',')) goto fail;
  if (!lex_reg_name(REG_BIT_Dn, &Dj)) goto fail;
  if (!lex_match(',')) goto fail;
  if (!lex_imm(&imm, NULL)) goto fail;

  // 2. Determine instruction size and allocate buffer
  int size = size_from_suffix(insn, 0);
  // Assuming 'size' typically represents byte length (1, 2, 3, or 4).
  if (size <= 0 || size > 4) {
    as_fatal(_("Invalid instruction size derived from suffix. Expected 1, 2, 3, or 4 bytes."));
    goto fail;
  }

  // Calculate total bytes needed for the instruction encoding.
  // Page 2 instructions require an additional prebyte.
  int total_bytes_needed = (insn->page == 2 ? 2 : 1) + size;
  char *f = s12z_new_insn(total_bytes_needed);
  if (f == NULL) { // Check for allocation failure
    as_fatal(_("Failed to allocate instruction buffer."));
    goto fail;
  }

  // 3. Encode instruction bytes

  // Write page 2 prebyte if applicable.
  if (insn->page == 2) {
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  }

  // Write opcode byte, incorporating the Dd register index.
  // Assuming Dd is a 3-bit field (0-7) that is added to the base opcode.
  if (Dd < 0 || Dd > 7) {
      as_fatal(_("Invalid Dd register index. Expected 0-7."));
      goto fail;
  }
  number_to_chars_bigendian(f++, insn->opc + Dd, 1);

  // Construct ModR/M-like byte (mb).
  uint8_t mb = MB_BASE_VALUE;

  // Determine signed/unsigned property from the instruction name.
  // This logic assumes `strchrnul` (GNU extension) is used, which returns
  // a pointer to the null terminator if the character is not found.
  // Expected name formats: "MULS.W", "MULU.L", "MULS", "MULU".
  // The 's' or 'u' is expected immediately before the first dot, or as the last
  // character of the name if no dot is present.
  const char *dot_ptr = strchrnul(insn->name, '.');
  char sign_char = '\0'; // Default to a value that will trigger an error if not 's' or 'u'

  if (strlen(insn->name) == 0) {
      as_fatal(_("Empty instruction name provided."));
      goto fail;
  }

  if (dot_ptr == insn->name) { // Dot is the first character, e.g., ".MULS" - considered invalid.
      as_fatal(_("Invalid instruction name format: starts with dot."));
      goto fail;
  } else if (*dot_ptr == '\0') { // No dot found (dot_ptr points to the NUL terminator).
      sign_char = insn->name[strlen(insn->name) - 1]; // Use last character of the name.
  } else { // Dot found and not at the beginning of the string.
      sign_char = *(dot_ptr - 1); // Character before the dot.
  }

  switch (sign_char) {
    case 's':
      mb |= MB_SIGNED_MASK; // Set bit 7 for signed operation.
      break;
    case 'u':
      // Bit 7 is already 0, no action needed for unsigned, but explicit for clarity.
      break;
    default:
      as_fatal(_("Instruction name must indicate signed ('s') or unsigned ('u') operation. E.g., 'MULS.W' or 'MULU.L'."));
      goto fail;
  }

  // Incorporate Dj register index (3 bits, shifted by 3).
  if (Dj < 0 || Dj > 7) { // Assuming Dj is a 3-bit field.
    as_fatal(_("Invalid Dj register index. Expected 0-7."));
    goto fail;
  }
  mb |= (uint8_t)(Dj << MB_REG_SHIFT);

  // Incorporate size (2 bits, 0-indexed: 0 for size 1, 1 for size 2, etc.).
  // `size - 1` will be 0, 1, 2, or 3 for sizes 1, 2, 3, or 4 respectively,
  // fitting precisely into the lowest two bits.
  mb |= (uint8_t)(size - 1);

  number_to_chars_bigendian(f++, mb, 1);
  number_to_chars_bigendian(f++, imm, size); // Write the immediate value.

  return true;

fail:
  // On failure, restore `input_line_pointer` as parsing functions modify it.
  fail_line_pointer = input_line_pointer;
  input_line_pointer = original_ilp;
  return false;
}


static bool
mul_reg_reg_opr (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;
  int Dd, Dj;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_reg_name (REG_BIT_Dn, &Dd)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_reg_name (REG_BIT_Dn, &Dj)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_opr (buffer, &n_bytes, &exp, true)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  int size = size_from_suffix (insn, 0);

  char *f = s12z_new_insn (insn->page + 1 + n_bytes);
  if (f == NULL) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }
  char *current_f_ptr = f;

  if (insn->page == 2) {
    number_to_chars_bigendian (current_f_ptr++, PAGE2_PREBYTE, 1);
  }

  number_to_chars_bigendian (current_f_ptr++, (uint8_t)(insn->opc + Dd), 1);

  uint8_t mb = 0x40;
  const char *dot = strchrnul (insn->name, '.');

  if (dot == NULL || dot == insn->name) {
    as_fatal (_("BAD MUL suffix: Malformed instruction name '%s'. Expected 'name.s' or 'name.u'."), insn->name);
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  switch (dot[-1]) {
    case 's':
      mb |= 0x80;
      break;
    case 'u':
      mb |= 0x00;
      break;
    default:
      as_fatal (_("BAD MUL suffix for instruction '%s'. Expected '.s' or '.u' but found '.%c'."), insn->name, dot[-1]);
      fail_line_pointer = input_line_pointer;
      input_line_pointer = original_input_line_pointer;
      return false;
  }

  mb |= (uint8_t)(Dj << 3);
  mb |= (uint8_t)(size - 1);

  number_to_chars_bigendian (current_f_ptr++, mb, 1);

  emit_opr (current_f_ptr, buffer, n_bytes, &exp);

  return true;
}

static bool
mul_reg_opr_opr (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;

  int Dd;
  if (!lex_reg_name (REG_BIT_Dn, &Dd)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  uint8_t buffer1[4];
  int n_bytes1;
  expressionS exp1;
  if (!lex_opr (buffer1, &n_bytes1, &exp1, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  uint8_t buffer2[4];
  int n_bytes2;
  expressionS exp2;
  if (!lex_opr (buffer2, &n_bytes2, &exp2, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  int size1 = size_from_suffix (insn, 0);
  int size2 = size_from_suffix (insn, 1);

  char *f = s12z_new_insn (insn->page + 1 + n_bytes1 + n_bytes2);
  if (f == NULL) {
    return false;
  }

  if (insn->page == 2) {
    number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
  }

  number_to_chars_bigendian (f++, insn->opc + Dd, 1);

  uint8_t mb = 0x42;
  const char *dot_ptr = strchrnul (insn->name, '.');
  char suffix_to_check;

  if (dot_ptr == insn->name) {
    suffix_to_check = '\0';
  } else {
    suffix_to_check = dot_ptr[-1];
  }

  switch (suffix_to_check)
    {
    case 's':
      mb |= 0x80;
      break;
    case 'u':
      mb |= 0x00;
      break;
    default:
      as_fatal (_("BAD MUL: Invalid instruction suffix for signed/unsigned operation. Expected 's' or 'u'."));
      break;
    }

  mb |= (uint8_t)((size1 - 1) << 4);
  mb |= (uint8_t)((size2 - 1) << 2);
  number_to_chars_bigendian (f++, mb, 1);

  f = emit_opr (f, buffer1, n_bytes1, &exp1);
  f = emit_opr (f, buffer2, n_bytes2, &exp2);

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
      *reg_bits |= 0x1u << reg;
    }

  return true;
}

static bool
psh_pull (const struct instruction *insn)
{
  uint8_t pb = (0 == strcmp ("pul", insn->name)) ? 0x80 : 0x00;

  if (lex_match_string ("all16b"))
    {
      pb |= 0x40;
    }
  else if (lex_match_string ("all"))
    {
      // No action needed for "all"
    }
  else
    {
      int reg1;
      if (!lex_reg_name (REG_BIT_GRP1 | REG_BIT_GRP0, &reg1))
	{
	  fail_line_pointer = input_line_pointer;
	  return false;
	}

      uint16_t admitted_group = 0;
      uint16_t reg1_bit_mask = 0x1U << reg1;

      if (reg1_bit_mask & REG_BIT_GRP1)
	{
	  admitted_group = REG_BIT_GRP1;
	}
      else if (reg1_bit_mask & REG_BIT_GRP0)
	{
	  admitted_group = REG_BIT_GRP0;
	}

      uint16_t reg_bits = reg1_bit_mask;
      if (!lex_reg_list (admitted_group, &reg_bits))
	{
	  fail_line_pointer = input_line_pointer;
	  return false;
	}

      if (reg_bits & REG_BIT_GRP1)
	{
	  pb |= 0x40;
	}

      for (int i = 0; i < 16; ++i)
	{
	  if (reg_bits & (0x1U << i))
	    {
	      pb |= reg_map[i];
	    }
	}
    }

  char *f = s12z_new_insn (2);

  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, pb, 1);
  return true;
}


static bool
tfr (const struct instruction *insn)
{
  int reg1;
  if (!lex_reg_name (~0, &reg1)) {
    goto fail;
  }

  if (!lex_match (',')) {
    goto fail;
  }

  int reg2;
  if (!lex_reg_name (~0, &reg2)) {
    goto fail;
  }

  bool is_sex_or_zex_instruction = (0 == strcasecmp ("sex", insn->name)) ||
                                   (0 == strcasecmp ("zex", insn->name));

  if (is_sex_or_zex_instruction &&
      (registers[reg2].bytes <= registers[reg1].bytes)) {
    as_warn (_("Source register for %s is no larger than the destination register"),
             insn->name);
  } else if (reg1 == reg2) {
    as_warn (_("The destination and source registers are identical"));
  }

  size_t instruction_length = 2; // Base length for opcode and register byte
  if (insn->page == 2) {
    instruction_length = 3; // Add one byte for the page 2 prefix
  }

  char *f = s12z_new_insn (instruction_length);
  if (f == NULL) {
    goto fail; // Handle memory allocation failure
  }

  if (insn->page == 2) {
    number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
  }

  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, (reg1 << 4) | reg2, 1);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  return false;
}

#include <stdint.h>

static bool
imm8 (const struct instruction *insn)
{
  long imm;

  if (!lex_imm (&imm, NULL))
    {
      return false;
    }

  if (imm > INT8_MAX || imm < INT8_MIN)
    {
      as_bad (_("Immediate value %ld is out of range for instruction %s"),
	      imm, insn->name);
      return false;
    }

  char *buffer = s12z_new_insn (2);

  if (buffer == NULL)
    {
      return false;
    }

  number_to_chars_bigendian (buffer, insn->opc, 1);
  number_to_chars_bigendian (buffer + 1, imm, 1);

  return true;
}

static bool
reg_imm (const struct instruction *insn, int allowed_reg)
{
  char *original_input_pointer = input_line_pointer;
  int reg;

  if (!lex_reg_name (allowed_reg, &reg))
    goto fail;

  if (!lex_force_match (','))
    goto fail;

  long imm;
  if (!lex_imm (&imm, NULL))
    goto fail;

  short size = registers[reg].bytes;
  char *buffer_ptr = s12z_new_insn (insn->page + size);

  if (insn->page == 2)
    number_to_chars_bigendian (buffer_ptr++, PAGE2_PREBYTE, 1);

  number_to_chars_bigendian (buffer_ptr++, insn->opc + reg, 1);
  number_to_chars_bigendian (buffer_ptr++, imm, size);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = original_input_pointer;
  return false;
}


static bool
regd_imm (const struct instruction *insn)
{
  if (insn == NULL)
    {
      return false;
    }
  return reg_imm (insn, REG_BIT_Dn);
}

static bool
regdxy_imm (const struct instruction *insn)
{
  int combined_register_bits = REG_BIT_Dn | REG_BIT_XY;
  return reg_imm (insn, combined_register_bits);
}


static const unsigned int REG_S_MASK = (0x1U << REG_S);

static bool
regs_imm (const struct instruction *insn)
{
  if (insn == NULL)
  {
    return false;
  }
  return reg_imm (insn, REG_S_MASK);
}

static bool
trap_imm (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  long imm = -1;

  if (!lex_imm(&imm, NULL)) {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  if (imm < 0x92 || imm > 0xFF ||
      (imm >= 0xA0 && imm <= 0xA7) ||
      (imm >= 0xB0 && imm <= 0xB7)) {
    as_bad(_("trap value %ld is not valid"), imm);
    return false;
  }

  char *f = s12z_new_insn(2);
  number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f + 1, imm & 0xFF, 1);

  return true;
}



/* Special one byte instruction CMP X, Y */
static bool
regx_regy (const struct instruction *insn)
{
  int reg;

  if (!lex_reg_name (0x1U << REG_X, &reg))
    {
      return false;
    }

  if (!lex_force_match (','))
    {
      return false;
    }

  if (!lex_reg_name (0x1U << REG_Y, &reg))
    {
      return false;
    }

  char *f = s12z_new_insn (1);
  if (f == NULL)
    {
      return false;
    }

  number_to_chars_bigendian (f, insn->opc, 1);
  return true;
}

/* Special one byte instruction SUB D6, X, Y */
static bool
regd6_regx_regy (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int reg;

  if (!lex_reg_name (0x1U << REG_D6, &reg))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (0x1U << REG_X, &reg))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (0x1U << REG_Y, &reg))
    goto fail;

  // The value written to 'reg' by lex_reg_name is not used by this function.
  // This explicit cast addresses potential "value written to, but never read" code smells.
  (void)reg; 

  char *f = s12z_new_insn (1);
  number_to_chars_bigendian (f, insn->opc, 1);
  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

/* Special one byte instruction SUB D6, Y, X */
static bool
regd6_regy_regx (const struct instruction *insn)
{
  char *original_input_pointer = input_line_pointer;
  int dummy_parsed_reg_value;

  if (lex_reg_name(0x1U << REG_D6, &dummy_parsed_reg_value) &&
      lex_match(',') &&
      lex_reg_name(0x1U << REG_Y, &dummy_parsed_reg_value) &&
      lex_match(',') &&
      lex_reg_name(0x1U << REG_X, &dummy_parsed_reg_value))
  {
    char *instruction_buffer = s12z_new_insn(1);
    number_to_chars_bigendian(instruction_buffer, insn->opc, 1);
    return true;
  }
  else
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_pointer;
    return false;
  }
}

static bool
reg_opr (const struct instruction *insn, int allowed_regs,
	 bool immediate_ok)
{
  char *ilp = input_line_pointer;
  int reg;

  if (!lex_reg_name (allowed_regs, &reg))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  if (!lex_force_match (','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  if (!lex_opr (buffer, &n_bytes, &exp, immediate_ok))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp;
      return false;
    }

  const bool is_ext24_constant_mode = (exp.X_op == O_constant
                                       && buffer[0] == 0xFA
                                       && insn->alt_opc != 0);

  char *f;
  if (is_ext24_constant_mode)
    {
      f = s12z_new_insn (4);

      gas_assert (insn->page == 1);

      number_to_chars_bigendian (f++, insn->alt_opc + reg, 1);
      emit_ext24 (f, exp.X_add_number);
    }
  else
    {
      f = s12z_new_insn (n_bytes + insn->page);

      if (insn->page == 2)
        number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);

      number_to_chars_bigendian (f++, insn->opc + reg, 1);

      emit_opr (f, buffer, n_bytes, &exp);
    }

  return true;
}


static bool
regdxy_opr_dest (const struct instruction *insn)
{
  const unsigned int target_registers_mask = REG_BIT_Dn | REG_BIT_XY;
  return reg_opr (insn, target_registers_mask, false);
}

static bool
regdxy_opr_src (const struct instruction *insn)
{
  return reg_opr (insn, REG_BIT_Dn | REG_BIT_XY, true);
}


static bool
regd_opr (const struct instruction *insn)
{
  if (insn == NULL) {
    return false;
  }
  return reg_opr (insn, REG_BIT_Dn, true);
}


/* OP0: S; OP1: destination OPR */
static bool
regs_opr_dest (const struct instruction *insn)
{
  enum {
    REG_S_MASK = (0x1U << REG_S)
  };
  return reg_opr (insn, REG_S_MASK, false);
}

/* OP0: S; OP1: source OPR */
static bool
regs_opr_src (const struct instruction *insn)
{
  const unsigned int source_register_mask = 0x1U << REG_S;
  return reg_opr (insn, source_register_mask, true);
}

static bool
imm_opr  (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;
  long immediate_value;
  expressionS immediate_expression = { .X_op = O_absent };
  int size = size_from_suffix (insn, 0);

  if (!lex_imm (&immediate_value, size > 1 ? &immediate_expression : NULL))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (','))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  uint8_t operand_buffer[4];
  int operand_bytes_count;
  expressionS operand_expression;
  if (!lex_opr (operand_buffer, &operand_bytes_count, &operand_expression, false))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  int total_insn_size = 1 + operand_bytes_count + size;
  char *insn_buffer = s12z_new_insn (total_insn_size);

  number_to_chars_bigendian (insn_buffer++, insn->opc, 1);

  emit_reloc (&immediate_expression, insn_buffer, size,
              (size == 4) ? BFD_RELOC_32 : BFD_RELOC_S12Z_OPR);

  for (int i = 0; i < size; ++i)
  {
    number_to_chars_bigendian (insn_buffer++,
                               immediate_value >> (CHAR_BIT * (size - i - 1)),
                               1);
  }

  emit_opr (insn_buffer, operand_buffer, operand_bytes_count, &operand_expression);

  return true;
}

static bool
opr_opr  (const struct instruction *insn)
{
  char *initial_input_line_pointer = input_line_pointer;

  uint8_t buffer1[4];
  int n_bytes1;
  expressionS exp1;
  if (!lex_opr (buffer1, &n_bytes1, &exp1, false))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_input_line_pointer;
      return false;
    }

  if (!lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_input_line_pointer;
      return false;
    }

  uint8_t buffer2[4];
  int n_bytes2;
  expressionS exp2;
  if (!lex_opr (buffer2, &n_bytes2, &exp2, false))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_input_line_pointer;
      return false;
    }

  char *f = s12z_new_insn (1 + n_bytes1 + n_bytes2);
  if (f == NULL)
    {
      // If s12z_new_insn fails, it's an internal error, not a lexing error.
      // However, to maintain consistent error reporting for the caller,
      // we still set fail_line_pointer to the current parse position
      // and restore input_line_pointer as if a lexing error occurred.
      fail_line_pointer = input_line_pointer;
      input_line_pointer = initial_input_line_pointer;
      return false;
    }

  number_to_chars_bigendian (f++, insn->opc, 1);

  f = emit_opr (f, buffer1, n_bytes1, &exp1);
  f = emit_opr (f, buffer2, n_bytes2, &exp2);

  return true;
}

static bool
reg67sxy_opr (const struct instruction *insn)
{
  static const int VALID_REG_MASK = REG_BIT_XYS | (0x1U << REG_D6) | (0x1U << REG_D7);

  int reg_value;
  if (!lex_reg_name (VALID_REG_MASK, &reg_value))
    return false;

  if (!lex_match (','))
    return false;

  uint8_t operand_buffer[4];
  int operand_n_bytes;
  expressionS operand_expression;
  if (!lex_opr (operand_buffer, &operand_n_bytes, &operand_expression, false))
    return false;

  const int total_insn_size = 1 + operand_n_bytes;
  char *new_insn_buffer = s12z_new_insn (total_insn_size);

  if (new_insn_buffer == NULL)
    {
      return false;
    }

  int calculated_opcode = insn->opc + (reg_value - REG_D6);

  char *current_ptr = new_insn_buffer;

  number_to_chars_bigendian (current_ptr, calculated_opcode, 1);
  current_ptr += 1;

  emit_opr (current_ptr, operand_buffer, operand_n_bytes, &operand_expression);

  return true;
}

static bool
rotate  (const struct instruction *insn, short dir)
{
  const int MAX_OPERAND_BUFFER_SIZE = 4;
  const int FIXED_INSTRUCTION_OVERHEAD_BYTES = 2; 

  const uint8_t SB_BASE_VALUE = 0x24;
  const uint8_t SB_DIRECTION_BIT = 0x40;
  const int MIN_VALID_SIZE = 1;

  uint8_t operand_buffer[MAX_OPERAND_BUFFER_SIZE];
  int num_operand_bytes;
  expressionS operand_expression;

  if (lex_opr (operand_buffer, &num_operand_bytes, &operand_expression, false))
    {
      int total_instruction_size = num_operand_bytes + FIXED_INSTRUCTION_OVERHEAD_BYTES;
      char *instruction_buffer = s12z_new_insn (total_instruction_size);

      char *current_write_pos = instruction_buffer;

      number_to_chars_bigendian (current_write_pos++, insn->opc, 1);

      int instruction_suffix_size = size_from_suffix (insn, 0);
      if (instruction_suffix_size < MIN_VALID_SIZE)
	{
	  instruction_suffix_size = MIN_VALID_SIZE;
	}

      uint8_t sb_byte = SB_BASE_VALUE;
      sb_byte |= (uint8_t)(instruction_suffix_size - MIN_VALID_SIZE);

      if (dir)
	{
	  sb_byte |= SB_DIRECTION_BIT;
	}

      number_to_chars_bigendian (current_write_pos++, sb_byte, 1);

      emit_opr (current_write_pos, operand_buffer, num_operand_bytes, &operand_expression);

      return true;
    }

  return false;
}

#include <stdbool.h>

static bool
rol (const struct instruction *insn)
{
  if (insn == NULL) {
    return false;
  }
  return rotate (insn, 1);
}

static bool
ror  (const struct instruction *insn)
{
  if (insn == NULL) {
    return false;
  }
  const int rotate_direction_right = 0;
  return rotate (insn, rotate_direction_right);
}


/* Shift instruction with a register operand and an immediate #1 or #2
   left = 1; right = 0;
   logical = 0; arithmetic = 1;
*/
static bool
s12z_try_parse_shift_operand (long *imm_out, char **original_ilp_start)
{
  *original_ilp_start = input_line_pointer;

  int Dd;
  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    return false;

  if (!lex_match (','))
    return false;

  long imm = -1;
  if (!lex_imm (&imm, NULL))
    return false;

  if (imm != 1 && imm != 2)
    return false;

  *imm_out = imm;
  return true;
}

static bool
lex_shift_reg_imm1  (const struct instruction *insn, short type, short dir)
{
  char *ilp_start_of_attempt;
  long imm;

  if (!s12z_try_parse_shift_operand(&imm, &ilp_start_of_attempt))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp_start_of_attempt;
      return false;
    }

  input_line_pointer = ilp_start_of_attempt;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_opr (buffer, &n_bytes, &exp, false))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = ilp_start_of_attempt;
      return false;
    }

  gas_assert (n_bytes == 1);

  uint8_t sb = 0x34;
  sb |= (dir & 0x01) << 6;
  sb |= (type & 0x01) << 7;
  if (imm == 2)
    sb |= 0x08;

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
lex_shift_reg  (const struct instruction *insn, short type, short dir)
{
  int Dd, Ds, Dn;

  if (!lex_reg_name (REG_BIT_Dn, &Dd)) {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  if (!lex_reg_name (REG_BIT_Dn, &Ds)) {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    return false;
  }

  uint8_t sb = 0x10;
  sb |= Ds;
  sb |= dir << 6;
  sb |= type << 7;

  if (lex_reg_name (REG_BIT_Dn, &Dn)) {
    char *f = s12z_new_insn (3);
    number_to_chars_bigendian (f++, insn->opc | Dd, 1);
    number_to_chars_bigendian (f++, sb, 1);
    uint8_t xb = 0xb8;
    xb |= Dn;
    number_to_chars_bigendian (f++, xb, 1);
    return true;
  } else {
    long imm;
    if (lex_imm (&imm, NULL)) {
      if (imm < 0 || imm > 31) {
        as_bad (_("Shift value should be in the range [0,31]"));
        fail_line_pointer = input_line_pointer;
        return false;
      }

      int n_bytes = 3;
      if (imm == 1 || imm == 2) {
        n_bytes = 2;
        sb &= ~0x10;
      } else {
        sb |= (imm & 0x01) << 3;
      }

      char *f = s12z_new_insn (n_bytes);
      number_to_chars_bigendian (f++, insn->opc | Dd, 1);
      number_to_chars_bigendian (f++, sb, 1);
      if (n_bytes > 2) {
        uint8_t xb = 0x70;
        xb |= imm >> 1;
        number_to_chars_bigendian (f++, xb, 1);
      }
      return true;
    }
  }

  fail_line_pointer = input_line_pointer;
  return false;
}

#include <string.h>

enum ShiftType {
    SHIFT_TYPE_LOGICAL = 0,
    SHIFT_TYPE_ARITHMETIC = 1
};

enum ShiftDirection {
    SHIFT_DIR_RIGHT = 0,
    SHIFT_DIR_LEFT = 1
};

static void
impute_shift_dir_and_type (const struct instruction *insn, short *type, short *dir)
{
  if (insn == NULL) {
    as_fatal (_("Internal error: instruction pointer is NULL in impute_shift_dir_and_type."));
  }
  if (type == NULL) {
    as_fatal (_("Internal error: type pointer is NULL in impute_shift_dir_and_type."));
  }
  if (dir == NULL) {
    as_fatal (_("Internal error: dir pointer is NULL in impute_shift_dir_and_type."));
  }

  // Ensure insn->name is a valid, sufficiently long string.
  // Assumes insn->name is a NULL-terminated C string.
  if (insn->name == NULL || strlen (insn->name) < 3)
    {
      as_fatal (_("Bad shift instruction name length or NULL: '%s'"), insn->name ? insn->name : "(null)");
    }

  switch (insn->name[0])
    {
    case 'l':
      *type = SHIFT_TYPE_LOGICAL;
      break;
    case 'a':
      *type = SHIFT_TYPE_ARITHMETIC;
      break;
    default:
      as_fatal (_("Bad shift mode '%c' in instruction name '%s'"), insn->name[0], insn->name);
      break;
    }

  switch (insn->name[2])
    {
    case 'l':
      *dir = SHIFT_DIR_LEFT;
      break;
    case 'r':
      *dir = SHIFT_DIR_RIGHT;
      break;
    default:
      as_fatal (_("Bad shift direction '%c' in instruction name '%s'"), insn->name[2], insn->name);
      break;
    }
}

/* Shift instruction with a OPR operand */
static bool
shift_two_operand  (const struct instruction *insn)
{
  char *input_line_pointer_save = input_line_pointer;

  uint8_t sb = 0x34;

  short dir;
  short type;
  impute_shift_dir_and_type (insn, &type, &dir);
  sb |= (uint8_t)dir << 6;
  sb |= (uint8_t)type << 7;

  int size = size_from_suffix (insn, 0);
  sb |= (uint8_t)(size - 1);

  uint8_t buffer[4];
  int n_opr_bytes;
  expressionS exp;
  if (!lex_opr (buffer, &n_opr_bytes, &exp, false))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = input_line_pointer_save;
      return false;
    }

  if (!lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = input_line_pointer_save;
      return false;
    }

  long imm;
  if (!lex_imm (&imm, NULL))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = input_line_pointer_save;
      return false;
    }

  if (imm != 1 && imm != 2)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = input_line_pointer_save;
      return false;
    }

  if (imm == 2)
    sb |= 0x08;

  char *f = s12z_new_insn (2 + n_opr_bytes);
  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, sb, 1);
  emit_opr (f, buffer, n_opr_bytes, &exp);

  return true;
}

/* Shift instruction with a OPR operand */
static bool
shift_opr_imm  (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;

  short shift_direction = -1;
  short shift_type = -1;
  impute_shift_dir_and_type (insn, &shift_type, &shift_direction);

  int dest_reg_Dd = 0;
  if (!lex_reg_name (REG_BIT_Dn, &dest_reg_Dd))
    {
      input_line_pointer = original_input_line_pointer;
      return false;
    }

  if (!lex_match (','))
    {
      input_line_pointer = original_input_line_pointer;
      return false;
    }

  int instruction_bytes_count = 2; // Initial bytes for opcode | Dd and status byte

  uint8_t operand1_buffer[4];
  int operand1_bytes_count;
  expressionS operand1_exp;
  if (!lex_opr (operand1_buffer, &operand1_bytes_count, &operand1_exp, false))
    {
      input_line_pointer = original_input_line_pointer;
      return false;
    }
  instruction_bytes_count += operand1_bytes_count;

  if (!lex_match (','))
    {
      input_line_pointer = original_input_line_pointer;
      return false;
    }

  uint8_t operand2_buffer[4];
  int operand2_bytes_count = 0;
  expressionS operand2_exp;
  long immediate_value;
  bool is_immediate = false;

  if (lex_imm (&immediate_value, NULL))
    {
      is_immediate = true;
    }
  else if (!lex_opr (operand2_buffer, &operand2_bytes_count, &operand2_exp, false))
    {
      input_line_pointer = original_input_line_pointer;
      return false;
    }

  uint8_t status_byte = 0x20;

  int size_suffix = size_from_suffix (insn, 0);
  if (size_suffix != -1)
    {
      status_byte |= (uint8_t)(size_suffix - 1);
    }

  status_byte |= (uint8_t)(shift_direction << 6);
  status_byte |= (uint8_t)(shift_type << 7);

  if (is_immediate)
    {
      if (immediate_value == 2)
        {
          status_byte |= 0x08;
        }
      else if (immediate_value > 2) // For immediate values greater than 2 (imm != 1 and imm != 2)
        {
          instruction_bytes_count++; // Additional byte for the immediate value (0x70 | (imm >> 1))
          status_byte |= 0x10;
          if (immediate_value % 2 != 0) // If immediate value is odd
            {
              status_byte |= 0x08;
            }
        }
      // If immediate_value == 1, no specific bits (0x08 or 0x10) are set in status_byte
      // and instruction_bytes_count is not incremented here.
    }
  else // Second operand is not an immediate (e.g., a register)
    {
      instruction_bytes_count += operand2_bytes_count;
      status_byte |= 0x10; // Bit indicating 2-byte operand or immediate > 2
    }

  char *insn_output_ptr = s12z_new_insn (instruction_bytes_count);
  if (insn_output_ptr == NULL)
    {
      input_line_pointer = original_input_line_pointer;
      return false;
    }

  number_to_chars_bigendian (insn_output_ptr++, insn->opc | dest_reg_Dd, 1);
  number_to_chars_bigendian (insn_output_ptr++, status_byte, 1);
  insn_output_ptr = emit_opr (insn_output_ptr, operand1_buffer, operand1_bytes_count, &operand1_exp);

  if (is_immediate)
    {
      if (immediate_value != 1 && immediate_value != 2) // Emit additional byte only for imm > 2
        {
          number_to_chars_bigendian (insn_output_ptr++, (uint8_t)(0x70 | (immediate_value >> 1)), 1);
        }
    }
  else
    {
      insn_output_ptr = emit_opr (insn_output_ptr, operand2_buffer, operand2_bytes_count, &operand2_exp);
    }

  return true;
}

/* Shift instruction with a register operand */
static bool
shift_reg  (const struct instruction *insn)
{
  short dir;
  short type;

  impute_shift_dir_and_type (insn, &type, &dir);

  return lex_shift_reg_imm1 (insn, type, dir) || lex_shift_reg (insn, type, dir);
}

static bool
bm_regd_imm  (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;

  int Di = 0;
  if (!lex_reg_name (REG_BIT_Dn, &Di)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  long imm;
  if (!lex_imm (&imm, NULL)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  uint8_t bm = (uint8_t)(imm << 3);
  bm |= (uint8_t)Di;

  char *f = s12z_new_insn (2);

  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, bm, 1);

  return true;
}

static bool
bm_opr_reg (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;

  uint8_t buffer[4];
  int n_opr_bytes;
  expressionS exp;
  int Dn;

  if (!lex_opr (buffer, &n_opr_bytes, &exp, false))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (REG_BIT_Dn, &Dn))
    goto fail;

  uint8_t bm = (uint8_t)(Dn << 4);
  int size = size_from_suffix (insn, 0);
  bm |= (uint8_t)((size - 1) << 2);
  bm |= 0x81;

  char *instruction_buffer = s12z_new_insn (2 + n_opr_bytes);
  if (instruction_buffer == NULL)
    goto fail;

  char *current_write_ptr = instruction_buffer;
  number_to_chars_bigendian (current_write_ptr++, insn->opc, 1);
  number_to_chars_bigendian (current_write_ptr++, bm, 1);

  emit_opr (current_write_ptr, buffer, n_opr_bytes, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = original_input_line_pointer;
  return false;
}


static bool
bm_opr_imm  (const struct instruction *insn)
{
  char * const original_input_line_pointer = input_line_pointer;
  bool success = false;

  uint8_t buffer[4];
  int n_opr_bytes;
  expressionS exp;
  long imm;
  int size;
  uint8_t bm;
  char *f;

  if (!lex_opr (buffer, &n_opr_bytes, &exp, false)) {
    goto error_exit;
  }

  if (!lex_match (',')) {
    goto error_exit;
  }

  if (!lex_imm (&imm, NULL)) {
    goto error_exit;
  }

  size = size_from_suffix (insn, 0);

  if (imm < 0 || imm >= size * 8)
  {
    as_bad (_("Immediate operand %ld is inappropriate for size of instruction"), imm);
    goto error_exit;
  }

  bm = 0x80;
  if (size == 2) {
    bm |= 0x02;
  } else if (size == 4) {
    bm |= 0x08;
  }
  bm |= (imm & 0x07) << 4;
  bm |= (imm >> 3);

  f = s12z_new_insn (2 + n_opr_bytes);
  number_to_chars_bigendian (f++, insn->opc, 1);
  number_to_chars_bigendian (f++, bm, 1);
  emit_opr (f, buffer, n_opr_bytes, &exp);

  success = true;

error_exit:
  if (!success) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
  }
  return success;
}


static bool
bm_regd_reg(const struct instruction *insn)
{
    char *original_input_line_pointer = input_line_pointer;

    int di_register_index;
    if (!lex_reg_name(REG_BIT_Dn, &di_register_index)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_input_line_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_input_line_pointer;
        return false;
    }

    int dn_register_index;
    if (!lex_reg_name(REG_BIT_Dn, &dn_register_index)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_input_line_pointer;
        return false;
    }

    uint8_t bm_byte = (uint8_t)(dn_register_index << 4);
    bm_byte |= 0x81;

    uint8_t xb_byte = (uint8_t)(di_register_index | 0xb8);

    char *instruction_buffer = s12z_new_insn(3);
    if (instruction_buffer == NULL) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    char *current_byte_ptr = instruction_buffer;
    number_to_chars_bigendian(current_byte_ptr++, insn->opc, 1);
    number_to_chars_bigendian(current_byte_ptr++, bm_byte, 1);
    number_to_chars_bigendian(current_byte_ptr++, xb_byte, 1);

    return true;
}





static bool
bf_reg_opr_imm  (const struct instruction *insn, short ie)
{
  char * const initial_line_pointer = input_line_pointer;
  bool success = false;

  int Dd = 0;
  uint8_t buffer[4];
  int n_bytes = 0;
  expressionS exp;
  long width = 0;
  long offset = 0;
  char *output_ptr = NULL;

  if (!lex_reg_name (REG_BIT_Dn, &Dd)) {
    goto cleanup;
  }

  if (!lex_match (',')) {
    goto cleanup;
  }

  if (!lex_opr (buffer, &n_bytes, &exp, false)) {
    goto cleanup;
  }

  if (!lex_match (',')) {
    goto cleanup;
  }

  if (!lex_imm (&width, NULL)) {
    goto cleanup;
  }

  if (width < 0 || width > 31) {
    as_bad (_("Invalid width value for %s"), insn->name);
    goto cleanup;
  }

  if (!lex_match (':')) {
    goto cleanup;
  }

  if (!lex_constant (&offset)) {
    goto cleanup;
  }

  if (offset < 0 || offset > 31) {
    as_bad (_("Invalid offset value for %s"), insn->name);
    goto cleanup;
  }

  uint8_t i1 = (uint8_t) (width << 5);
  i1 |= (uint8_t) offset;

  int size = size_from_suffix (insn, 0);
  uint8_t bb = ie ? 0x80 : 0x00;
  bb |= 0x60;
  bb |= (uint8_t) ((size - 1) << 2);
  bb |= (uint8_t) (width >> 3);

  output_ptr = s12z_new_insn (4 + n_bytes);
  if (output_ptr == NULL) {
    as_bad (_("Failed to allocate memory for instruction for %s"), insn->name);
    goto cleanup;
  }

  char *f = output_ptr;
  number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian (f++, (uint8_t)(0x08 | Dd), 1);
  number_to_chars_bigendian (f++, bb, 1);
  number_to_chars_bigendian (f++, i1, 1);

  emit_opr (f, buffer, n_bytes, &exp);

  success = true;

cleanup:
  if (!success) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
  }
  return success;
}


static bool
bf_opr_reg_imm(const struct instruction *insn, short is_extended_instruction)
{
  // Store the current input line pointer for error recovery
  char *original_input_line_pointer = input_line_pointer;

  // Constants for instruction encoding and operand parsing
  const int OPR_BUFFER_MAX_BYTES = 4;
  const int MIN_FIELD_VALUE = 0;
  const int MAX_FIELD_VALUE = 31; // Max value for width and offset (5 bits)

  const int WIDTH_ENCODING_SHIFT = 5;
  const int OFFSET_ENCODING_MASK = 0x1F; // 0b00011111

  const uint8_t BB_IE_BIT_MASK = 0x80; // Bit for 'ie' (is_extended_instruction)
  const uint8_t BB_FIXED_BITS = 0x70;  // Fixed bits for instruction control byte (0b01110000)
  const int BB_SIZE_SHIFT = 2;
  const int BB_WIDTH_HIGH_BITS_SHIFT = 3;

  const uint8_t DS_ENCODING_MASK = 0x08;

  uint8_t operand_buffer[OPR_BUFFER_MAX_BYTES];
  int num_operand_bytes;
  expressionS operand_expression;

  // 1. Parse the operand
  if (!lex_opr(operand_buffer, &num_operand_bytes, &operand_expression, false))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  // 2. Match comma separator and parse destination register (Ds)
  if (!lex_match(','))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  int destination_register = 0;
  if (!lex_reg_name(REG_BIT_Dn, &destination_register))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  // 3. Match comma separator and parse width
  if (!lex_match(','))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  long width_value;
  if (!lex_imm(&width_value, NULL))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (width_value < MIN_FIELD_VALUE || width_value > MAX_FIELD_VALUE)
  {
    as_bad(_("Invalid width value for %s"), insn->name);
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  // 4. Match colon separator and parse offset
  if (!lex_match(':'))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  long offset_value;
  if (!lex_constant(&offset_value))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (offset_value < MIN_FIELD_VALUE || offset_value > MAX_FIELD_VALUE)
  {
    as_bad(_("Invalid offset value for %s"), insn->name);
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  // 5. Calculate instruction-specific bytes
  uint8_t width_offset_byte = (uint8_t)(width_value << WIDTH_ENCODING_SHIFT) | ((uint8_t)offset_value & OFFSET_ENCODING_MASK);

  int instruction_size = size_from_suffix(insn, 0);
  uint8_t instruction_control_byte = is_extended_instruction ? BB_IE_BIT_MASK : 0x00;
  instruction_control_byte |= BB_FIXED_BITS;
  instruction_control_byte |= (uint8_t)(instruction_size - 1) << BB_SIZE_SHIFT;
  instruction_control_byte |= (uint8_t)width_value >> BB_WIDTH_HIGH_BITS_SHIFT;

  // 6. Allocate memory for the new instruction and emit bytes
  // The total size is 4 bytes for the instruction header + num_operand_bytes
  char *new_instruction_ptr = s12z_new_insn(4 + num_operand_bytes);

  // Write the instruction bytes to the allocated memory, incrementing the pointer after each write
  number_to_chars_bigendian(new_instruction_ptr++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(new_instruction_ptr++, (uint8_t)(DS_ENCODING_MASK | destination_register), 1);
  number_to_chars_bigendian(new_instruction_ptr++, instruction_control_byte, 1);
  number_to_chars_bigendian(new_instruction_ptr++, width_offset_byte, 1);

  // Emit the operand bytes following the instruction header
  emit_opr(new_instruction_ptr, operand_buffer, num_operand_bytes, &operand_expression);

  return true;
}



static bool
bf_reg_reg_imm(const struct instruction *insn, short ie)
{
  char *const original_ilp = input_line_pointer;
  bool success = true;

  int Dd = 0;
  int Ds = 0;
  long width = 0;
  long offset = 0;

  if (!lex_reg_name(REG_BIT_Dn, &Dd)) {
    success = false;
    goto cleanup;
  }

  if (!lex_match(',')) {
    success = false;
    goto cleanup;
  }

  if (!lex_reg_name(REG_BIT_Dn, &Ds)) {
    success = false;
    goto cleanup;
  }

  if (!lex_match(',')) {
    success = false;
    goto cleanup;
  }

  if (!lex_imm(&width, NULL)) {
    success = false;
    goto cleanup;
  }

  if (width < 0 || width > 31) {
    as_bad(_("Invalid width value for %s"), insn->name);
    success = false;
    goto cleanup;
  }

  if (!lex_match(':')) {
    success = false;
    goto cleanup;
  }

  if (!lex_constant(&offset)) {
    success = false;
    goto cleanup;
  }

  if (offset < 0 || offset > 31) {
    as_bad(_("Invalid offset value for %s"), insn->name);
    success = false;
    goto cleanup;
  }

  uint8_t bb = ie ? 0x80 : 0x00;
  bb |= 0x20;
  bb |= (uint8_t)(Ds << 2);
  bb |= (uint8_t)(width >> 3);

  uint8_t i1 = (uint8_t)(width << 5);
  i1 |= (uint8_t)offset;

  char *f = s12z_new_insn(4);
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, (uint8_t)(0x08 | Dd), 1);
  number_to_chars_bigendian(f++, bb, 1);
  number_to_chars_bigendian(f++, i1, 1);

cleanup:
  if (!success) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_ilp;
  }

  return success;
}

static bool
bf_reg_reg_reg  (const struct instruction *insn ATTRIBUTE_UNUSED, short ie)
{
  char *ilp_on_entry = input_line_pointer;

  int Dd = 0;
  if (!lex_reg_name (REG_BIT_Dn, &Dd)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp_on_entry;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp_on_entry;
    return false;
  }

  int Ds = 0;
  if (!lex_reg_name (REG_BIT_Dn, &Ds)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp_on_entry;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp_on_entry;
    return false;
  }

  int Dp = 0;
  const unsigned int dp_reg_mask = ((0x01u << REG_D2) |
                                    (0x01u << REG_D3) |
                                    (0x01u << REG_D4) |
                                    (0x01u << REG_D5));
  if (!lex_reg_name (dp_reg_mask, &Dp)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp_on_entry;
    return false;
  }

  uint8_t bb = ie ? 0x80 : 0x00;
  bb |= (uint8_t)Ds << 2;
  bb |= (uint8_t)Dp;

  char *f = s12z_new_insn (3);
  number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian (f++, (uint8_t)(0x08 | Dd), 1);
  number_to_chars_bigendian (f++, bb , 1);

  return true;
}

static bool
bf_opr_reg_reg  (const struct instruction *insn, short ie)
{
  char *original_input_line_pointer = input_line_pointer;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_opr (buffer, &n_bytes, &exp, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  int Ds = 0;
  if (!lex_reg_name (REG_BIT_Dn, &Ds)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  int Dp = 0;
  if (!lex_reg_name  ((0x01u << REG_D2) |
		      (0x01u << REG_D3) |
		      (0x01u << REG_D4) |
		      (0x01u << REG_D5),
		      &Dp)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  int size = size_from_suffix (insn, 0);
  uint8_t bb = ie ? 0x80 : 0x00;
  bb |= 0x50;
  bb |= (uint8_t)Dp;
  bb |= (uint8_t)((size - 1) << 2);

  char *f = s12z_new_insn (3 + n_bytes);

  number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian (f++, (uint8_t)(0x08 | Ds), 1);
  number_to_chars_bigendian (f++, bb , 1);

  emit_opr (f, buffer, n_bytes, &exp);

  return true;
}


#include <stdbool.h>
#include <stdint.h>

// Helper function to manage error state consistently.
// This preserves the external behavior of input_line_pointer and fail_line_pointer.
// It assumes input_line_pointer and fail_line_pointer are global variables.
static inline bool handle_parse_error_and_restore_pointer(char *original_input_line_pointer) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
}

// Constants for instruction encoding specific to this function/file.
#define BF_REG_OPR_REG_VALID_DP_REG_MASK \
    ((1u << REG_D2) | (1u << REG_D3) | (1u << REG_D4) | (1u << REG_D5))

#define BF_REG_OPR_REG_INST_BYTE_B_EXTENDED_MODE_BIT 0x80
#define BF_REG_OPR_REG_INST_BYTE_B_FIXED_FLAG_BIT    0x40
#define BF_REG_OPR_REG_INST_BYTE_B_SIZE_SHIFT        2
#define BF_REG_OPR_REG_INST_BYTE_B_OPCODE_PART       0x08

static bool
bf_reg_opr_reg  (const struct instruction *insn, short is_extended_mode_flag)
{
  char *original_input_line_pointer = input_line_pointer;
  int destination_register_d_index = 0;
  int operand_register_p_index = 0;
  uint8_t operand_buffer[4];
  int operand_n_bytes = 0;
  expressionS operand_expression;

  if (!lex_reg_name(REG_BIT_Dn, &destination_register_d_index)) {
    return handle_parse_error_and_restore_pointer(original_input_line_pointer);
  }

  if (!lex_match(',')) {
    return handle_parse_error_and_restore_pointer(original_input_line_pointer);
  }

  if (!lex_opr(operand_buffer, &operand_n_bytes, &operand_expression, false)) {
    return handle_parse_error_and_restore_pointer(original_input_line_pointer);
  }

  if (!lex_match(',')) {
    return handle_parse_error_and_restore_pointer(original_input_line_pointer);
  }

  if (!lex_reg_name(BF_REG_OPR_REG_VALID_DP_REG_MASK, &operand_register_p_index)) {
    return handle_parse_error_and_restore_pointer(original_input_line_pointer);
  }

  int instruction_size_from_suffix = size_from_suffix(insn, 0);

  uint8_t instruction_byte_b = 0;
  if (is_extended_mode_flag) {
    instruction_byte_b |= BF_REG_OPR_REG_INST_BYTE_B_EXTENDED_MODE_BIT;
  }
  instruction_byte_b |= BF_REG_OPR_REG_INST_BYTE_B_FIXED_FLAG_BIT;
  instruction_byte_b |= (uint8_t)(operand_register_p_index & 0x03);
  instruction_byte_b |= (uint8_t)((instruction_size_from_suffix - 1) << BF_REG_OPR_REG_INST_BYTE_B_SIZE_SHIFT);

  char *new_instruction_buffer = s12z_new_insn(3 + operand_n_bytes);
  char *current_output_position = new_instruction_buffer;

  number_to_chars_bigendian(current_output_position++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(current_output_position++, (uint8_t)(BF_REG_OPR_REG_INST_BYTE_B_OPCODE_PART | destination_register_d_index), 1);
  number_to_chars_bigendian(current_output_position++, instruction_byte_b, 1);

  emit_opr(current_output_position, operand_buffer, operand_n_bytes, &operand_expression);

  return true;
}



static bool
bfe_reg_reg_reg  (const struct instruction *insn)
{
  const int BF_DEFAULT_FLAG_VALUE = 0;

  if (insn == NULL) {
    return false;
  }

  return bf_reg_reg_reg (insn, BF_DEFAULT_FLAG_VALUE);
}

static bool
bfi_reg_reg_reg  (const struct instruction *insn)
{
  enum { INSERT_FLAG = 1 };
  return bf_reg_reg_reg (insn, INSERT_FLAG);
}

static const int BF_MODE_EXTRACT = 0;

static bool
bfe_reg_reg_imm  (const struct instruction *insn)
{
  return bf_reg_reg_imm (insn, BF_MODE_EXTRACT);
}

static bool
bfi_reg_reg_imm  (const struct instruction *insn)
{
  return bf_reg_reg_imm (insn, true);
}


#ifndef BF_DEFAULT_OPERATION_MODE
#define BF_DEFAULT_OPERATION_MODE 0
#endif

static bool
bfe_reg_opr_reg(const struct instruction *insn)
{
  return bf_reg_opr_reg(insn, BF_DEFAULT_OPERATION_MODE);
}

#include <stdbool.h>

static bool
bfi_reg_opr_reg  (const struct instruction *insn)
{
  return bf_reg_opr_reg (insn, true);
}


#define BFE_DEFAULT_OPERAND_OPTION 0

static bool
bfe_opr_reg_reg  (const struct instruction *insn)
{
  return bf_opr_reg_reg (insn, BFE_DEFAULT_OPERAND_OPTION);
}

#define BFI_IMMEDIATE_OPERATION_VALUE 1

static bool
bfi_opr_reg_reg  (const struct instruction *insn)
{
  return bf_opr_reg_reg (insn, BFI_IMMEDIATE_OPERATION_VALUE);
}

enum {
  BFE_IMMEDIATE_DEFAULT_VALUE = 0
};

static bool
bfe_reg_opr_imm  (const struct instruction *insn)
{
  if (insn == NULL) {
    return false;
  }
  return bf_reg_opr_imm (insn, BFE_IMMEDIATE_DEFAULT_VALUE);
}

static bool
bfi_reg_opr_imm  (const struct instruction *insn)
{
  return bf_reg_opr_imm (insn, true);
}

static const int BFE_DEFAULT_IMMEDIATE_ARG = 0;

static bool
bfe_opr_reg_imm(const struct instruction *insn)
{
  if (insn == NULL) {
    return false;
  }
  return bf_opr_reg_imm(insn, BFE_DEFAULT_IMMEDIATE_ARG);
}

static const int BF_OPERAND_MODE_IMMEDIATE = 1;

static bool
bfi_opr_reg_imm  (const struct instruction *insn)
{
  return bf_opr_reg_imm (insn, BF_OPERAND_MODE_IMMEDIATE);
}




static bool
tb_reg_rel  (const struct instruction *insn)
{
  char *original_input_lp = input_line_pointer;

  int reg;
  if (!lex_reg_name (REG_BIT_Dn | REG_BIT_XY, &reg))
    goto fail;

  if (!lex_match (','))
    goto fail;

  bool long_displacement;
  expressionS exp;
  if (!lex_15_bit_offset (&long_displacement, &exp))
    goto fail;

  uint8_t lb = 0x00;

  // Encode register (D0-D7, X, Y) into bits 0-3
  if (reg == REG_X)
    {
      lb |= 0x08; // Specific encoding for X register
    }
  else if (reg == REG_Y)
    {
      lb |= 0x09; // Specific encoding for Y register (0x08 | 0x01)
    }
  else /* Assume Dn registers map directly to their value (0-7) */
    {
      lb |= (uint8_t)reg;
    }

  // Encode condition code (ne, eq, pl, mi, gt, le) into bits 4-6
  const char *condition_suffix = insn->name + 2;
  if (startswith (condition_suffix, "ne"))
    lb |= (0x00 << 4);
  else if (startswith (condition_suffix, "eq"))
    lb |= (0x01 << 4);
  else if (startswith (condition_suffix, "pl"))
    lb |= (0x02 << 4);
  else if (startswith (condition_suffix, "mi"))
    lb |= (0x03 << 4);
  else if (startswith (condition_suffix, "gt"))
    lb |= (0x04 << 4);
  else if (startswith (condition_suffix, "le"))
    lb |= (0x05 << 4);
  // If no condition matches, bits 4-6 remain 0x00, which corresponds to 'ne'.

  // Encode instruction prefix ('d' or 't') into bit 7
  switch (insn->name[0])
    {
    case 'd':
      lb |= 0x80; // Set bit 7 for 'd' prefix
      break;
    case 't':
      // 't' prefix does not set any specific bit in 'lb', bit 7 remains 0.
      break;
    default:
      // This indicates an unsupported instruction prefix.
      gas_assert (0);
      break;
    };

  char *insn_bytes = s12z_new_insn (long_displacement ? 4 : 3);
  number_to_chars_bigendian (insn_bytes++, insn->opc, 1);
  number_to_chars_bigendian (insn_bytes++, lb, 1);

  emit_15_bit_offset (insn_bytes, 4, &exp);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = original_input_lp; // Restore parser state on failure
  return false;
}


#define TB_COND_NE 0x00
#define TB_COND_EQ 0x01
#define TB_COND_PL 0x02
#define TB_COND_MI 0x03
#define TB_COND_GT 0x04
#define TB_COND_LE 0x05

#define TB_LB_BASE 0x0C
#define TB_LB_D_BIT 0x80

static uint8_t
get_condition_code_bits(const char *name_suffix)
{
  if (startswith(name_suffix, "ne"))
    return TB_COND_NE << 4;
  if (startswith(name_suffix, "eq"))
    return TB_COND_EQ << 4;
  if (startswith(name_suffix, "pl"))
    return TB_COND_PL << 4;
  if (startswith(name_suffix, "mi"))
    return TB_COND_MI << 4;
  if (startswith(name_suffix, "gt"))
    return TB_COND_GT << 4;
  if (startswith(name_suffix, "le"))
    return TB_COND_LE << 4;
  return 0;
}

static bool
tb_opr_rel  (const struct instruction *insn)
{
  char *ilp = input_line_pointer;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  if (!lex_opr (buffer, &n_bytes, &exp, false))
    goto fail;

  if (!lex_match (','))
    goto fail;

  bool long_displacement;
  expressionS exp2;
  if (! lex_15_bit_offset (&long_displacement, &exp2))
    goto fail;

  uint8_t lb = TB_LB_BASE;

  lb |= get_condition_code_bits(insn->name + 2);

  switch (insn->name[0])
    {
    case 'd':
      lb |= TB_LB_D_BIT;
      break;
    case 't':
      break;
    default:
      gas_assert (0);
      break;
    };

  int size = size_from_suffix (insn, 0);

  lb |= size - 1;

  int insn_mem_size = n_bytes + (long_displacement ? 4 : 3);
  char *f = s12z_new_insn (insn_mem_size);

  number_to_chars_bigendian (f, insn->opc, 1);
  f += 1;
  number_to_chars_bigendian (f, lb, 1);
  f += 1;
  f = emit_opr (f, buffer, n_bytes, &exp);

  emit_15_bit_offset (f, n_bytes + 4, &exp2);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}




static bool
test_br_reg_reg_rel(const struct instruction *insn)
{
  char *initial_input_line_pointer = input_line_pointer;
  int Di = 0;
  int Dn = 0;
  bool long_displacement = false;
  expressionS exp;
  uint8_t bm;
  uint8_t xb;
  char *f;
  int insn_len;

  if (!lex_reg_name(REG_BIT_Dn, &Di)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_input_line_pointer;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_input_line_pointer;
    return false;
  }

  if (!lex_reg_name(REG_BIT_Dn, &Dn)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_input_line_pointer;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_input_line_pointer;
    return false;
  }

  if (!lex_15_bit_offset(&long_displacement, &exp)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_input_line_pointer;
    return false;
  }

  bm = 0x81 | (uint8_t)(Dn << 4);
  xb = 0xb8 | (uint8_t)Di;

  insn_len = long_displacement ? 5 : 4;
  f = s12z_new_insn(insn_len);

  number_to_chars_bigendian(f, insn->opc, 1);
  f++;
  number_to_chars_bigendian(f, bm, 1);
  f++;
  number_to_chars_bigendian(f, xb, 1);
  f++;

  emit_15_bit_offset(f, 5, &exp);

  return true;
}

static bool
test_br_opr_reg_rel  (const struct instruction *insn)
{
  char *initial_input_line_pointer = input_line_pointer;
  bool parsing_succeeded = false;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  int Dn = 0;
  uint8_t bm;
  int size;
  bool long_displacement;
  expressionS exp2;
  int n;
  char *instruction_buffer_ptr;

  do {
    if (!lex_opr (buffer, &n_bytes,  &exp, false)) {
      break;
    }

    if (!lex_match (',')) {
      break;
    }

    if (!lex_reg_name (REG_BIT_Dn, &Dn)) {
      break;
    }

    if (!lex_match (',')) {
      break;
    }

    bm = 0x81;
    bm |= (uint8_t)Dn << 4;
    size = size_from_suffix (insn, 0);
    bm |= (uint8_t)((size - 1) << 2);

    if (!lex_15_bit_offset (&long_displacement, &exp2)) {
      break;
    }

    n = n_bytes + (long_displacement ? 4 : 3);
    instruction_buffer_ptr = s12z_new_insn (n);
    // Assuming s12z_new_insn always returns a valid pointer if 'n' is reasonable,
    // or handles internal errors. If it can return NULL, a check should be added here.

    number_to_chars_bigendian (instruction_buffer_ptr++, insn->opc, 1);
    number_to_chars_bigendian (instruction_buffer_ptr++, bm, 1);
    instruction_buffer_ptr = emit_opr (instruction_buffer_ptr, buffer, n_bytes, &exp);

    emit_15_bit_offset (instruction_buffer_ptr, n, &exp2);

    parsing_succeeded = true;
  } while (0);

  if (!parsing_succeeded) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_input_line_pointer;
  }

  return parsing_succeeded;
}


static bool
test_br_opr_imm_rel  (const struct instruction *insn)
{
  char * const initial_line_pointer = input_line_pointer;

  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;

  if (!lex_opr (buffer, &n_bytes, &exp, false))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
    return false;
  }

  if (!lex_match (','))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
    return false;
  }

  long imm;
  if (!lex_imm (&imm, NULL))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
    return false;
  }

  if (imm < 0 || imm > 31)
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
    return false;
  }

  if (!lex_match (','))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
    return false;
  }

  bool long_displacement;
  expressionS exp2;
  if (!lex_15_bit_offset (&long_displacement, &exp2))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
    return false;
  }

  const int size = size_from_suffix (insn, 0);

  uint8_t bm = 0x80;
  bm |= (uint8_t)((imm & 0x07) << 4);
  bm |= (uint8_t)((imm >> 3) & 0x03);

  if (size == 4)
  {
    bm |=  0x08;
  }
  else if  (size == 2)
  {
    bm |= 0x02;
  }

  const int total_insn_len = 1 + 1 + n_bytes + (long_displacement ? 4 : 3);
  char *current_insn_ptr = s12z_new_insn (total_insn_len);

  number_to_chars_bigendian (current_insn_ptr++, insn->opc, 1);
  number_to_chars_bigendian (current_insn_ptr++, bm, 1);
  current_insn_ptr = emit_opr (current_insn_ptr, buffer, n_bytes, &exp);

  emit_15_bit_offset (current_insn_ptr, n_bytes + 4,  &exp2);

  return true;
}


static bool
test_br_reg_imm_rel  (const struct instruction *insn)
{
  char *original_input_line_pointer = input_line_pointer;

  int reg_index = 0;
  if (!lex_reg_name (REG_BIT_Dn, &reg_index)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  long immediate_value;
  if (!lex_imm (&immediate_value, NULL)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (immediate_value < 0 || immediate_value > 31) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  if (!lex_match (',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  bool long_displacement;
  expressionS exp;
  if (! lex_15_bit_offset (&long_displacement, &exp)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_line_pointer;
    return false;
  }

  uint8_t bm_byte = (uint8_t)reg_index;
  bm_byte |= (uint8_t)(immediate_value << 3);

  char *insn_bytes = s12z_new_insn (long_displacement ? 4 : 3);
  // The original code does not check if s12z_new_insn returns NULL.
  // Adding a NULL check here would improve reliability/security but might
  // alter external functionality if the original code was expected to crash
  // or proceed with a NULL pointer in such a scenario. Preserving original behavior.

  char *current_byte_ptr = insn_bytes;
  number_to_chars_bigendian (current_byte_ptr++, insn->opc, 1);
  number_to_chars_bigendian (current_byte_ptr++, bm_byte, 1);

  // The '4' parameter to emit_15_bit_offset is preserved from the original code.
  // It is assumed to be handled correctly by the emit_15_bit_offset function
  // even when long_displacement is false and the instruction size is 3 bytes,
  // to avoid buffer overflow (e.g., if it means the maximum possible size,
  // and the actual size is determined internally from 'exp' or other context).
  emit_15_bit_offset (current_byte_ptr, 4, &exp);

  return true;
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
  char name[20];
  size_t nlen = 0;
  const char *p = str;
  const size_t max_name_len = sizeof(name) - 1;

  fail_line_pointer = NULL;

  while (!is_end_of_stmt(*p) && !is_whitespace(*p))
    {
      if (nlen == max_name_len)
        {
          as_bad(_("Opcode name \"%.*s...\" is too long. Maximum %zu characters allowed."),
                 (int)max_name_len, str, max_name_len);
          name[max_name_len] = 0;
          fail_line_pointer = str;
          input_line_pointer = p;
          while (*input_line_pointer++)
            ;
          return;
        }
      name[nlen++] = TOLOWER(*p);
      p++;
    }
  name[nlen] = 0;

  if (nlen == 0)
    {
      as_bad(_("No instruction or missing opcode."));
      return;
    }

  input_line_pointer = skip_whites(p);

  for (size_t i = 0; i < sizeof(opcodes) / sizeof(opcodes[0]); ++i)
    {
      const struct instruction *opc = opcodes + i;
      if (0 == strcmp(name, opc->name))
        {
          if (opc->parse_operands(opc))
            return;
          return;
        }
    }

  as_bad(_("Invalid instruction: \"%s\""), str);
  fail_line_pointer = str;
  as_bad(_("First invalid token: \"%s\""), fail_line_pointer);
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
  assert(fixP != NULL);
  assert(fixP->fx_frag != NULL);

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
s12z_relax_frag (segT seg, fragS *fragP,
                   long stretch)
{
  (void)seg;
  (void)fragP;
  (void)stretch;
  return 0;
}

void
md_convert_frag (bfd *abfd, asection *sec, fragS *fragP)
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
int
md_estimate_size_before_relax (fragS *fragP ATTRIBUTE_UNUSED, asection *segment ATTRIBUTE_UNUSED)
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
  arelent *reloc = NULL;
  asymbol **sym_ptr_ptr = NULL;

  reloc = notes_alloc (sizeof (arelent));
  if (reloc == NULL)
    {
      return NULL;
    }
  reloc->sym_ptr_ptr = NULL;

  sym_ptr_ptr = notes_alloc (sizeof (asymbol *));
  if (sym_ptr_ptr == NULL)
    {
      notes_free (reloc);
      return NULL;
    }
  reloc->sym_ptr_ptr = sym_ptr_ptr;

  *reloc->sym_ptr_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;

  reloc->howto = bfd_reloc_type_lookup (stdoutput, fixp->fx_r_type);
  if (reloc->howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
		    _("Relocation %d is not supported by object file format."),
		    (int) fixp->fx_r_type);
      notes_free (reloc->sym_ptr_ptr);
      notes_free (reloc);
      return NULL;
    }

  if (!(section->flags & SEC_CODE))
    reloc->addend = fixp->fx_offset;
  else
    reloc->addend = fixp->fx_addnumber;

  return reloc;
}

/* See whether we need to force a relocation into the output file.  */
int
tc_s12z_force_relocation (fixS *fixP)
{
  if (fixP == NULL) {
    return -1;
  }
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

  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_8:
      where[0] = (char)value;
      break;
    case BFD_RELOC_16:
      bfd_putb16 (value, where);
      break;
    case BFD_RELOC_24:
      bfd_putb24 (value, where);
      break;
    case BFD_RELOC_S12Z_OPR:
      {
        switch (fixP->fx_size)
          {
          case 3:
            bfd_putb24 (value, where);
            break;
          case 2:
            bfd_putb16 (value, where);
            break;
          default:
            as_fatal (_("Line %d: unknown size for BFD_RELOC_S12Z_OPR: %d."),
                      fixP->fx_line, fixP->fx_size);
            break;
          }
      }
      break;
    case BFD_RELOC_32:
      bfd_putb32 (value, where);
      break;
    case BFD_RELOC_16_PCREL:
      {
        static const long PCREL_16_MIN_VALUE = -0x4000L;
        static const long PCREL_16_MAX_VALUE = 0x3FFFL;
        static const unsigned short PCREL_16_FLAG_MASK = 0x8000U;

        if (value < PCREL_16_MIN_VALUE || value > PCREL_16_MAX_VALUE)
          as_bad_where (fixP->fx_file, fixP->fx_line,
                        _("Value out of 16-bit range."));

        bfd_putb16 (value | PCREL_16_FLAG_MASK, where);
      }
      break;

    default:
      as_fatal (_("Line %d: unknown relocation type: 0x%x."),
                fixP->fx_line, fixP->fx_r_type);
      break;
    }
}

/* Set the ELF specific flags.  */
void
s12z_elf_final_processing (void)
{
}
