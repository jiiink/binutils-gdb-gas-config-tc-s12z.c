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
  if (str == NULL || endptr == NULL)
    {
      if (endptr != NULL)
        *endptr = (char *)str;
      return 0;
    }

  const char *start = str;
  bool negative = false;
  int base = 0;

  if (*str == '-')
    {
      negative = true;
      str++;
    }
  else if (*str == '+')
    {
      str++;
    }

  if (literal_prefix_dollar_hex && *str == '$')
    {
      base = 16;
      str++;
    }

  char *local_endptr;
  errno = 0;
  long result = strtol(str, &local_endptr, base);
  
  if (local_endptr == str)
    {
      *endptr = (char *)start;
      return 0;
    }
  
  *endptr = local_endptr;
  
  if (errno == ERANGE)
    return negative ? LONG_MIN : LONG_MAX;
  
  return negative ? -result : result;
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
const char *s12z_listing_header(void)
{
    static const char header[] = "S12Z GAS ";
    return header;
}

void md_show_usage(FILE *stream)
{
    if (stream == NULL) {
        return;
    }
    
    const char *messages[] = {
        _("\ns12z options:\n"),
        _("  -mreg-prefix=PREFIX     set a prefix used to indicate register names (default none)\n"),
        _("  -mdollar-hex            the prefix '$' instead of '0x' is used to indicate literal hexadecimal constants\n")
    };
    
    for (size_t i = 0; i < sizeof(messages) / sizeof(messages[0]); i++) {
        if (fputs(messages[i], stream) == EOF) {
            break;
        }
    }
}

void s12z_print_statistics(FILE *file ATTRIBUTE_UNUSED)
{
    (void)file;
}

int
md_parse_option (int c, const char *arg)
{
  switch (c)
    {
    case OPTION_REG_PREFIX:
      if (arg == NULL)
        return 0;
      free(register_prefix);
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
md_atof (int type, char *litP, int *sizeP)
{
  if (litP == NULL || sizeP == NULL)
    {
      return "Invalid parameters";
    }
  return ieee_md_atof (type, litP, sizeP, true);
}

valueT
md_section_align (asection *seg, valueT addr)
{
  int align = bfd_section_alignment (seg);
  valueT alignment_mask = (valueT) 1 << align;
  valueT inverse_mask = -alignment_mask;
  return (addr + alignment_mask - 1) & inverse_mask;
}

void md_begin(void)
{
}

void
s12z_init_after_args (void)
{
  literal_prefix_dollar_hex = flag_traditional_format;
}

/* Builtin help.  */


static char *skip_whites(char *p)
{
    if (p == NULL) {
        return NULL;
    }
    
    while (*p != '\0' && is_whitespace(*p)) {
        p++;
    }
    
    return p;
}



/* Start a new insn that contains at least 'size' bytes.  Record the
   line information of that insn in the dwarf2 debug sections.  */
static char *s12z_new_insn(int size)
{
    if (size <= 0) {
        return NULL;
    }
    
    char *fragment = frag_more(size);
    if (fragment == NULL) {
        return NULL;
    }
    
    dwarf2_emit_insn(size);
    
    return fragment;
}



static bool lex_reg_name (uint16_t which, int *reg);

static bool
lex_constant (long *v)
{
  char *end = NULL;
  char *saved_position = input_line_pointer;
  int dummy;
  
  if (lex_reg_name (~0, &dummy))
    {
      input_line_pointer = saved_position;
      return false;
    }

  errno = 0;
  *v = s12z_strtol (saved_position, &end);
  if (errno != 0 || end == saved_position)
    {
      return false;
    }

  input_line_pointer = end;
  return true;
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
  char *saved_pointer = input_line_pointer;
  int dummy;
  
  exp->X_op = O_absent;

  if (lex_match ('#'))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  if (lex_reg_name (~0, &dummy))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  expression (exp);
  
  if (exp->X_op != O_absent)
    {
      return true;
    }

  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_pointer;
  return false;
}

/* Immediate operand.
   If EXP_O is non-null, then a symbolic expression is permitted,
   in which case, EXP_O will be populated with the parsed expression.
 */
static bool
lex_imm (long *v, expressionS *exp_o)
{
  char *saved_pointer = input_line_pointer;
  expressionS exp;

  if (*input_line_pointer != '#')
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  input_line_pointer++;
  
  if (!lex_expression (&exp))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  if (exp.X_op != O_constant)
    {
      if (exp_o == NULL)
        {
          as_bad (_("A non-constant expression is not permitted here"));
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
static bool
lex_imm_e4 (long *val)
{
  char *saved_pointer = input_line_pointer;
  
  if (!lex_imm(val, NULL))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }
  
  if (*val == -1 || (*val > 0 && *val <= 15))
    {
      return true;
    }
  
  fail_line_pointer = input_line_pointer;
  input_line_pointer = saved_pointer;
  return false;
}

static bool
lex_match_string (const char *s)
{
  if (s == NULL || input_line_pointer == NULL)
    return false;

  size_t s_len = strlen (s);
  const char *p = input_line_pointer;
  
  while (*p != '\0' && !is_whitespace (*p) && !is_end_of_stmt (*p))
    {
      p++;
    }

  size_t token_len = p - input_line_pointer;
  
  if (token_len != s_len)
    return false;

  if (strncasecmp (s, input_line_pointer, token_len) == 0)
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
lex_reg_name (uint16_t which, int *reg)
{
  if (input_line_pointer == NULL || reg == NULL)
    return false;

  char *p = input_line_pointer;

  if (register_prefix != NULL)
    {
      size_t prefix_len = strlen (register_prefix);
      if (strncmp (register_prefix, p, prefix_len) != 0)
        return false;
      p += prefix_len;
    }

  char *start_of_reg_name = p;

  while ((*p >= 'a' && *p <= 'z') ||
         (*p >= '0' && *p <= '9') ||
         (*p >= 'A' && *p <= 'Z'))
    {
      p++;
    }

  size_t len = p - start_of_reg_name;

  if (len == 0)
    return false;

  for (int i = 0; i < S12Z_N_REGISTERS; i++)
    {
      gas_assert (registers[i].name);

      if (strlen (registers[i].name) == len &&
          strncasecmp (registers[i].name, start_of_reg_name, len) == 0 &&
          ((1U << i) & which) != 0)
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

static bool
lex_opr (uint8_t *buffer, int *n_bytes, expressionS *exp,
	 bool immediate_ok)
{
  char *ilp = input_line_pointer;
  uint8_t *xb = buffer;
  int reg;
  long imm;
  exp->X_op = O_absent;
  *n_bytes = 0;
  *xb = 0;

  if (lex_imm_e4 (&imm))
    {
      if (!immediate_ok)
	{
	  as_bad (_("An immediate value in a source operand is inappropriate"));
	  return false;
	}
      *xb = (imm > 0) ? (imm | 0x70) : 0x70;
      *n_bytes = 1;
      return true;
    }

  if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      *xb = reg | 0xb8;
      *n_bytes = 1;
      return true;
    }

  if (lex_match ('['))
    return handle_bracket_expression(buffer, n_bytes, exp, xb, ilp);

  if (lex_match ('('))
    return handle_paren_expression(buffer, n_bytes, xb, ilp);

  if (lex_expression (exp))
    return handle_simple_expression(buffer, n_bytes, exp, xb);

  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
handle_bracket_expression(uint8_t *buffer, int *n_bytes, expressionS *exp, uint8_t *xb, char *ilp)
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
	      goto fail;
	    }
	  setup_constant_offset(buffer, n_bytes, xb, c, reg);
	}
      else
	{
	  *xb = 0xfe;
	  *n_bytes = 4;
	  buffer[1] = c >> 16;
	  buffer[2] = c >> 8;
	  buffer[3] = c;
	}
    }
  else if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      if (!lex_force_match (','))
	goto fail;

      int reg2;
      if (!lex_reg_name (REG_BIT_XY, &reg2))
	{
	  as_bad (_("Invalid operand for register offset"));
	  goto fail;
	}
      *n_bytes = 1;
      *xb = reg | ((reg2 - REG_X) << 4) | 0xc8;
    }
  else
    {
      goto fail;
    }

  if (!lex_force_match (']'))
    goto fail;
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static void
setup_constant_offset(uint8_t *buffer, int *n_bytes, uint8_t *xb, long c, int reg)
{
  if (c <= 255 && c >= -256)
    {
      *n_bytes = 2;
      *xb = 0xc4;
    }
  else
    {
      *n_bytes = 4;
      *xb = 0xc6;
    }
  *xb |= (reg - REG_X) << 4;

  if (c < 0)
    *xb |= 0x01;
    
  for (int i = 1; i < *n_bytes; ++i)
    {
      buffer[i] = c >> (8 * (*n_bytes - i - 1));
    }
}

static bool
handle_paren_expression(uint8_t *buffer, int *n_bytes, uint8_t *xb, char *ilp)
{
  long c;
  int reg;
  
  if (lex_constant (&c))
    {
      if (!lex_force_match (','))
	goto fail;
      return handle_constant_paren(buffer, n_bytes, xb, c, ilp);
    }

  if (lex_reg_name (REG_BIT_Dn, &reg))
    {
      if (!lex_match (','))
	goto fail;
      return handle_register_offset(buffer, n_bytes, xb, reg, ilp);
    }

  if (lex_reg_name (REG_BIT_XYS, &reg))
    return handle_postdec_preinc(n_bytes, xb, reg, ilp);

  if (lex_match ('+'))
    return handle_preincrement(n_bytes, xb, ilp);

  if (lex_match ('-'))
    return handle_predecrement(n_bytes, xb, ilp);

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
handle_constant_paren(uint8_t *buffer, int *n_bytes, uint8_t *xb, long c, char *ilp)
{
  int reg2;
  
  if (lex_reg_name (REG_BIT_XYSP, &reg2))
    {
      setup_xysp_constant(buffer, n_bytes, xb, c, reg2);
    }
  else if (lex_reg_name (REG_BIT_Dn, &reg2))
    {
      setup_dn_constant(buffer, n_bytes, xb, c, reg2);
    }
  else
    {
      as_bad (_("Bad operand for constant offset"));
      goto fail;
    }

  if (!lex_match (')'))
    goto fail;
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static void
setup_xysp_constant(uint8_t *buffer, int *n_bytes, uint8_t *xb, long c, int reg2)
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
}

static void
setup_dn_constant(uint8_t *buffer, int *n_bytes, uint8_t *xb, long c, int reg2)
{
  if (c >= -1 * (1L << 17) && c < (1L << 17) - 1)
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
}

static bool
handle_register_offset(uint8_t *buffer, int *n_bytes, uint8_t *xb, int reg, char *ilp)
{
  int reg2;
  
  if (!lex_reg_name (REG_BIT_XYS, &reg2))
    {
      as_bad (_("Invalid operand for register offset"));
      goto fail;
    }
  
  *n_bytes = 1;
  *xb = 0x88 | ((reg2 - REG_X) << 4) | reg;
  
  if (!lex_match (')'))
    goto fail;
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
handle_postdec_preinc(int *n_bytes, uint8_t *xb, int reg, char *ilp)
{
  *n_bytes = 1;
  
  if (lex_match ('-'))
    {
      if (reg == REG_S)
	{
	  as_bad (_("Invalid register for postdecrement operation"));
	  goto fail;
	}
      *xb = (reg == REG_X) ? 0xc7 : 0xd7;
    }
  else if (lex_match ('+'))
    {
      if (reg == REG_X)
	*xb = 0xe7;
      else if (reg == REG_Y)
	*xb = 0xf7;
      else if (reg == REG_S)
	*xb = 0xff;
    }
  else
    {
      goto fail;
    }

  if (!lex_match (')'))
    goto fail;
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
handle_preincrement(int *n_bytes, uint8_t *xb, char *ilp)
{
  int reg;
  
  if (!lex_reg_name (REG_BIT_XY, &reg))
    {
      as_bad (_("Invalid register for preincrement operation"));
      goto fail;
    }
  
  *n_bytes = 1;
  *xb = (reg == REG_X) ? 0xe3 : 0xf3;
  
  if (!lex_match (')'))
    goto fail;
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
handle_predecrement(int *n_bytes, uint8_t *xb, char *ilp)
{
  int reg;
  
  if (!lex_reg_name (REG_BIT_XYS, &reg))
    {
      as_bad (_("Invalid register for predecrement operation"));
      goto fail;
    }
  
  *n_bytes = 1;
  if (reg == REG_X)
    *xb = 0xc3;
  else if (reg == REG_Y)
    *xb = 0xd3;
  else if (reg == REG_S)
    *xb = 0xfb;
  
  if (!lex_match (')'))
    goto fail;
  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
handle_simple_expression(uint8_t *buffer, int *n_bytes, expressionS *exp, uint8_t *xb)
{
  *xb = 0xfa;
  *n_bytes = 4;
  buffer[1] = 0;
  buffer[2] = 0;
  buffer[3] = 0;
  
  if (exp->X_op == O_constant)
    {
      valueT value = exp->X_add_number;

      if (value < (0x1U << 14))
	{
	  *xb = value >> 8;
	  *n_bytes = 2;
	  buffer[1] = value;
	}
      else if (value < (0x1U << 19))
	{
	  *xb = 0xf8;
	  if (value & (0x1U << 17))
	    *xb |= 0x04;
	  if (value & (0x1U << 16))
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
  return true;
}

static bool
lex_offset (long *val)
{
  char *end = NULL;
  char *p = input_line_pointer;

  if (*p != '*')
    return false;
  
  p++;
  
  if (*p != '+' && *p != '-')
    return false;

  bool negative = (*p == '-');
  p++;

  errno = 0;
  *val = s12z_strtol (p, &end);
  
  if (errno != 0)
    return false;
    
  if (negative)
    *val = -(*val);
    
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
  if (exp == NULL || f == NULL) {
    return;
  }

  if (exp->X_op == O_absent || exp->X_op == O_constant) {
    return;
  }

  fixS *fix = fix_new_exp (frag_now,
                           f - frag_now->fr_literal,
                           size,
                           exp,
                           false,
                           reloc);
  if (fix != NULL) {
    fix->fx_addnumber = 0x00;
  }
}

/* Emit the code for an OPR address mode operand */
static char *
emit_opr (char *f, const uint8_t *buffer, int n_bytes, expressionS *exp)
{
  if (f == NULL || buffer == NULL || exp == NULL || n_bytes <= 0)
    return f;

  number_to_chars_bigendian (f, buffer[0], 1);
  f++;

  emit_reloc (exp, f, 3, BFD_RELOC_S12Z_OPR);

  for (int i = 1; i < n_bytes; i++)
    {
      number_to_chars_bigendian (f, buffer[i], 1);
      f++;
    }

  return f;
}

/* Emit the code for a 24 bit direct address operand */
static char *emit_ext24(char *f, long v)
{
    if (f == NULL) {
        return NULL;
    }
    
    number_to_chars_bigendian(f, v, 3);
    return f + 3;
}

static bool
opr (const struct instruction *insn)
{
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  
  if (!lex_opr (buffer, &n_bytes, &exp, false))
    return false;

  if (exp.X_op == O_constant && buffer[0] == 0xFA && insn->alt_opc != 0)
    {
      char *f = s12z_new_insn (4);
      gas_assert (insn->page == 1);
      number_to_chars_bigendian (f++, insn->alt_opc, 1);
      emit_ext24 (f, exp.X_add_number);
    }
  else
    {
      char *f = s12z_new_insn (n_bytes + 1);
      number_to_chars_bigendian (f++, insn->opc, 1);
      emit_opr (f, buffer, n_bytes, &exp);
    }
    
  return true;
}

/* Parse a 15 bit offset, as an expression.
   LONG_DISPLACEMENT will be set to true if the offset is wider than 7 bits.
   */
static bool
lex_15_bit_offset (bool *long_displacement, expressionS *exp)
{
  char *saved_input = input_line_pointer;
  long val = 0;
  bool has_value = false;

  if (lex_offset (&val))
    {
      exp->X_op = O_absent;
      exp->X_add_number = val;
      has_value = true;
    }
  else if (lex_expression (exp))
    {
      if (exp->X_op == O_constant)
        {
          val = exp->X_add_number;
          has_value = true;
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
      input_line_pointer = saved_input;
      return false;
    }

  if (!has_value)
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_input;
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
  if (!exp || !f)
    return;

  if (exp->X_op != O_absent && exp->X_op != O_constant)
    {
      exp->X_add_number += where;
      fixS *fix = fix_new_exp (frag_now,
                               f - frag_now->fr_literal,
                               2,
                               exp,
                               true,
                               BFD_RELOC_16_PCREL);
      if (fix)
        fix->fx_addnumber = where - 2;
    }
  else
    {
      long val = exp->X_add_number;
      bool is_long = (val > 63 || val < -64);
      
      if (is_long)
        val |= 0x8000;
      else
        val &= 0x7F;

      number_to_chars_bigendian (f, val, is_long ? 2 : 1);
    }
}

static bool
rel(const struct instruction *insn)
{
  bool long_displacement;
  expressionS exp;
  char *f;
  
  if (!lex_15_bit_offset(&long_displacement, &exp))
    return false;

  f = s12z_new_insn(long_displacement ? 3 : 2);
  if (!f)
    return false;
    
  number_to_chars_bigendian(f, insn->opc, 1);
  emit_15_bit_offset(f + 1, 3, &exp);
  
  return true;
}

static bool
reg_inh(const struct instruction *insn)
{
    int reg;
    
    if (!lex_reg_name(REG_BIT_Dn, &reg)) {
        return false;
    }
    
    char *f = s12z_new_insn(insn->page);
    if (f == NULL) {
        return false;
    }
    
    if (insn->page == 2) {
        number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
        f++;
    }
    
    number_to_chars_bigendian(f, insn->opc + reg, 1);
    
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
  if (!f)
    return false;

  number_to_chars_bigendian (f, 0x9a + reg - REG_X, 1);
  return true;
}

/* Some instructions have a suffix like ".l", ".b", ".w" etc
   which indicates the size of the operands. */
static int
size_from_suffix(const struct instruction *insn, int idx)
{
  if (insn == NULL || insn->name == NULL) {
    return -3;
  }

  const char *dot = strchr(insn->name, '.');
  if (dot == NULL) {
    return -3;
  }

  if (idx < 0 || dot[1 + idx] == '\0') {
    return -2;
  }

  switch (dot[1 + idx]) {
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
      return -2;
  }
}

static bool
mul_reg_reg_reg (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd, Dj, Dk;

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

  char *f = s12z_new_insn (insn->page + 1);
  if (insn->page == 2)
    number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);

  number_to_chars_bigendian (f++, insn->opc + Dd, 1);
  
  const char *dot = strchrnul (insn->name, '.');
  if (dot == insn->name)
    {
      as_fatal (_("BAD MUL"));
      goto fail;
    }
  
  uint8_t mb = (dot[-1] == 's') ? 0x80 : 0x00;
  if (dot[-1] != 's' && dot[-1] != 'u')
    {
      as_fatal (_("BAD MUL"));
      goto fail;
    }

  mb |= (Dj << 3) | Dk;
  number_to_chars_bigendian (f++, mb, 1);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool
mul_reg_reg_imm (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd = 0;
  int Dj = 0;
  long imm = 0;
  char *f = NULL;
  uint8_t mb = 0x44;
  int size = 0;
  const char *dot = NULL;
  char sign_char = '\0';

  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (REG_BIT_Dn, &Dj))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_imm (&imm, NULL))
    goto fail;

  size = size_from_suffix (insn, 0);

  f = s12z_new_insn (insn->page + 1 + size);
  if (insn->page == 2)
    number_to_chars_bigendian (f++, PAGE2_PREBYTE, 1);

  number_to_chars_bigendian (f++, insn->opc + Dd, 1);
  
  dot = strchrnul (insn->name, '.');
  if (dot > insn->name)
    sign_char = dot[-1];
  
  if (sign_char == 's')
    mb |= 0x80;
  else if (sign_char != 'u')
    as_fatal (_("BAD MUL"));

  mb |= Dj << 3;
  mb |= size - 1;

  number_to_chars_bigendian (f++, mb, 1);
  number_to_chars_bigendian (f++, imm, size);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool
mul_reg_reg_opr (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd;
  int Dj;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  int size;
  char *f;
  uint8_t mb;
  const char *dot;

  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_reg_name (REG_BIT_Dn, &Dj))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_opr (buffer, &n_bytes, &exp, true))
    goto fail;

  size = size_from_suffix (insn, 0);

  f = s12z_new_insn (insn->page + 1 + n_bytes);
  if (insn->page == 2)
    {
      number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
      f++;
    }

  number_to_chars_bigendian (f, insn->opc + Dd, 1);
  f++;
  
  mb = 0x40;
  dot = strchrnul (insn->name, '.');
  if (dot > insn->name)
    {
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
    }

  mb |= (Dj << 3) | (size - 1);

  number_to_chars_bigendian (f, mb, 1);
  f++;

  emit_opr (f, buffer, n_bytes, &exp);

  return true;

 fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}

static bool
mul_reg_opr_opr (const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int Dd;
  uint8_t buffer1[4];
  uint8_t buffer2[4];
  int n_bytes1;
  int n_bytes2;
  expressionS exp1;
  expressionS exp2;
  uint8_t mb;
  const char *dot;
  char *f;
  int size1;
  int size2;

  if (!lex_reg_name (REG_BIT_Dn, &Dd))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_opr (buffer1, &n_bytes1, &exp1, false))
    goto fail;

  if (!lex_match (','))
    goto fail;

  if (!lex_opr (buffer2, &n_bytes2, &exp2, false))
    goto fail;

  size1 = size_from_suffix (insn, 0);
  size2 = size_from_suffix (insn, 1);

  f = s12z_new_insn (insn->page + 1 + n_bytes1 + n_bytes2);
  if (insn->page == 2)
    {
      number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
      f++;
    }

  number_to_chars_bigendian (f, insn->opc + Dd, 1);
  f++;
  
  mb = 0x42;
  dot = strchrnul (insn->name, '.');
  if (dot > insn->name)
    {
      switch (dot[-1])
        {
        case 's':
          mb |= 0x80;
          break;
        case 'u':
          mb |= 0x00;
          break;
        default:
          as_fatal (_("BAD MUL"));
          break;
        }
    }

  mb |= ((size1 - 1) & 0x03) << 4;
  mb |= ((size2 - 1) & 0x03) << 2;
  number_to_chars_bigendian (f, mb, 1);
  f++;

  f = emit_opr (f, buffer1, n_bytes1, &exp1);
  f = emit_opr (f, buffer2, n_bytes2, &exp2);

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
      if (reg < 16)
        *reg_bits |= 0x1u << reg;
    }
  return true;
}

static bool
psh_pull(const struct instruction *insn)
{
    uint8_t pb = (strcmp("pul", insn->name) == 0) ? 0x80 : 0x00;

    if (lex_match_string("all16b")) {
        pb |= 0x40;
        char *f = s12z_new_insn(2);
        number_to_chars_bigendian(f++, insn->opc, 1);
        number_to_chars_bigendian(f++, pb, 1);
        return true;
    }

    if (lex_match_string("all")) {
        char *f = s12z_new_insn(2);
        number_to_chars_bigendian(f++, insn->opc, 1);
        number_to_chars_bigendian(f++, pb, 1);
        return true;
    }

    int reg1;
    if (!lex_reg_name(REG_BIT_GRP1 | REG_BIT_GRP0, &reg1)) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    uint16_t reg_mask = (uint16_t)(1U << reg1);
    uint16_t admitted_group = 0;

    if (reg_mask & REG_BIT_GRP1) {
        admitted_group = REG_BIT_GRP1;
    } else if (reg_mask & REG_BIT_GRP0) {
        admitted_group = REG_BIT_GRP0;
    }

    uint16_t reg_bits = reg_mask;
    if (!lex_reg_list(admitted_group, &reg_bits)) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    if (reg_bits & REG_BIT_GRP1) {
        pb |= 0x40;
    }

    for (int i = 0; i < 16; ++i) {
        if (reg_bits & (1U << i)) {
            pb |= reg_map[i];
        }
    }

    char *f = s12z_new_insn(2);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, pb, 1);
    return true;
}


static bool
tfr (const struct instruction *insn)
{
  int reg1;
  int reg2;
  char *f;
  
  if (!lex_reg_name (~0, &reg1))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  if (!lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  if (!lex_reg_name (~0, &reg2))
    {
      fail_line_pointer = input_line_pointer;
      return false;
    }

  if ((strcasecmp ("sex", insn->name) == 0 || strcasecmp ("zex", insn->name) == 0) &&
      (registers[reg2].bytes <= registers[reg1].bytes))
    {
      as_warn (_("Source register for %s is no larger than the destination register"),
               insn->name);
    }
  else if (reg1 == reg2)
    {
      as_warn (_("The destination and source registers are identical"));
    }

  f = s12z_new_insn (1 + insn->page);
  if (insn->page == 2)
    {
      number_to_chars_bigendian (f, PAGE2_PREBYTE, 1);
      f++;
    }

  number_to_chars_bigendian (f, insn->opc, 1);
  f++;
  number_to_chars_bigendian (f, (reg1 << 4) | reg2, 1);

  return true;
}

static bool
imm8 (const struct instruction *insn)
{
  long imm;
  
  if (!lex_imm(&imm, NULL))
    return false;
    
  if (imm < -128 || imm > 127)
    {
      as_bad(_("Immediate value %ld is out of range for instruction %s"),
             imm, insn->name);
      return false;
    }

  char *f = s12z_new_insn(2);
  if (!f)
    return false;
    
  number_to_chars_bigendian(f, insn->opc, 1);
  number_to_chars_bigendian(f + 1, imm, 1);

  return true;
}

static bool
reg_imm(const struct instruction *insn, int allowed_reg)
{
    char *saved_pointer = input_line_pointer;
    int reg;
    long imm;
    short size;
    char *f;

    if (!lex_reg_name(allowed_reg, &reg)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_force_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_imm(&imm, NULL)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    size = registers[reg].bytes;
    f = s12z_new_insn(insn->page + size);
    
    if (insn->page == 2) {
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(f++, insn->opc + reg, 1);
    number_to_chars_bigendian(f++, imm, size);
    
    return true;
}


static bool regd_imm(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return reg_imm(insn, REG_BIT_Dn);
}

static bool regdxy_imm(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return reg_imm(insn, REG_BIT_Dn | REG_BIT_XY);
}


static bool regs_imm(const struct instruction *insn)
{
    const uint32_t REG_S_MASK = 0x1U << REG_S;
    return reg_imm(insn, REG_S_MASK);
}

static bool
trap_imm(const struct instruction *insn ATTRIBUTE_UNUSED)
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
    if (f == NULL) {
        return false;
    }
    
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
    return false;
    
  if (!lex_force_match (','))
    return false;
    
  if (!lex_reg_name (0x1U << REG_Y, &reg))
    return false;
    
  char *f = s12z_new_insn (1);
  if (f == NULL)
    return false;
    
  number_to_chars_bigendian (f, insn->opc, 1);
  return true;
}

/* Special one byte instruction SUB D6, X, Y */
static bool
regd6_regx_regy (const struct instruction *insn)
{
  char *saved_pointer = input_line_pointer;
  int reg;
  
  if (!lex_reg_name (0x1U << REG_D6, &reg))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  if (!lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  if (!lex_reg_name (0x1U << REG_X, &reg))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  if (!lex_match (','))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  if (!lex_reg_name (0x1U << REG_Y, &reg))
    {
      fail_line_pointer = input_line_pointer;
      input_line_pointer = saved_pointer;
      return false;
    }

  char *f = s12z_new_insn (1);
  if (f != NULL)
    {
      number_to_chars_bigendian (f, insn->opc, 1);
    }
  return true;
}

/* Special one byte instruction SUB D6, Y, X */
static bool
regd6_regy_regx (const struct instruction *insn)
{
  char *saved_pointer = input_line_pointer;
  int reg;
  
  if (!lex_reg_name (0x1U << REG_D6, &reg))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  if (!lex_match (','))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  if (!lex_reg_name (0x1U << REG_Y, &reg))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  if (!lex_match (','))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  if (!lex_reg_name (0x1U << REG_X, &reg))
  {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  char *f = s12z_new_insn (1);
  if (f != NULL)
  {
    number_to_chars_bigendian (f, insn->opc, 1);
  }
  return true;
}

static bool
reg_opr(const struct instruction *insn, int allowed_regs, bool immediate_ok)
{
    char *saved_ilp = input_line_pointer;
    int reg;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    char *f;

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

    if (!lex_opr(buffer, &n_bytes, &exp, immediate_ok)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (exp.X_op == O_constant && buffer[0] == 0xFA && insn->alt_opc != 0) {
        gas_assert(insn->page == 1);
        f = s12z_new_insn(4);
        number_to_chars_bigendian(f, insn->alt_opc + reg, 1);
        emit_ext24(f + 1, exp.X_add_number);
    } else {
        f = s12z_new_insn(n_bytes + insn->page);
        if (insn->page == 2) {
            number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
            f++;
        }
        number_to_chars_bigendian(f, insn->opc + reg, 1);
        emit_opr(f + 1, buffer, n_bytes, &exp);
    }

    return true;
}


static bool regdxy_opr_dest(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return reg_opr(insn, REG_BIT_Dn | REG_BIT_XY, false);
}

static bool regdxy_opr_src(const struct instruction *insn)
{
    const unsigned int REG_MASK = REG_BIT_Dn | REG_BIT_XY;
    const bool IS_SOURCE = true;
    return reg_opr(insn, REG_MASK, IS_SOURCE);
}


static bool regd_opr(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return reg_opr(insn, REG_BIT_Dn, true);
}


/* OP0: S; OP1: destination OPR */
static bool regs_opr_dest(const struct instruction *insn)
{
    const unsigned int reg_s_mask = 0x1U << REG_S;
    return reg_opr(insn, reg_s_mask, false);
}

/* OP0: S; OP1: source OPR */
static bool regs_opr_src(const struct instruction *insn)
{
    const unsigned int reg_s_mask = 0x1U << REG_S;
    const bool is_source = true;
    return reg_opr(insn, reg_s_mask, is_source);
}

static bool
imm_opr(const struct instruction *insn)
{
  char *saved_input_ptr = input_line_pointer;
  long imm = 0;
  expressionS exp0;
  expressionS exp1;
  uint8_t buffer[4];
  int n_bytes = 0;
  int size = size_from_suffix(insn, 0);
  char *f = NULL;
  int i;
  
  exp0.X_op = O_absent;
  
  if (!lex_imm(&imm, size > 1 ? &exp0 : NULL)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input_ptr;
    return false;
  }
  
  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input_ptr;
    return false;
  }
  
  if (!lex_opr(buffer, &n_bytes, &exp1, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input_ptr;
    return false;
  }
  
  f = s12z_new_insn(1 + n_bytes + size);
  if (f == NULL) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input_ptr;
    return false;
  }
  
  number_to_chars_bigendian(f++, insn->opc, 1);
  
  emit_reloc(&exp0, f, size, size == 4 ? BFD_RELOC_32 : BFD_RELOC_S12Z_OPR);
  
  for (i = 0; i < size; ++i) {
    number_to_chars_bigendian(f++, imm >> (CHAR_BIT * (size - i - 1)), 1);
  }
  
  emit_opr(f, buffer, n_bytes, &exp1);
  
  return true;
}

static bool
opr_opr(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  uint8_t buffer1[4];
  uint8_t buffer2[4];
  int n_bytes1;
  int n_bytes2;
  expressionS exp1;
  expressionS exp2;
  char *f;

  if (!lex_opr(buffer1, &n_bytes1, &exp1, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_opr(buffer2, &n_bytes2, &exp2, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  f = s12z_new_insn(1 + n_bytes1 + n_bytes2);
  number_to_chars_bigendian(f++, insn->opc, 1);
  f = emit_opr(f, buffer1, n_bytes1, &exp1);
  emit_opr(f, buffer2, n_bytes2, &exp2);

  return true;
}

static bool
reg67sxy_opr(const struct instruction *insn)
{
  int reg;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  char *f;

  if (!lex_reg_name(REG_BIT_XYS | (0x1U << REG_D6) | (0x1U << REG_D7), &reg))
    return false;

  if (!lex_match(','))
    return false;

  if (!lex_opr(buffer, &n_bytes, &exp, false))
    return false;

  f = s12z_new_insn(1 + n_bytes);
  if (!f)
    return false;

  number_to_chars_bigendian(f, insn->opc + reg - REG_D6, 1);
  emit_opr(f + 1, buffer, n_bytes, &exp);

  return true;
}

static bool rotate(const struct instruction *insn, short dir)
{
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    
    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        return false;
    }
    
    char *f = s12z_new_insn(n_bytes + 2);
    if (f == NULL) {
        return false;
    }
    
    number_to_chars_bigendian(f, insn->opc, 1);
    f++;
    
    int size = size_from_suffix(insn, 0);
    if (size <= 0) {
        size = 1;
    }
    
    uint8_t sb = 0x24 | ((size - 1) & 0x03);
    if (dir != 0) {
        sb |= 0x40;
    }
    
    number_to_chars_bigendian(f, sb, 1);
    f++;
    
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
  char *saved_input = input_line_pointer;
  int reg_number;
  long imm_value = -1;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  uint8_t sb;
  char *output;

  if (!lex_reg_name(REG_BIT_Dn, &reg_number)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input;
    return false;
  }

  if (!lex_imm(&imm_value, NULL)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input;
    return false;
  }

  if (imm_value != 1 && imm_value != 2) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input;
    return false;
  }

  input_line_pointer = saved_input;

  if (!lex_opr(buffer, &n_bytes, &exp, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_input;
    return false;
  }

  gas_assert(n_bytes == 1);

  sb = 0x34;
  sb |= (dir & 1) << 6;
  sb |= (type & 1) << 7;
  if (imm_value == 2) {
    sb |= 0x08;
  }

  output = s12z_new_insn(3);
  number_to_chars_bigendian(output, insn->opc, 1);
  number_to_chars_bigendian(output + 1, sb, 1);
  emit_opr(output + 2, buffer, n_bytes, &exp);

  return true;
}

/* Shift instruction with a register operand.
   left = 1; right = 0;
   logical = 0; arithmetic = 1; */
static bool
lex_shift_reg(const struct instruction *insn, short type, short dir)
{
    int Dd, Ds, Dn;
    long imm;
    uint8_t sb;
    uint8_t xb;
    char *f;
    int n_bytes;

    if (!lex_reg_name(REG_BIT_Dn, &Dd)) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    if (!lex_reg_name(REG_BIT_Dn, &Ds)) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    sb = 0x10;
    sb |= Ds;
    sb |= dir << 6;
    sb |= type << 7;

    if (lex_reg_name(REG_BIT_Dn, &Dn)) {
        f = s12z_new_insn(3);
        number_to_chars_bigendian(f++, insn->opc | Dd, 1);
        number_to_chars_bigendian(f++, sb, 1);
        xb = 0xb8;
        xb |= Dn;
        number_to_chars_bigendian(f++, xb, 1);
        return true;
    }

    if (lex_imm(&imm, NULL)) {
        if (imm < 0 || imm > 31) {
            as_bad(_("Shift value should be in the range [0,31]"));
            fail_line_pointer = input_line_pointer;
            return false;
        }

        n_bytes = 3;
        if (imm == 1 || imm == 2) {
            n_bytes = 2;
            sb &= ~0x10;
        } else {
            sb |= (imm & 0x01) << 3;
        }

        f = s12z_new_insn(n_bytes);
        number_to_chars_bigendian(f++, insn->opc | Dd, 1);
        number_to_chars_bigendian(f++, sb, 1);
        if (n_bytes > 2) {
            xb = 0x70;
            xb |= imm >> 1;
            number_to_chars_bigendian(f++, xb, 1);
        }
        return true;
    }

    fail_line_pointer = input_line_pointer;
    return false;
}

static void
impute_shift_dir_and_type (const struct instruction *insn, short *type, short *dir)
{
  if (insn == NULL || type == NULL || dir == NULL) {
    return;
  }

  *type = -1;
  *dir = -1;

  if (insn->name == NULL) {
    as_fatal (_("Bad shift mode"));
    return;
  }

  if (insn->name[0] == 'l') {
    *type = 0;
  } else if (insn->name[0] == 'a') {
    *type = 1;
  } else {
    as_fatal (_("Bad shift mode"));
    return;
  }

  if (insn->name[2] == 'l') {
    *dir = 1;
  } else if (insn->name[2] == 'r') {
    *dir = 0;
  } else {
    as_fatal (_("Bad shift *direction"));
  }
}

/* Shift instruction with a OPR operand */
static bool
shift_two_operand(const struct instruction *insn)
{
    char *saved_ilp = input_line_pointer;
    uint8_t sb = 0x34;
    short dir = -1;
    short type = -1;
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;
    long imm = -1;
    char *f;
    int size;

    impute_shift_dir_and_type(insn, &type, &dir);
    sb |= (dir & 0x01) << 6;
    sb |= (type & 0x01) << 7;

    size = size_from_suffix(insn, 0);
    if (size < 1) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }
    sb |= (size - 1) & 0x03;

    if (!lex_opr(buffer, &n_opr_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_imm(&imm, NULL)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (imm != 1 && imm != 2) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (imm == 2) {
        sb |= 0x08;
    }

    f = s12z_new_insn(2 + n_opr_bytes);
    if (!f) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    number_to_chars_bigendian(f, insn->opc, 1);
    number_to_chars_bigendian(f + 1, sb, 1);
    emit_opr(f + 2, buffer, n_opr_bytes, &exp);

    return true;
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
    int n_opr_bytes1 = 0;
    expressionS exp1;
    uint8_t buffer2[4];
    int n_opr_bytes2 = 0;
    expressionS exp2;
    long imm = 0;
    bool immediate = false;
    uint8_t sb = 0x20;
    int size;
    char *f;

    impute_shift_dir_and_type(insn, &type, &dir);

    if (!lex_reg_name(REG_BIT_Dn, &Dd)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_opr(buffer1, &n_opr_bytes1, &exp1, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    n_bytes += n_opr_bytes1;

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (lex_imm(&imm, NULL)) {
        immediate = true;
    } else if (!lex_opr(buffer2, &n_opr_bytes2, &exp2, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    size = size_from_suffix(insn, 0);
    if (size != -1) {
        sb |= size - 1;
    }

    sb |= dir << 6;
    sb |= type << 7;

    if (immediate) {
        if (imm == 2) {
            sb |= 0x08;
        } else if (imm != 1) {
            n_bytes++;
            sb |= 0x10;
            if (imm % 2) {
                sb |= 0x08;
            }
        }
    } else {
        n_bytes += n_opr_bytes2;
        sb |= 0x10;
    }

    f = s12z_new_insn(n_bytes);
    number_to_chars_bigendian(f++, insn->opc | Dd, 1);
    number_to_chars_bigendian(f++, sb, 1);
    f = emit_opr(f, buffer1, n_opr_bytes1, &exp1);

    if (immediate && imm != 1 && imm != 2) {
        number_to_chars_bigendian(f++, 0x70 | (imm >> 1), 1);
    } else if (!immediate) {
        f = emit_opr(f, buffer2, n_opr_bytes2, &exp2);
    }

    return true;
}

/* Shift instruction with a register operand */
static bool shift_reg(const struct instruction *insn)
{
    short dir = -1;
    short type = -1;
    impute_shift_dir_and_type(insn, &type, &dir);
    
    return lex_shift_reg_imm1(insn, type, dir) || lex_shift_reg(insn, type, dir);
}

static bool
bm_regd_imm(const struct instruction *insn)
{
  char *saved_pointer = input_line_pointer;
  int Di = 0;
  long imm = 0;
  
  if (!lex_reg_name(REG_BIT_Dn, &Di)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  if (!lex_imm(&imm, NULL)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  uint8_t bm = (imm << 3) | Di;

  char *f = s12z_new_insn(2);
  if (f == NULL) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_pointer;
    return false;
  }

  number_to_chars_bigendian(f, insn->opc, 1);
  number_to_chars_bigendian(f + 1, bm, 1);

  return true;
}

static bool
bm_opr_reg(const struct instruction *insn)
{
    char *saved_input_pointer = input_line_pointer;
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;
    int Dn = 0;
    uint8_t bm;
    int size;
    char *f;

    if (!lex_opr(buffer, &n_opr_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }

    if (!lex_reg_name(REG_BIT_Dn, &Dn)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }

    size = size_from_suffix(insn, 0);
    bm = (Dn << 4) | ((size - 1) << 2) | 0x81;

    f = s12z_new_insn(2 + n_opr_bytes);
    if (f == NULL) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }

    number_to_chars_bigendian(f, insn->opc, 1);
    number_to_chars_bigendian(f + 1, bm, 1);
    emit_opr(f + 2, buffer, n_opr_bytes, &exp);

    return true;
}


static bool
bm_opr_imm(const struct instruction *insn)
{
    char *saved_ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;
    long imm;
    int size;
    uint8_t bm;
    char *f;

    if (!lex_opr(buffer, &n_opr_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_imm(&imm, NULL)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    size = size_from_suffix(insn, 0);

    if (imm < 0 || imm >= size * 8) {
        as_bad(_("Immediate operand %ld is inappropriate for size of instruction"), imm);
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    bm = 0x80;
    if (size == 2) {
        bm |= 0x02;
    } else if (size == 4) {
        bm |= 0x08;
    }
    bm |= (imm & 0x07) << 4;
    bm |= (imm >> 3);

    f = s12z_new_insn(2 + n_opr_bytes);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    emit_opr(f, buffer, n_opr_bytes, &exp);

    return true;
}


static bool
bm_regd_reg(const struct instruction *insn)
{
    char *saved_input_pointer = input_line_pointer;
    int Di = 0;
    int Dn = 0;
    
    if (!lex_reg_name(REG_BIT_Dn, &Di)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }
    
    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }
    
    if (!lex_reg_name(REG_BIT_Dn, &Dn)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }
    
    uint8_t bm = (uint8_t)((Dn << 4) | 0x81);
    uint8_t xb = (uint8_t)(Di | 0xb8);
    
    char *f = s12z_new_insn(3);
    if (f == NULL) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_input_pointer;
        return false;
    }
    
    number_to_chars_bigendian(f, insn->opc, 1);
    number_to_chars_bigendian(f + 1, bm, 1);
    number_to_chars_bigendian(f + 2, xb, 1);
    
    return true;
}





static bool
bf_reg_opr_imm(const struct instruction *insn, short ie)
{
    char *saved_ptr = input_line_pointer;
    int Dd = 0;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    long width;
    long offset;
    
    if (!lex_reg_name(REG_BIT_Dn, &Dd))
        goto restore_and_fail;
    
    if (!lex_match(','))
        goto restore_and_fail;
    
    if (!lex_opr(buffer, &n_bytes, &exp, false))
        goto restore_and_fail;
    
    if (!lex_match(','))
        goto restore_and_fail;
    
    if (!lex_imm(&width, NULL))
        goto restore_and_fail;
    
    if (width < 0 || width > 31) {
        as_bad(_("Invalid width value for %s"), insn->name);
        goto restore_and_fail;
    }
    
    if (!lex_match(':'))
        goto restore_and_fail;
    
    if (!lex_constant(&offset))
        goto restore_and_fail;
    
    if (offset < 0 || offset > 31) {
        as_bad(_("Invalid offset value for %s"), insn->name);
        goto restore_and_fail;
    }
    
    uint8_t i1 = (width << 5) | offset;
    int size = size_from_suffix(insn, 0);
    uint8_t bb = (ie ? 0x80 : 0x00) | 0x60 | ((size - 1) << 2) | (width >> 3);
    
    char *f = s12z_new_insn(4 + n_bytes);
    if (!f)
        goto restore_and_fail;
    
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Dd, 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);
    
    emit_opr(f, buffer, n_bytes, &exp);
    
    return true;
    
restore_and_fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = saved_ptr;
    return false;
}


static bool
bf_opr_reg_imm(const struct instruction *insn, short ie)
{
  char *ilp = input_line_pointer;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  int Ds = 0;
  long width = 0;
  long offset = 0;
  
  if (!lex_opr(buffer, &n_bytes, &exp, false))
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

  uint8_t i1 = (width << 5) | offset;
  
  int size = size_from_suffix(insn, 0);
  uint8_t bb = (ie ? 0x80 : 0x00) | 0x70 | ((size - 1) << 2) | (width >> 3);

  char *f = s12z_new_insn(4 + n_bytes);
  if (!f)
    goto fail;
    
  number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f + 1, 0x08 | Ds, 1);
  number_to_chars_bigendian(f + 2, bb, 1);
  number_to_chars_bigendian(f + 3, i1, 1);

  emit_opr(f + 4, buffer, n_bytes, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}



static bool
bf_reg_reg_imm(const struct instruction *insn, short ie)
{
    char *ilp = input_line_pointer;
    int Dd = 0;
    int Ds = 0;
    long width = 0;
    long offset = 0;
    uint8_t bb;
    uint8_t i1;
    char *f;

    if (!lex_reg_name(REG_BIT_Dn, &Dd)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_reg_name(REG_BIT_Dn, &Ds)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_imm(&width, NULL)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (width < 0 || width > 31) {
        as_bad(_("Invalid width value for %s"), insn->name);
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_match(':')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_constant(&offset)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (offset < 0 || offset > 31) {
        as_bad(_("Invalid offset value for %s"), insn->name);
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    bb = ie ? 0x80 : 0x00;
    bb |= 0x20;
    bb |= Ds << 2;
    bb |= width >> 3;

    i1 = width << 5;
    i1 |= offset;

    f = s12z_new_insn(4);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Dd, 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);

    return true;
}

static bool
bf_reg_reg_reg(const struct instruction *insn ATTRIBUTE_UNUSED, short ie)
{
  char *ilp = input_line_pointer;
  int Dd = 0;
  int Ds = 0;
  int Dp = 0;
  uint8_t bb;
  char *f;
  
  if (!lex_reg_name(REG_BIT_Dn, &Dd)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_reg_name(REG_BIT_Dn, &Ds)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_reg_name((0x01u << REG_D2) |
                    (0x01u << REG_D3) |
                    (0x01u << REG_D4) |
                    (0x01u << REG_D5),
                    &Dp)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  bb = ie ? 0x80 : 0x00;
  bb |= Ds << 2;
  bb |= Dp;

  f = s12z_new_insn(3);
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f++, 0x08 | Dd, 1);
  number_to_chars_bigendian(f++, bb, 1);

  return true;
}

static bool
bf_opr_reg_reg(const struct instruction *insn, short ie)
{
    char *saved_ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    int Ds = 0;
    int Dp = 0;
    int size;
    uint8_t bb;
    char *f;

    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_reg_name(REG_BIT_Dn, &Ds)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_reg_name((0x01u << REG_D2) |
                      (0x01u << REG_D3) |
                      (0x01u << REG_D4) |
                      (0x01u << REG_D5),
                      &Dp)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    size = size_from_suffix(insn, 0);
    bb = ie ? 0x80 : 0x00;
    bb |= 0x50;
    bb |= Dp;
    bb |= (size - 1) << 2;

    f = s12z_new_insn(3 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Ds, 1);
    number_to_chars_bigendian(f++, bb, 1);

    emit_opr(f, buffer, n_bytes, &exp);

    return true;
}


static bool
bf_reg_opr_reg(const struct instruction *insn, short ie)
{
    char *saved_ptr = input_line_pointer;
    int Dd = 0;
    int Dp = 0;
    uint8_t buffer[4];
    int n_bytes = 0;
    expressionS exp;
    
    if (!lex_reg_name(REG_BIT_Dn, &Dd)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ptr;
        return false;
    }
    
    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ptr;
        return false;
    }
    
    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ptr;
        return false;
    }
    
    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ptr;
        return false;
    }
    
    uint16_t dp_mask = (1u << REG_D2) | (1u << REG_D3) | (1u << REG_D4) | (1u << REG_D5);
    if (!lex_reg_name(dp_mask, &Dp)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ptr;
        return false;
    }
    
    int size = size_from_suffix(insn, 0);
    uint8_t bb = (ie ? 0x80u : 0x00u) | 0x40u | (uint8_t)Dp | (uint8_t)((size - 1) << 2);
    
    char *f = s12z_new_insn(3 + n_bytes);
    if (!f) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ptr;
        return false;
    }
    
    number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f + 1, 0x08u | (uint8_t)Dd, 1);
    number_to_chars_bigendian(f + 2, bb, 1);
    emit_opr(f + 3, buffer, n_bytes, &exp);
    
    return true;
}



static bool bfe_reg_reg_reg(const struct instruction *insn)
{
    return bf_reg_reg_reg(insn, 0);
}

static bool bfi_reg_reg_reg(const struct instruction *insn)
{
    return bf_reg_reg_reg(insn, 1);
}

static bool bfe_reg_reg_imm(const struct instruction *insn)
{
    return bf_reg_reg_imm(insn, 0);
}

static bool bfi_reg_reg_imm(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return bf_reg_reg_imm(insn, 1);
}


static bool bfe_reg_opr_reg(const struct instruction *insn)
{
    return bf_reg_opr_reg(insn, 0);
}

static bool bfi_reg_opr_reg(const struct instruction *insn)
{
    return bf_reg_opr_reg(insn, 1);
}


static bool bfe_opr_reg_reg(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return bf_opr_reg_reg(insn, 0);
}

static bool bfi_opr_reg_reg(const struct instruction *insn)
{
    return bf_opr_reg_reg(insn, 1);
}

static bool bfe_reg_opr_imm(const struct instruction *insn)
{
    return bf_reg_opr_imm(insn, 0);
}

static bool bfi_reg_opr_imm(const struct instruction *insn)
{
    return bf_reg_opr_imm(insn, 1);
}

static bool bfe_opr_reg_imm(const struct instruction *insn)
{
    if (insn == NULL) {
        return false;
    }
    return bf_opr_reg_imm(insn, 0);
}

static bool bfi_opr_reg_imm(const struct instruction *insn)
{
    return bf_opr_reg_imm(insn, 1);
}




static bool
tb_reg_rel(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  int reg;
  bool long_displacement;
  expressionS exp;
  uint8_t lb = 0x00;
  char *f;

  if (!lex_reg_name(REG_BIT_Dn | REG_BIT_XY, &reg))
    goto fail;

  if (!lex_match(','))
    goto fail;

  if (!lex_15_bit_offset(&long_displacement, &exp))
    goto fail;

  if (reg == REG_X || reg == REG_Y) {
    lb |= 0x08;
    if (reg == REG_Y)
      lb |= 0x01;
  } else {
    lb |= reg;
  }

  if (insn->name[2] == 'n' && insn->name[3] == 'e')
    lb |= 0x00 << 4;
  else if (insn->name[2] == 'e' && insn->name[3] == 'q')
    lb |= 0x01 << 4;
  else if (insn->name[2] == 'p' && insn->name[3] == 'l')
    lb |= 0x02 << 4;
  else if (insn->name[2] == 'm' && insn->name[3] == 'i')
    lb |= 0x03 << 4;
  else if (insn->name[2] == 'g' && insn->name[3] == 't')
    lb |= 0x04 << 4;
  else if (insn->name[2] == 'l' && insn->name[3] == 'e')
    lb |= 0x05 << 4;

  if (insn->name[0] == 'd')
    lb |= 0x80;
  else if (insn->name[0] != 't')
    goto fail;

  f = s12z_new_insn(long_displacement ? 4 : 3);
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, lb, 1);
  emit_15_bit_offset(f, 4, &exp);

  return true;

fail:
  fail_line_pointer = input_line_pointer;
  input_line_pointer = ilp;
  return false;
}


static bool
tb_opr_rel(const struct instruction *insn)
{
  char *ilp = input_line_pointer;
  uint8_t buffer[4];
  int n_bytes;
  expressionS exp;
  expressionS exp2;
  bool long_displacement;
  uint8_t lb;
  int size;
  char *f;

  if (!lex_opr(buffer, &n_bytes, &exp, false)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_match(',')) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  if (!lex_15_bit_offset(&long_displacement, &exp2)) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
  }

  lb = 0x0C;

  if (startswith(insn->name + 2, "ne")) {
    lb |= 0x00 << 4;
  } else if (startswith(insn->name + 2, "eq")) {
    lb |= 0x01 << 4;
  } else if (startswith(insn->name + 2, "pl")) {
    lb |= 0x02 << 4;
  } else if (startswith(insn->name + 2, "mi")) {
    lb |= 0x03 << 4;
  } else if (startswith(insn->name + 2, "gt")) {
    lb |= 0x04 << 4;
  } else if (startswith(insn->name + 2, "le")) {
    lb |= 0x05 << 4;
  }

  if (insn->name[0] == 'd') {
    lb |= 0x80;
  } else if (insn->name[0] != 't') {
    gas_assert(0);
  }

  size = size_from_suffix(insn, 0);
  lb |= size - 1;

  f = s12z_new_insn(n_bytes + (long_displacement ? 4 : 3));
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, lb, 1);
  f = emit_opr(f, buffer, n_bytes, &exp);
  emit_15_bit_offset(f, n_bytes + 4, &exp2);

  return true;
}




static bool
test_br_reg_reg_rel(const struct instruction *insn)
{
    char *saved_ilp = input_line_pointer;
    int Di = 0;
    int Dn = 0;
    bool long_displacement = false;
    expressionS exp;
    uint8_t bm;
    uint8_t xb;
    char *f;

    if (!lex_reg_name(REG_BIT_Dn, &Di)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_reg_name(REG_BIT_Dn, &Dn)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    if (!lex_15_bit_offset(&long_displacement, &exp)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_ilp;
        return false;
    }

    bm = 0x81 | (Dn << 4);
    xb = 0xb8 | Di;

    f = s12z_new_insn(long_displacement ? 5 : 4);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    number_to_chars_bigendian(f++, xb, 1);

    emit_15_bit_offset(f, 5, &exp);

    return true;
}

static bool
test_br_opr_reg_rel(const struct instruction *insn)
{
    char *saved_pointer = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    int Dn = 0;
    expressionS exp2;
    bool long_displacement;
    uint8_t bm;
    int size;
    int total_bytes;
    char *output;

    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_reg_name(REG_BIT_Dn, &Dn)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    bm = 0x81;
    bm |= Dn << 4;
    size = size_from_suffix(insn, 0);
    bm |= (size - 1) << 2;

    if (!lex_15_bit_offset(&long_displacement, &exp2)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    total_bytes = n_bytes + (long_displacement ? 4 : 3);
    output = s12z_new_insn(total_bytes);
    
    number_to_chars_bigendian(output, insn->opc, 1);
    number_to_chars_bigendian(output + 1, bm, 1);
    output = emit_opr(output + 2, buffer, n_bytes, &exp);
    emit_15_bit_offset(output, total_bytes, &exp2);

    return true;
}


static bool
test_br_opr_imm_rel(const struct instruction *insn)
{
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    expressionS exp2;
    long imm;
    bool long_displacement;
    int size;
    uint8_t bm;
    char *f;

    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_imm(&imm, NULL)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (imm < 0 || imm > 31) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    if (!lex_15_bit_offset(&long_displacement, &exp2)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    size = size_from_suffix(insn, 0);

    bm = 0x80;
    bm |= (imm & 0x07) << 4;
    bm |= (imm >> 3) & 0x03;
    
    if (size == 4) {
        bm |= 0x08;
    } else if (size == 2) {
        bm |= 0x02;
    }

    f = s12z_new_insn(n_bytes + (long_displacement ? 4 : 3));
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    f = emit_opr(f, buffer, n_bytes, &exp);
    emit_15_bit_offset(f, n_bytes + 4, &exp2);

    return true;
}


static bool
test_br_reg_imm_rel(const struct instruction *insn)
{
    char *saved_pointer = input_line_pointer;
    int Di = 0;
    long imm = 0;
    bool long_displacement = false;
    expressionS exp;
    uint8_t bm;
    char *f;

    if (!lex_reg_name(REG_BIT_Dn, &Di)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_imm(&imm, NULL)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (imm < 0 || imm > 31) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    if (!lex_15_bit_offset(&long_displacement, &exp)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = saved_pointer;
        return false;
    }

    bm = Di;
    bm |= imm << 3;

    f = s12z_new_insn(long_displacement ? 4 : 3);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);

    emit_15_bit_offset(f, 4, &exp);

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
  char *op_end = str;

  fail_line_pointer = NULL;

  while (!is_end_of_stmt (*op_end) && !is_whitespace (*op_end))
    {
      if (nlen >= sizeof (name) - 1)
        {
          as_bad (_("Opcode too long."));
          return;
        }
      name[nlen] = TOLOWER (*op_end);
      nlen++;
      op_end++;
    }
  name[nlen] = 0;

  if (nlen == 0)
    {
      as_bad (_("No instruction or missing opcode."));
      return;
    }

  input_line_pointer = skip_whites (op_end);

  size_t opcodes_count = sizeof (opcodes) / sizeof (opcodes[0]);
  for (size_t i = 0; i < opcodes_count; ++i)
    {
      const struct instruction *opc = &opcodes[i];
      if (strcmp (name, opc->name) == 0)
        {
          if (opc->parse_operands (opc))
            return;
        }
    }

  as_bad (_("Invalid instruction: \"%s\""), str);
  if (fail_line_pointer != NULL)
    {
      as_bad (_("First invalid token: \"%s\""), fail_line_pointer);
    }
  while (*input_line_pointer != '\0')
    {
      input_line_pointer++;
    }
}





/* Relocation, relaxation and frag conversions.  */

/* PC-relative offsets are relative to the start of the
   next instruction.  That is, the address of the offset, plus its
   size, since the offset is always the last part of the insn.  */
long
md_pcrel_from (fixS *fixP)
{
  if (!fixP || !fixP->fx_frag)
    return 0;
    
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

void md_convert_frag(bfd *abfd ATTRIBUTE_UNUSED, asection *sec ATTRIBUTE_UNUSED, fragS *fragP ATTRIBUTE_UNUSED)
{
}

/* On an ELF system, we can't relax a weak symbol.  The weak symbol
   can be overridden at final link time by a non weak symbol.  We can
   relax externally visible symbol because there is no shared library
   and such symbol can't be overridden (unless they are weak).  */

/* Force truly undefined symbols to their maximum size, and generally set up
   the frag list to be relaxed.  */
int md_estimate_size_before_relax(fragS *fragP ATTRIBUTE_UNUSED, asection *segment ATTRIBUTE_UNUSED)
{
    return 0;
}


/* If while processing a fixup, a reloc really needs to be created
   then it is done here.  */
arelent *
tc_gen_reloc (asection *section, fixS *fixp)
{
  arelent *reloc;
  asymbol **sym_ptr;
  bfd_reloc_code_real_type reloc_type;
  
  if (section == NULL || fixp == NULL)
    return NULL;
    
  reloc = notes_alloc (sizeof (arelent));
  if (reloc == NULL)
    return NULL;
    
  sym_ptr = notes_alloc (sizeof (asymbol *));
  if (sym_ptr == NULL)
    {
      return NULL;
    }
    
  *sym_ptr = symbol_get_bfdsym (fixp->fx_addsy);
  reloc->sym_ptr_ptr = sym_ptr;
  reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;
  
  reloc_type = fixp->fx_r_type;
  reloc->howto = bfd_reloc_type_lookup (stdoutput, reloc_type);
  
  if (reloc->howto == NULL)
    {
      as_bad_where (fixp->fx_file, fixp->fx_line,
                    _("Relocation %d is not supported by object file format."),
                    (int) reloc_type);
      return NULL;
    }

  if ((section->flags & SEC_CODE) == 0)
    reloc->addend = fixp->fx_offset;
  else
    reloc->addend = fixp->fx_addnumber;

  return reloc;
}

/* See whether we need to force a relocation into the output file.  */
int tc_s12z_force_relocation(fixS *fixP)
{
    if (fixP == NULL) {
        return 0;
    }
    return generic_force_reloc(fixP);
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
  if (fixP == NULL || valP == NULL) {
    return;
  }

  long value = *valP;
  
  if (fixP->fx_addsy == NULL) {
    fixP->fx_done = 1;
  }

  if (fixP->fx_subsy != NULL) {
    as_bad_subtract (fixP);
  }

  if (fixP->fx_frag == NULL || fixP->fx_frag->fr_literal == NULL) {
    return;
  }

  char *where = fixP->fx_frag->fr_literal + fixP->fx_where;

  switch (fixP->fx_r_type)
    {
    case BFD_RELOC_8:
      where[0] = value;
      break;
      
    case BFD_RELOC_16:
      bfd_putb16 (value, where);
      break;
      
    case BFD_RELOC_24:
      bfd_putb24 (value, where);
      break;
      
    case BFD_RELOC_S12Z_OPR:
      if (fixP->fx_size == 3) {
        bfd_putb24 (value, where);
      } else if (fixP->fx_size == 2) {
        bfd_putb16 (value, where);
      } else {
        abort ();
      }
      break;
      
    case BFD_RELOC_32:
      bfd_putb32 (value, where);
      break;
      
    case BFD_RELOC_16_PCREL:
      if (value < -0x4000 || value > 0x3FFF) {
        as_bad_where (fixP->fx_file, fixP->fx_line,
                      _("Value out of 16-bit range."));
      }
      bfd_putb16 (value | 0x8000, where);
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
