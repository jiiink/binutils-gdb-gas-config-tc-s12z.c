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
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

extern bool literal_prefix_dollar_hex;

static long s12z_strtol(const char *str, char **endptr) {
    long result = 0;
    int base = 0;
    char *start = (char *)str;

    if (!str || !endptr) {
        errno = EINVAL;
        return 0;
    }

    bool negative = str[0] == '-';
    if (negative || str[0] == '+') {
        str++;
    }

    if (literal_prefix_dollar_hex && str[0] == '$') {
        base = 16;
        str++;
    }

    result = strtol(str, endptr, base);
    if (*endptr == str) {
        *endptr = start;
    } else if (negative) {
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
const char *s12z_arch_format(void) {
    static const char format[] = "elf32-s12z";
    return format;
}

enum bfd_architecture {
    bfd_arch_s12z
};

enum bfd_architecture s12z_arch(void) {
    return bfd_arch_s12z;
}

int s12z_mach(void) {
    return 0;
}

/* Listing header selected according to cpu.  */
const char *s12z_listing_header(void) {
    return "S12Z GAS ";
}

void md_show_usage(FILE *stream) {
    const char *usage[] = {
        "\ns12z options:\n",
        "  -mreg-prefix=PREFIX     set a prefix used to indicate register names (default none)\n",
        "  -mdollar-hex            the prefix '$' instead of '0x' is used to indicate literal hexadecimal constants\n"
    };

    for (size_t i = 0; i < sizeof(usage) / sizeof(usage[0]); ++i) {
        if (fputs(usage[i], stream) == EOF) {
            perror("Error writing to stream");
            break;
        }
    }
}

void s12z_print_statistics(FILE *file)
{
    if (file == NULL) {
        return;
    }
    // Add future statistics logic here
}

#include <string.h>
#include <stdbool.h>

#define OPTION_REG_PREFIX 1
#define OPTION_DOLLAR_HEX 2

bool literal_prefix_dollar_hex = false;
char *register_prefix = NULL;

int md_parse_option(int c, const char *arg) {
    if (c == OPTION_REG_PREFIX) {
        if (register_prefix) {
            free(register_prefix);
        }
        register_prefix = strdup(arg);
        if (!register_prefix) {
            return 0; // Memory allocation failed
        }
    } else if (c == OPTION_DOLLAR_HEX) {
        literal_prefix_dollar_hex = true;
    } else {
        return 0;
    }
    return 1;
}

static symbolS *md_undefined_symbol(const char *name)
{
    (void)name; 
    return NULL;
}

const char *md_atof(int type, const char *litP, int *sizeP) {
    if (litP == NULL || sizeP == NULL) {
        return NULL;
    }
    return ieee_md_atof(type, litP, sizeP, true);
}

valueT md_section_align(asection *seg, valueT addr) {
    valueT alignment_mask = ((valueT) 1 << bfd_section_alignment(seg)) - 1;
    return (addr + alignment_mask) & ~alignment_mask;
}

void md_begin(void) {
    // Functionality not defined - consider adding implementation or removing the function
}

void s12z_init_after_args(void) {
    literal_prefix_dollar_hex = flag_traditional_format ? true : false;
}

/* Builtin help.  */


#include <ctype.h>

static char *skip_whites(char *p) {
    if (p == NULL) return NULL;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}



/* Start a new insn that contains at least 'size' bytes.  Record the
   line information of that insn in the dwarf2 debug sections.  */
char *s12z_new_insn(int size) {
    if (size <= 0) {
        return NULL;
    }

    char *frag = frag_more(size);
    if (!frag) {
        return NULL;
    }

    dwarf2_emit_insn(size);

    return frag;
}



static bool lex_reg_name (uint16_t which, int *reg);

bool lex_constant(long *v) {
    char *end = NULL;
    char *p = input_line_pointer;

    if (lex_reg_name(~0, NULL)) {
        return false;
    }

    errno = 0;
    *v = s12z_strtol(p, &end);
    if (errno || end == p) {
        return false;
    }

    input_line_pointer = end;
    return true;
}

static bool lex_match(char x) {
    if (*input_line_pointer != x) {
        return false;
    }
    
    input_line_pointer++;
    return true;
}


static bool lex_expression(expressionS *exp) {
    char *initial_pointer = input_line_pointer;
    exp->X_op = O_absent;

    if (lex_match('#') || lex_reg_name(~0, NULL)) {
        input_line_pointer = initial_pointer;
        fail_line_pointer = input_line_pointer;
        return false;
    }

    expression(exp);
    if (exp->X_op != O_absent) {
        return true;
    }

    input_line_pointer = initial_pointer;
    fail_line_pointer = input_line_pointer;
    return false;
}

/* Immediate operand.
   If EXP_O is non-null, then a symbolic expression is permitted,
   in which case, EXP_O will be populated with the parsed expression.
 */
#include <stdbool.h>
#include <stdio.h>

static bool lex_imm(long *v, expressionS *exp_o) {
  char *ilp = input_line_pointer;

  if (*ilp != '#') {
    fail_line_pointer = ilp;
    return false;
  }

  input_line_pointer++;
  expressionS exp;
  if (!lex_expression(&exp)) {
    fail_line_pointer = ilp;
    return false;
  }

  if (exp.X_op != O_constant) {
    if (!exp_o) {
      fprintf(stderr, "A non-constant expression is not permitted here\n");
    } else {
      *exp_o = exp;
    }
  }

  *v = exp.X_add_number;
  return true;
}

/* Short mmediate operand */
static bool lex_imm_e4(long *val) {
    char *original_pointer = input_line_pointer;
    if (lex_imm(val, NULL)) {
        if (*val == -1 || (*val > 0 && *val <= 15)) {
            return true;
        }
    }
    input_line_pointer = original_pointer;
    return false;
}

#include <string.h>
#include <ctype.h>
#include <stdbool.h>

static bool lex_match_string(const char *s) {
    if (!s || !input_line_pointer) return false;

    char *p = input_line_pointer;
    while (*p && !is_whitespace(*p) && !is_end_of_stmt(*p)) {
        p++;
    }

    size_t len = p - input_line_pointer;
    if (len != strlen(s)) return false;

    if (strncasecmp(s, input_line_pointer, len) == 0) {
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
static bool lex_reg_name(uint16_t which, int *reg) {
    if (input_line_pointer == NULL) {
        return false;
    }

    char *p = input_line_pointer;

    if (register_prefix) {
        size_t prefix_len = strlen(register_prefix);
        if (strncmp(register_prefix, p, prefix_len) != 0) {
            return false;
        }
        p += prefix_len;
    }

    char *start_of_reg_name = p;
    while (isalnum((unsigned char)*p)) {
        p++;
    }

    size_t len = p - start_of_reg_name;
    if (len == 0) {
        return false;
    }

    for (int i = 0; i < S12Z_N_REGISTERS; ++i) {
        if (registers[i].name == NULL) {
            continue;
        }

        if (len == strlen(registers[i].name) &&
            strncasecmp(registers[i].name, start_of_reg_name, len) == 0 &&
            ((0x1U << i) & which)) {
            input_line_pointer = p;
            *reg = i;
            return true;
        }
    }

    return false;
}

#include <stdbool.h>

static bool is_char_at_pointer_match(char expected) {
    return *input_line_pointer == expected;
}

static bool lex_force_match(char x) {
    if (!is_char_at_pointer_match(x)) {
        as_bad(_("Expecting '%c'"), x);
        return false;
    }
    input_line_pointer++;
    return true;
}

static bool lex_opr(uint8_t *buffer, int *n_bytes, expressionS *exp, bool immediate_ok) {
    char *original_line_pointer = input_line_pointer;
    uint8_t *byte_ptr = buffer;
    int reg;
    long imm;

    exp->X_op = O_absent;
    *n_bytes = 0;
    *byte_ptr = 0;

    if (lex_imm_e4(&imm)) {
        if (!immediate_ok) {
            as_bad(_("An immediate value in a source operand is inappropriate"));
            return false;
        }
        *byte_ptr = (imm > 0) ? imm : 0;
        *byte_ptr |= 0x70;
        *n_bytes = 1;
        return true;
    }

    if (lex_reg_name(REG_BIT_Dn, &reg)) {
        *byte_ptr = reg | 0xb8;
        *n_bytes = 1;
        return true;
    }

    if (lex_match('[')) {
        if (lex_expression(exp)) {
            long c = exp->X_add_number;
            if (lex_match(',')) {
                if (lex_reg_name(REG_BIT_XYSP, &reg)) {
                    int num_bytes = (c >= -256 && c <= 255) ? 2 : 4;
                    *n_bytes = num_bytes;
                    *byte_ptr |= (num_bytes == 2) ? 0xc4 : 0xc6;
                    *byte_ptr |= (reg - REG_X) << 4;
                    if (c < 0) *byte_ptr |= 0x01;
                    for (int i = 1; i < num_bytes; ++i) {
                        buffer[i] = c >> (8 * (num_bytes - i - 1));
                    }
                } else {
                    as_bad(_("Bad operand for constant offset"));
                    goto fail;
                }
            } else {
                *byte_ptr = 0xfe;
                *n_bytes = 4;
                buffer[1] = c >> 16;
                buffer[2] = c >> 8;
                buffer[3] = c;
            }
        } else if (lex_reg_name(REG_BIT_Dn, &reg)) {
            if (!lex_force_match(',') || !lex_reg_name(REG_BIT_XY, &reg)) goto fail;
            *n_bytes = 1;
            *byte_ptr = reg | ((reg - REG_X) << 4) | 0xc8;
        } else goto fail;

        if (!lex_force_match(']')) goto fail;
        return true;
    }

    if (lex_match('(')) {
        long c;
        if (lex_constant(&c)) {
            if (!lex_force_match(',') || !lex_reg_name(REG_BIT_XYSP, &reg)) goto fail;
            int num_bytes;
            if (reg != REG_P && 0 <= c && c <= 15) {
                num_bytes = 1;
                *byte_ptr = 0x40 | ((reg - REG_X) << 4) | c;
            } else if (-256 <= c && c <= 255) {
                num_bytes = 2;
                *byte_ptr = 0xc0 | ((reg - REG_X) << 4) | (c < 0 ? 0x01 : 0);
                buffer[1] = c;
            } else {
                num_bytes = 4;
                *byte_ptr = 0xc2 | ((reg - REG_X) << 4);
                buffer[1] = c >> 16;
                buffer[2] = c >> 8;
                buffer[3] = c;
            }
            *n_bytes = num_bytes;
        } else if (lex_reg_name(REG_BIT_Dn, &reg)) {
            if (!lex_match(',')) goto fail;
            if (lex_reg_name(REG_BIT_XYS, &reg)) {
                *n_bytes = 1;
                *byte_ptr = 0x88 | ((reg - REG_X) << 4) | reg;
            } else {
                as_bad(_("Invalid operand for register offset"));
                goto fail;
            }
        } else if (lex_reg_name(REG_BIT_XYS, &reg)) {
            if (lex_match('-')) {
                if (reg == REG_S) {
                    as_bad(_("Invalid register for postdecrement operation"));
                    goto fail;
                }
                *n_bytes = 1;
                *byte_ptr = (reg == REG_X) ? 0xc7 : 0xd7;
            } else if (lex_match('+')) {
                *n_bytes = 1;
                *byte_ptr = (reg == REG_X) ? 0xe7 : ((reg == REG_Y) ? 0xf7 : 0xff);
            } else goto fail;
        } else if (lex_match('+')) {
            if (!lex_reg_name(REG_BIT_XY, &reg)) {
                as_bad(_("Invalid register for preincrement operation"));
                goto fail;
            }
            *n_bytes = 1;
            *byte_ptr = (reg == REG_X) ? 0xe3 : 0xf3;
        } else if (lex_match('-')) {
            if (!lex_reg_name(REG_BIT_XYS, &reg)) {
                as_bad(_("Invalid register for predecrement operation"));
                goto fail;
            }
            *n_bytes = 1;
            *byte_ptr = (reg == REG_X) ? 0xc3 : ((reg == REG_Y) ? 0xd3 : 0xfb);
        } else goto fail;

        if (!lex_match(')')) goto fail;
        return true;
    }

    if (lex_expression(exp)) {
        *byte_ptr = 0xfa;
        *n_bytes = 4;
        buffer[1] = buffer[2] = buffer[3] = 0;
        if (exp->X_op == O_constant) {
            valueT value = exp->X_add_number;
            if (value < (0x1U << 14)) {
                *byte_ptr = value >> 8;
                *n_bytes = 2;
                buffer[1] = value;
            } else if (value < (0x1U << 19)) {
                *byte_ptr = 0xf8 | ((value & (0x1U << 17)) ? 0x04 : 0) | ((value & (0x1U << 16)) ? 0x01 : 0);
                *n_bytes = 3;
                buffer[1] = value >> 8;
                buffer[2] = value;
            } else {
                buffer[1] = value >> 16;
                buffer[2] = value >> 8;
                buffer[3] = value;
            }
        }
        return true;
    }

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_line_pointer;
    return false;
}

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

static bool lex_offset(long *val) {
    char *p = input_line_pointer;
    if (*p != '*' || (*(p + 1) != '+' && *(p + 1) != '-')) {
        return false;
    }

    bool negative = (*(++p) == '-');
    char *end;
    errno = 0;
    *val = strtol(++p, &end, 10);

    if (errno != 0 || end == p) {
        return false;
    }

    *val = negative ? -*val : *val;
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

#include <stdbool.h>

static bool no_operands(const struct instruction *insn) {
    if (*input_line_pointer != '\0') {
        as_bad(_("Garbage at end of instruction"));
        return false;
    }

    char *f = s12z_new_insn(insn->page);
    if (!f) {
        as_bad(_("Failed to allocate new instruction"));
        return false;
    }

    if (insn->page == 2) {
        number_to_chars_bigendian(f, PAGE2_PREBYTE, 1);
        f++;
    }

    number_to_chars_bigendian(f, insn->opc, 1);

    return true;
}


static void emit_reloc(expressionS *exp, char *f, int size, enum bfd_reloc_code_real reloc) {
    if (exp == NULL || f == NULL || size <= 0 || (exp->X_op != O_absent && exp->X_op != O_constant)) {
        return;
    }
    
    fixS *fix = fix_new_exp(frag_now, f - frag_now->fr_literal, size, exp, false, reloc);
    if (fix != NULL) {
        fix->fx_addnumber = 0x00;
    }
}

/* Emit the code for an OPR address mode operand */
static char *emit_opr(char *f, const uint8_t *buffer, int n_bytes, expressionS *exp) {
    number_to_chars_bigendian(f++, buffer[0], 1);
    emit_reloc(exp, f, 3, BFD_RELOC_S12Z_OPR);

    for (int i = 1; i < n_bytes; ++i) {
        number_to_chars_bigendian(f++, buffer[i], 1);
    }

    return f;
}

/* Emit the code for a 24 bit direct address operand */
static char *emit_ext24(char *f, long v) {
  if (!f) {
    return NULL;
  }

  number_to_chars_bigendian(f, v, 3);
  return f + 3;
}

#include <stdbool.h>
#include <stdint.h>

static bool opr(const struct instruction *insn) {
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;

    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        return false;
    }

    if ((exp.X_op == O_constant) && (buffer[0] == 0xFA) && (insn->alt_opc != 0)) {
        char *f = s12z_new_insn(4);

        gas_assert(insn->page == 1);

        number_to_chars_bigendian(f, insn->alt_opc, 1);
        f++;

        emit_ext24(f, exp.X_add_number);
    } else {
        char *f = s12z_new_insn(n_bytes + 1);
        
        number_to_chars_bigendian(f, insn->opc, 1);
        f++;
        
        emit_opr(f, buffer, n_bytes, &exp);
    }

    return true;
}

/* Parse a 15 bit offset, as an expression.
   LONG_DISPLACEMENT will be set to true if the offset is wider than 7 bits.
   */
static bool lex_15_bit_offset(bool *long_displacement, expressionS *exp) {
    char *ilp = input_line_pointer;
    long val;

    if (!lex_offset(&val) && !lex_expression(exp)) {
        exp->X_op = O_absent;
        goto fail;
    } 

    if (exp->X_op == O_absent) {
        exp->X_add_number = val;
    } else if (exp->X_op == O_constant) {
        val = exp->X_add_number;
    } else {
        *long_displacement = true;
        return true;
    }

    if (val > 0x3FFF || val < -0x4000) {
        as_fatal(_("Offset is outside of 15 bit range"));
        return false;
    }

    *long_displacement = (val > 63 || val < -64);
    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

static void emit_15_bit_offset(char *f, int where, expressionS *exp) {
    if (!exp) return;
    
    long val = exp->X_add_number;

    switch (exp->X_op) {
        case O_absent:
        case O_constant:
            {
                bool long_displacement = (val > 63 || val < -64);
                if (long_displacement) {
                    val |= 0x8000;
                } else {
                    val &= 0x7F;
                }
                number_to_chars_bigendian(f++, val, long_displacement ? 2 : 1);
            }
            break;

        default:
            {
                exp->X_add_number += where;
                fixS *fix = fix_new_exp(frag_now, 
                                        f - frag_now->fr_literal, 
                                        2, 
                                        exp, 
                                        true, 
                                        BFD_RELOC_16_PCREL);
                if (fix) {
                    fix->fx_addnumber = where - 2;
                }
            }
            break;
    }
}

#include <stdbool.h>

static bool rel(const struct instruction *insn) {
    bool long_displacement;
    expressionS exp;

    if (!lex_15_bit_offset(&long_displacement, &exp)) {
        return false;
    }

    int displacement_length = long_displacement ? 3 : 2;
    char *f = s12z_new_insn(displacement_length);
    if (!f) {
        return false; // Ensure memory allocation was successful
    }

    number_to_chars_bigendian(f++, insn->opc, 1);
    emit_15_bit_offset(f, 3, &exp);
    return true;
}

static bool reg_inh(const struct instruction *insn) {
    int reg;
    if (!lex_reg_name(REG_BIT_Dn, &reg)) {
        return false;
    }

    char *f = s12z_new_insn(insn->page);
    if (!f) {
        return false;
    }

    if (insn->page == 2) {
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(f, insn->opc + reg, 1);
    return true;
}


/* Special case for CLR X and CLR Y */
static bool clr_xy (const struct instruction *insn ATTRIBUTE_UNUSED) {
    int reg;
    if (!lex_reg_name(REG_BIT_XY, &reg)) {
        return false;
    }

    char *f = s12z_new_insn(1);
    if (f == NULL) {
        return false;
    }

    number_to_chars_bigendian(f, 0x9a + reg - REG_X, 1);
    return true;
}

/* Some instructions have a suffix like ".l", ".b", ".w" etc
   which indicates the size of the operands. */
#include <stddef.h>
#include <string.h>
#include <stdio.h>

static int size_from_suffix(const struct instruction *insn, int idx) {
    const char *dot = strchr(insn->name, '.');
    if (!dot) {
        return -3;
    }

    char suffix = dot[1 + idx];
    switch (suffix) {
        case 'b':
            return 1;
        case 'w':
            return 2;
        case 'p':
            return 3;
        case 'l':
            return 4;
        default:
            fprintf(stderr, "Error: Invalid size suffix '%c'\n", suffix);
            return -3;
    }
}

static bool
mul_reg_reg_reg(const struct instruction *insn) {
    char *initial_input_line_pointer = input_line_pointer;

    int Dd, Dj, Dk;
    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',') ||
        !lex_reg_name(REG_BIT_Dn, &Dj) || !lex_match(',') ||
        !lex_reg_name(REG_BIT_Dn, &Dk)) {
        input_line_pointer = initial_input_line_pointer;
        return false;
    }

    char *f = s12z_new_insn(insn->page + 1);
    if (insn->page == 2) {
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(f++, insn->opc + Dd, 1);

    const char *dot = strchrnul(insn->name, '.');
    uint8_t mb;
    switch (dot[-1]) {
        case 's':
            mb = 0x80;
            break;
        case 'u':
            mb = 0x00;
            break;
        default:
            as_fatal(_("BAD MUL"));
    }

    mb |= (Dj << 3) | Dk;
    number_to_chars_bigendian(f++, mb, 1);

    return true;
}


static bool mul_reg_reg_imm(const struct instruction *insn) {
    char *original_ilp = input_line_pointer;
    int Dd, Dj;
    long imm;
    
    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',') ||
        !lex_reg_name(REG_BIT_Dn, &Dj) || !lex_match(',') ||
        !lex_imm(&imm, NULL)) {
        input_line_pointer = original_ilp;
        fail_line_pointer = input_line_pointer;
        return false;
    }

    int size = size_from_suffix(insn, 0);
    char *f = s12z_new_insn(insn->page + 1 + size);

    if (insn->page == 2) {
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(f++, insn->opc + Dd, 1);

    uint8_t mb = 0x44;
    const char *dot = strchrnul(insn->name, '.');
    mb |= (dot[-1] == 's') ? 0x80 : (dot[-1] == 'u') ? 0x00 : (as_fatal(_("BAD MUL")), 0);

    mb |= Dj << 3;
    mb |= size - 1;

    number_to_chars_bigendian(f++, mb, 1);
    number_to_chars_bigendian(f++, imm, size);

    return true;
}


static bool mul_reg_reg_opr(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    int Dd, Dj;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;

    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',') || 
        !lex_reg_name(REG_BIT_Dn, &Dj) || !lex_match(',') || 
        !lex_opr(buffer, &n_bytes, &exp, true)) {
        goto fail;
    }

    int size = size_from_suffix(insn, 0);
    if (size < 1) {
        as_fatal(_("Invalid size from suffix"));
        goto fail;
    }

    char *f = s12z_new_insn(insn->page + 1 + n_bytes);
    if (!f) {
        as_fatal(_("Failed to allocate instruction buffer"));
        goto fail;
    }

    if (insn->page == 2) {
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(f++, insn->opc + Dd, 1);

    uint8_t mb = 0x40;
    const char *dot = strchrnul(insn->name, '.');
    if (!dot) {
        as_fatal(_("Malformed instruction name"));
        goto fail;
    }

    switch (dot[-1]) {
        case 's':
            mb |= 0x80;
            break;
        case 'u':
            mb |= 0x00;
            break;
        default:
            as_fatal(_("Invalid MUL instruction type"));
            goto fail;
    }

    mb |= (Dj << 3) | (size - 1);
    number_to_chars_bigendian(f++, mb, 1);
    emit_opr(f, buffer, n_bytes, &exp);

    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

static bool mul_reg_opr_opr(const struct instruction *insn) {
    char *original_input_pointer = input_line_pointer;
    int Dd;

    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',')) {
        goto error;
    }

    uint8_t buffer1[4], buffer2[4];
    int n_bytes1, n_bytes2;
    expressionS exp1, exp2;

    if (!lex_opr(buffer1, &n_bytes1, &exp1, false) || !lex_match(',') || !lex_opr(buffer2, &n_bytes2, &exp2, false)) {
        goto error;
    }

    int size1 = size_from_suffix(insn, 0);
    int size2 = size_from_suffix(insn, 1);

    char *instruction_storage = s12z_new_insn(insn->page + 1 + n_bytes1 + n_bytes2);
    if (insn->page == 2) {
        number_to_chars_bigendian(instruction_storage++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(instruction_storage++, insn->opc + Dd, 1);
    uint8_t multipliers_byte = 0x42;

    const char *dot_position = strchrnul(insn->name, '.');
    switch (dot_position[-1]) {
        case 's':
            multipliers_byte |= 0x80;
            break;
        case 'u':
            multipliers_byte |= 0x00;
            break;
        default:
            as_fatal(_("BAD MUL"));
            break;
    }

    multipliers_byte |= (size1 - 1) << 4;
    multipliers_byte |= (size2 - 1) << 2;
    number_to_chars_bigendian(instruction_storage++, multipliers_byte, 1);

    instruction_storage = emit_opr(instruction_storage, buffer1, n_bytes1, &exp1);
    instruction_storage = emit_opr(instruction_storage, buffer2, n_bytes2, &exp2);

    return true;

error:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_input_pointer;
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

static bool lex_reg_list(uint16_t grp, uint16_t *reg_bits) {
    while (lex_match(',')) {
        int reg;
        if (!lex_reg_name(grp, &reg)) {
            return false;
        }
        *reg_bits |= 0x1u << reg;
    }
    return true;
}

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static const uint16_t REG_BIT_GRP0 = 0x01; // Example value, replace with actual
static const uint16_t REG_BIT_GRP1 = 0x02; // Example value, replace with actual
static const uint8_t reg_map[16] = {0}; // Example values, replace with actual

static bool lex_match_string(const char *str);
static bool lex_reg_name(uint16_t mask, int *reg);
static bool lex_reg_list(uint16_t group, uint16_t *reg_bits);
static char* s12z_new_insn(int size);
static void number_to_chars_bigendian(char *buffer, uint8_t number, int size);
static const char* input_line_pointer; // Placeholder
static const char* fail_line_pointer; // Placeholder

static bool psh_pull(const struct instruction *insn) {
    uint8_t pb = (strcmp("pul", insn->name) == 0) ? 0x80 : 0x00;
    int reg1;
    uint16_t reg_bits = 0, admitted_group = 0;

    if (lex_match_string("all16b")) {
        pb |= 0x40;
    } else if (!lex_match_string("all")) {
        if (!lex_reg_name(REG_BIT_GRP1 | REG_BIT_GRP0, &reg1)) goto fail;

        admitted_group = ((0x1U << reg1) & REG_BIT_GRP1) ? REG_BIT_GRP1 : REG_BIT_GRP0;
        reg_bits = 0x1U << reg1;

        if (!lex_reg_list(admitted_group, &reg_bits)) goto fail;

        if (reg_bits & REG_BIT_GRP1) pb |= 0x40;
        for (int i = 0; i < 16; i++) {
            if (reg_bits & (0x1U << i)) pb |= reg_map[i];
        }
    }

    char *f = s12z_new_insn(2);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, pb, 1);
    return true;

fail:
    fail_line_pointer = input_line_pointer;
    return false;
}


bool tfr(const struct instruction *insn) {
    int reg1, reg2;
    if (!lex_reg_name(~0, &reg1) || !lex_match(',') || !lex_reg_name(~0, &reg2)) {
        fail_line_pointer = input_line_pointer;
        return false;
    }

    if (((strcasecmp("sex", insn->name) == 0) || (strcasecmp("zex", insn->name) == 0)) &&
        (registers[reg2].bytes <= registers[reg1].bytes)) {
        as_warn(_("Source register for %s is no larger than the destination register"), insn->name);
    } else if (reg1 == reg2) {
        as_warn(_("The destination and source registers are identical"));
    }

    char *f = s12z_new_insn(1 + insn->page);
    if (insn->page == 2) {
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, (reg1 << 4) | reg2, 1);

    return true;
}

static bool imm8(const struct instruction *insn) {
    long imm;
    if (!lex_imm(&imm, NULL)) {
        return false;
    }
    if (imm > 127 || imm < -128) {
        as_bad(_("Immediate value %ld is out of range for instruction %s"), imm, insn->name);
        return false;
    }

    char *f = s12z_new_insn(2);
    if (f == NULL) {
        return false;
    }

    number_to_chars_bigendian(f, insn->opc, 1);
    number_to_chars_bigendian(f + 1, imm, 1);

    return true;
}

static bool reg_imm(const struct instruction *insn, int allowed_reg) {
    char *original_line_pointer = input_line_pointer;
    int reg;
    long imm;
    if (!lex_reg_name(allowed_reg, &reg)) {
        reset_line_pointer(original_line_pointer);
        return false;
    }

    if (!lex_force_match(',')) {
        reset_line_pointer(original_line_pointer);
        return false;
    }

    if (!lex_imm(&imm, NULL)) {
        reset_line_pointer(original_line_pointer);
        return false;
    }

    short size = registers[reg].bytes;
    char *f = s12z_new_insn(insn->page + size);
    if (!f) {
        reset_line_pointer(original_line_pointer);
        return false;
    }

    if (insn->page == 2) {
        number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    }

    number_to_chars_bigendian(f++, insn->opc + reg, 1);
    number_to_chars_bigendian(f, imm, size);
    return true;
}

static void reset_line_pointer(char *original_line_pointer) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_line_pointer;
}


static bool regd_imm(const struct instruction *insn) {
    if (insn == NULL) return false;
    return reg_imm(insn, REG_BIT_Dn);
}

#include <stdbool.h>

static bool is_register_value_acceptable(const struct instruction *insn, int reg_flags);

static bool regdxy_imm(const struct instruction *insn) {
    const int reg_flags = REG_BIT_Dn | REG_BIT_XY;
    return is_register_value_acceptable(insn, reg_flags);
}


static bool regs_imm(const struct instruction *insn) {
    const unsigned int reg_mask = 0x1U << REG_S;
    return reg_imm(insn, reg_mask);
}

static bool
trap_imm (const struct instruction *insn ATTRIBUTE_UNUSED)
{
  long imm = -1;
  char *f;

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

  f = s12z_new_insn(2);
  if (f == NULL) {
    return false;
  }
  
  number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
  number_to_chars_bigendian(f, imm & 0xFF, 1);

  return true;
}



/* Special one byte instruction CMP X, Y */
bool regx_regy(const struct instruction *insn) {
    int reg;
    if (!lex_reg_name(0x1U << REG_X, &reg)) return false;
    if (!lex_force_match(',')) return false;
    if (!lex_reg_name(0x1U << REG_Y, &reg)) return false;

    char *f = s12z_new_insn(1);
    if (f == NULL) return false;
    number_to_chars_bigendian(f, insn->opc, 1);
    return true;
}

/* Special one byte instruction SUB D6, X, Y */
static bool
regd6_regx_regy(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    int reg;

    if (lex_reg_name(0x1U << REG_D6, &reg) &&
        lex_match(',') &&
        lex_reg_name(0x1U << REG_X, &reg) &&
        lex_match(',') &&
        lex_reg_name(0x1U << REG_Y, &reg)) {
        
        char *f = s12z_new_insn(1);
        number_to_chars_bigendian(f, insn->opc, 1);
        return true;
    }

    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

/* Special one byte instruction SUB D6, Y, X */
static bool regd6_regy_regx(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    int reg;
    
    if (!lex_reg_name(0x1U << REG_D6, &reg) || !lex_match(',') ||
        !lex_reg_name(0x1U << REG_Y, &reg) || !lex_match(',') ||
        !lex_reg_name(0x1U << REG_X, &reg)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }
    
    char *f = s12z_new_insn(1);
    number_to_chars_bigendian(f, insn->opc, 1);
    return true;
}

static bool reg_opr(const struct instruction *insn, int allowed_regs, bool immediate_ok) {
    char *original_line_pointer = input_line_pointer;
    int reg;
    
    if (!lex_reg_name(allowed_regs, &reg)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_line_pointer;
        return false;
    }
    
    if (!lex_force_match(',')) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_line_pointer;
        return false;
    }
    
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    
    if (!lex_opr(buffer, &n_bytes, &exp, immediate_ok)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_line_pointer;
        return false;
    }
    
    char *f;
    if (exp.X_op == O_constant && buffer[0] == 0xFA && insn->alt_opc != 0) {
        f = s12z_new_insn(4);
        gas_assert(insn->page == 1);
        number_to_chars_bigendian(f++, insn->alt_opc + reg, 1);
        emit_ext24(f, exp.X_add_number);
    } else {
        f = s12z_new_insn(n_bytes + insn->page);
        if (insn->page == 2) {
            number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
        }
        number_to_chars_bigendian(f++, insn->opc + reg, 1);
        emit_opr(f, buffer, n_bytes, &exp);
    }
    
    return true;
}


static bool regdxy_opr_dest(const struct instruction *insn) {
    static const int REG_BITS = REG_BIT_Dn | REG_BIT_XY;
    return reg_opr(insn, REG_BITS, false);
}

static bool regdxy_opr_src(const struct instruction *insn) {
    if (insn == NULL) {
        return false;
    }
    return reg_opr(insn, REG_BIT_Dn | REG_BIT_XY, true);
}


#include <stdbool.h>

static bool is_register_operand(const struct instruction* insn) {
    if (insn == NULL) {
        return false;
    }
    return reg_opr(insn, REG_BIT_Dn, true);
}


/* OP0: S; OP1: destination OPR */
static bool regs_opr_dest(const struct instruction *insn) {
    return insn != NULL && reg_opr(insn, 0x1U << REG_S, false);
}

/* OP0: S; OP1: source OPR */
#include <stdbool.h>

static bool reg_opr(const struct instruction *insn, unsigned int flag, bool is_source);

static bool regs_opr_src(const struct instruction *insn) {
    const unsigned int reg_s_flag = 0x1U << REG_S;
    return reg_opr(insn, reg_s_flag, true);
}

#include <stdbool.h>
#include <stdint.h>

static bool imm_opr(const struct instruction *insn) {
    char *original_input_ptr = input_line_pointer;
    long immediate_value;
    expressionS immediate_expr = { .X_op = O_absent };
    int size = size_from_suffix(insn, 0);

    if (!lex_imm(&immediate_value, size > 1 ? &immediate_expr : NULL) || 
        !lex_match(',')) {
        input_line_pointer = original_input_ptr;
        return false;
    }

    uint8_t buffer[4];
    int n_bytes;
    expressionS operand_expr;
    if (!lex_opr(buffer, &n_bytes, &operand_expr, false)) {
        input_line_pointer = original_input_ptr;
        return false;
    }

    char *instruction = s12z_new_insn(1 + n_bytes + size);
    number_to_chars_bigendian(instruction++, insn->opc, 1);

    emit_reloc(&immediate_expr, instruction, size, size == 4 ? BFD_RELOC_32 : BFD_RELOC_S12Z_OPR);

    for (int i = 0; i < size; ++i) {
        number_to_chars_bigendian(instruction++, immediate_value >> (CHAR_BIT * (size - i - 1)), 1);
    }

    emit_opr(instruction, buffer, n_bytes, &operand_expr);

    return true;
}

static bool opr_opr(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    uint8_t buffer1[4], buffer2[4];
    int n_bytes1, n_bytes2;
    expressionS exp1, exp2;

    if (!lex_opr(buffer1, &n_bytes1, &exp1, false) || !lex_match(',') || !lex_opr(buffer2, &n_bytes2, &exp2, false)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    char *f = s12z_new_insn(1 + n_bytes1 + n_bytes2);
    if (!f) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    number_to_chars_bigendian(f++, insn->opc, 1);
    f = emit_opr(f, buffer1, n_bytes1, &exp1);
    f = emit_opr(f, buffer2, n_bytes2, &exp2);

    return true;
}

static bool reg67sxy_opr(const struct instruction *insn) {
    int reg;

    if (!lex_reg_name(REG_BIT_XYS | (0x1U << REG_D6) | (0x1U << REG_D7), &reg) || !lex_match(',')) {
        return false;
    }

    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;

    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        return false;
    }

    char *f = s12z_new_insn(1 + n_bytes);
    if (f == NULL) {
        return false;
    }

    number_to_chars_bigendian(f++, insn->opc + reg - REG_D6, 1);
    emit_opr(f, buffer, n_bytes, &exp);

    return true;
}

bool rotate(const struct instruction *insn, short dir) {
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;

    if (!lex_opr(buffer, &n_bytes, &exp, false)) {
        return false;
    }

    int size = size_from_suffix(insn, 0);
    size = (size < 0) ? 1 : size;

    uint8_t sb = 0x24 | (size - 1);
    if (dir) {
        sb |= 0x40;
    }

    char *f = s12z_new_insn(n_bytes + 2);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, sb, 1);
    emit_opr(f, buffer, n_bytes, &exp);

    return true;
}

#include <stdbool.h>

bool rotate(const struct instruction *insn, int direction);

static bool rol(const struct instruction *insn) {
    return insn != NULL && rotate(insn, 1);
}

bool ror(const struct instruction *insn) {
    if (insn == NULL) {
        // Handle error: log or return a default value appropriate for your use case
        return false;
    }
    return rotate(insn, 0);
}


/* Shift instruction with a register operand and an immediate #1 or #2
   left = 1; right = 0;
   logical = 0; arithmetic = 1;
*/
#include <stdbool.h>
#include <stdint.h>

static bool lex_shift_reg_imm1(const struct instruction *insn, short type, short dir) {
    char *ilp = input_line_pointer;
    int Dd;
    long imm;

    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',') || !lex_imm(&imm, NULL) || (imm != 1 && imm != 2)) {
        input_line_pointer = ilp;
        fail_line_pointer = input_line_pointer;
        return false;
    }

    input_line_pointer = ilp;

    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;

    if (!lex_opr(buffer, &n_bytes, &exp, false) || n_bytes != 1) {
        input_line_pointer = ilp;
        fail_line_pointer = input_line_pointer;
        return false;
    }

    uint8_t sb = 0x34 | (dir << 6) | (type << 7) | (imm == 2 ? 0x08 : 0x00);
    char *f = s12z_new_insn(3);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, sb, 1);
    emit_opr(f, buffer, n_bytes, &exp);

    return true;
}

/* Shift instruction with a register operand.
   left = 1; right = 0;
   logical = 0; arithmetic = 1; */
static bool lex_shift_reg(const struct instruction *insn, short type, short dir) {
    int Dd, Ds, Dn;
    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',') || !lex_reg_name(REG_BIT_Dn, &Ds) || !lex_match(',')) {
        goto fail;
    }

    uint8_t sb = 0x10 | Ds | (dir << 6) | (type << 7);
    long imm;

    if (lex_reg_name(REG_BIT_Dn, &Dn)) {
        char *f = s12z_new_insn(3);
        if (f == NULL) goto fail;
        number_to_chars_bigendian(f++, insn->opc | Dd, 1);
        number_to_chars_bigendian(f++, sb, 1);
        number_to_chars_bigendian(f++, 0xb8 | Dn, 1);
        return true;
    } else if (lex_imm(&imm, NULL)) {
        if (imm < 0 || imm > 31) {
            as_bad(_("Shift value should be in the range [0,31]"));
            goto fail;
        }

        int n_bytes = (imm == 1 || imm == 2) ? 2 : 3;
        if (n_bytes == 2) {
            sb &= ~0x10;
        } else {
            sb |= (imm & 0x01) << 3;
        }

        char *f = s12z_new_insn(n_bytes);
        if (f == NULL) goto fail;
        number_to_chars_bigendian(f++, insn->opc | Dd, 1);
        number_to_chars_bigendian(f++, sb, 1);

        if (n_bytes > 2) {
            number_to_chars_bigendian(f, 0x70 | (imm >> 1), 1);
        }

        return true;
    }

fail:
    fail_line_pointer = input_line_pointer;
    return false;
}

static void impute_shift_dir_and_type(const struct instruction *insn, short *type, short *dir) {
    if (insn->name[0] == 'l') {
        *type = 0;
    } else if (insn->name[0] == 'a') {
        *type = 1;
    } else {
        as_fatal(_("Bad shift mode"));
        return;
    }

    if (insn->name[2] == 'l') {
        *dir = 1;
    } else if (insn->name[2] == 'r') {
        *dir = 0;
    } else {
        as_fatal(_("Bad shift direction"));
    }
}

/* Shift instruction with a OPR operand */
static bool shift_two_operand(const struct instruction *insn) {
    uint8_t sb = 0x34;
    char *original_ilp = input_line_pointer;
    short dir, type;
    int size, n_opr_bytes;
    uint8_t buffer[4];
    expressionS exp;
    long imm;

    impute_shift_dir_and_type(insn, &type, &dir);
    sb |= (dir << 6) | (type << 7);

    size = size_from_suffix(insn, 0);
    sb |= (size - 1);

    if (!lex_opr(buffer, &n_opr_bytes, &exp, false) || !lex_match(',')) {
        input_line_pointer = original_ilp;
        fail_line_pointer = input_line_pointer;
        return false;
    }

    if (!lex_imm(&imm, NULL) || !(imm == 1 || imm == 2)) {
        input_line_pointer = original_ilp;
        fail_line_pointer = input_line_pointer;
        return false;
    }

    if (imm == 2) {
        sb |= 0x08;
    }

    char *insn_buf = s12z_new_insn(2 + n_opr_bytes);
    number_to_chars_bigendian(insn_buf++, insn->opc, 1);
    number_to_chars_bigendian(insn_buf++, sb, 1);
    emit_opr(insn_buf, buffer, n_opr_bytes, &exp);

    return true;
}

/* Shift instruction with a OPR operand */
bool shift_opr_imm(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    
    short dir = -1, type = -1;
    impute_shift_dir_and_type(insn, &type, &dir);

    int Dd = 0;
    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',')) {
        goto fail;
    }

    int n_bytes = 2;
    uint8_t buffer1[4], buffer2[4];
    int n_opr_bytes1, n_opr_bytes2;
    expressionS exp1, exp2;
    long imm;
    bool immediate;

    if (!lex_opr(buffer1, &n_opr_bytes1, &exp1, false) || !lex_match(',')) {
        goto fail;
    }
    
    n_bytes += n_opr_bytes1;
    immediate = lex_imm(&imm, NULL);

    if (!immediate && !lex_opr(buffer2, &n_opr_bytes2, &exp2, false)) {
        goto fail;
    }
    
    uint8_t sb = 0x20 | (size_from_suffix(insn, 0) - 1) | (dir << 6) | (type << 7);

    if (immediate) {
        if (imm != 2 && imm != 1) {
            n_bytes++;
            sb |= 0x10;
            if (imm % 2) sb |= 0x08;
        } else if (imm == 2) {
            sb |= 0x08;
        }
    } else {
        n_bytes += n_opr_bytes2;
        sb |= 0x10;
    }

    char *f = s12z_new_insn(n_bytes);
    number_to_chars_bigendian(f++, insn->opc | Dd, 1);
    number_to_chars_bigendian(f++, sb, 1);
    f = emit_opr(f, buffer1, n_opr_bytes1, &exp1);

    if (!immediate || (imm != 1 && imm != 2)) {
        number_to_chars_bigendian(f++, 0x70 | (imm >> 1), 1);
    } else {
        f = emit_opr(f, buffer2, n_opr_bytes2, &exp2);
    }

    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

/* Shift instruction with a register operand */
bool shift_reg(const struct instruction *insn) {
    short dir, type;
    impute_shift_dir_and_type(insn, &type, &dir);
    return lex_shift_reg_imm1(insn, type, dir) || lex_shift_reg(insn, type, dir);
}

static bool bm_regd_imm(const struct instruction *insn) {
    char *initial_line_pointer = input_line_pointer;
    int reg_index = 0;
    
    if (!lex_reg_name(REG_BIT_Dn, &reg_index) || !lex_match(',')) {
        goto failure;
    }

    long immediate_value;
    if (!lex_imm(&immediate_value, NULL)) {
        goto failure;
    }

    uint8_t bitmask = (immediate_value << 3) | reg_index;
    char *instruction_buffer = s12z_new_insn(2);
    number_to_chars_bigendian(instruction_buffer++, insn->opc, 1);
    number_to_chars_bigendian(instruction_buffer, bitmask, 1);

    return true;

failure:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_line_pointer;
    return false;
}

static bool bm_opr_reg(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;

    if (!lex_opr(buffer, &n_opr_bytes, &exp, false) || !lex_match(',')) {
        input_line_pointer = ilp;
        return false;
    }

    int Dn = 0;
    if (!lex_reg_name(REG_BIT_Dn, &Dn)) {
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


#include <stdbool.h>
#include <stdint.h>

static bool bm_opr_imm(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_opr_bytes;
    expressionS exp;

    if (!lex_opr(buffer, &n_opr_bytes, &exp, false) || !lex_match(',')) {
        goto fail;
    }

    long imm;
    if (!lex_imm(&imm, NULL)) {
        goto fail;
    }

    int size = size_from_suffix(insn, 0);
    if (imm < 0 || imm >= size * 8) {
        as_bad(_("Immediate operand %ld is inappropriate for size of instruction"), imm);
        goto fail;
    }

    uint8_t bm = 0x80 | ((size == 2) ? 0x02 : (size == 4) ? 0x08 : 0x00) | ((imm & 0x07) << 4) | (imm >> 3);
    char *f = s12z_new_insn(2 + n_opr_bytes);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    emit_opr(f, buffer, n_opr_bytes, &exp);

    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}


bool bm_regd_reg(const struct instruction *insn) {
    char *original_pointer = input_line_pointer;
    int Di = 0, Dn = 0;

    if (!lex_reg_name(REG_BIT_Dn, &Di) || !lex_match(',') || !lex_reg_name(REG_BIT_Dn, &Dn)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = original_pointer;
        return false;
    }

    uint8_t bm = (Dn << 4) | 0x81;
    uint8_t xb = Di | 0xb8;

    char *f = s12z_new_insn(3);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    number_to_chars_bigendian(f, xb, 1);

    return true;
}





bool bf_reg_opr_imm(const struct instruction *insn, short ie) {
    char *initial_pointer = input_line_pointer;
    int register_index = 0;

    if (!lex_reg_name(REG_BIT_Dn, &register_index) || !lex_match(',')) {
        goto error;
    }

    uint8_t buffer[4];
    int n_bytes;

    expressionS exp;
    if (!lex_opr(buffer, &n_bytes, &exp, false) || !lex_match(',')) {
        goto error;
    }

    long width;
    if (!lex_imm(&width, NULL) || width < 0 || width > 31 || !lex_match(':')) {
        as_bad(_("Invalid width value for %s"), insn->name);
        goto error;
    }

    long offset;
    if (!lex_constant(&offset) || offset < 0 || offset > 31) {
        as_bad(_("Invalid offset value for %s"), insn->name);
        goto error;
    }

    uint8_t i1 = (width << 5) | offset;
    int size = size_from_suffix(insn, 0);
    uint8_t bb = (ie ? 0x80 : 0x00) | 0x60 | ((size - 1) << 2) | (width >> 3);

    char *f = s12z_new_insn(4 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | register_index, 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);

    emit_opr(f, buffer, n_bytes, &exp);

    return true;

error:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = initial_pointer;
    return false;
}


bool bf_opr_reg_imm(const struct instruction *insn, short ie) {
    const char *initial_line_pointer = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;

    if (!lex_opr(buffer, &n_bytes, &exp, false) || !lex_match(',')) return restore_input_line_pointer(&initial_line_pointer);

    int Ds = 0;
    if (!lex_reg_name(REG_BIT_Dn, &Ds) || !lex_match(',')) return restore_input_line_pointer(&initial_line_pointer);

    long width;
    if (!lex_imm(&width, NULL) || width < 0 || width > 31) {
        as_bad(_("Invalid width value for %s"), insn->name);
        return restore_input_line_pointer(&initial_line_pointer);
    }

    if (!lex_match(':')) return restore_input_line_pointer(&initial_line_pointer);

    long offset;
    if (!lex_constant(&offset) || offset < 0 || offset > 31) {
        as_bad(_("Invalid offset value for %s"), insn->name);
        return restore_input_line_pointer(&initial_line_pointer);
    }

    uint8_t i1 = (uint8_t)((width << 5) | offset);
    int size = size_from_suffix(insn, 0);
    uint8_t bb = (uint8_t)((ie ? 0x80 : 0x00) | 0x70 | ((size - 1) << 2) | (width >> 3));

    char *f = s12z_new_insn(4 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, (uint8_t)(0x08 | Ds), 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);

    emit_opr(f, buffer, n_bytes, &exp);

    return true;
}

bool restore_input_line_pointer(const char **initial_line_pointer) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = *initial_line_pointer;
    return false;
}



static bool
bf_reg_reg_imm(const struct instruction *insn, short ie)
{
    char *initial_input_pointer = input_line_pointer;
    int Dd, Ds;
    long width, offset;

    if (!lex_reg_name(REG_BIT_Dn, &Dd) || !lex_match(',') ||
        !lex_reg_name(REG_BIT_Dn, &Ds) || !lex_match(',') ||
        !lex_imm(&width, NULL) || width < 0 || width > 31 ||
        !lex_match(':') || !lex_constant(&offset) || offset < 0 || offset > 31) 
    {
        as_bad(_("Invalid input for %s"), insn->name);
        input_line_pointer = initial_input_pointer;
        return false;
    }

    uint8_t bb = 0x20 | (Ds << 2) | (width >> 3) | (ie ? 0x80 : 0x00);
    uint8_t i1 = (width << 5) | offset;

    char *f = s12z_new_insn(4);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Dd, 1);
    number_to_chars_bigendian(f++, bb, 1);
    number_to_chars_bigendian(f++, i1, 1);

    return true;
}

static bool bf_reg_reg_reg(const struct instruction *insn ATTRIBUTE_UNUSED, short ie) {
    char *ilp = input_line_pointer;
    int Dd = 0, Ds = 0, Dp = 0;
    if (!(lex_reg_name(REG_BIT_Dn, &Dd) && lex_match(',') &&
          lex_reg_name(REG_BIT_Dn, &Ds) && lex_match(',') &&
          lex_reg_name((0x01u << REG_D2) | (0x01u << REG_D3) |
                       (0x01u << REG_D4) | (0x01u << REG_D5), &Dp)))
        goto fail;

    uint8_t bb = (ie ? 0x80 : 0x00) | (Ds << 2) | Dp;
    char *f = s12z_new_insn(3);
    if (!f)
        goto fail;

    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Dd, 1);
    number_to_chars_bigendian(f, bb, 1);

    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

static bool bf_opr_reg_reg(const struct instruction *insn, short ie) {
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;
    
    if (!lex_opr(buffer, &n_bytes, &exp, false) || !lex_match(','))
        goto fail;

    int Ds = 0;
    if (!lex_reg_name(REG_BIT_Dn, &Ds) || !lex_match(','))
        goto fail;

    int Dp = 0;
    if (!lex_reg_name((0x01u << REG_D2) | (0x01u << REG_D3) | (0x01u << REG_D4) | (0x01u << REG_D5), &Dp))
        goto fail;

    int size = size_from_suffix(insn, 0);
    uint8_t bb = 0x50 | Dp | ((size - 1) << 2) | (ie ? 0x80 : 0x00);

    char *f = s12z_new_insn(3 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Ds, 1);
    number_to_chars_bigendian(f++, bb, 1);

    emit_opr(f, buffer, n_bytes, &exp);
    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}


static bool
bf_reg_opr_reg(const struct instruction *insn, short ie) {
    char *initial_line_pointer = input_line_pointer;
    int Dd = 0, Dp = 0;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp;

    if (!lex_reg_name(REG_BIT_Dn, &Dd) ||
        !lex_match(',') ||
        !lex_opr(buffer, &n_bytes, &exp, false) ||
        !lex_match(',') ||
        !lex_reg_name((0x01u << REG_D2) |
                      (0x01u << REG_D3) |
                      (0x01u << REG_D4) |
                      (0x01u << REG_D5), &Dp)) {
        
        fail_line_pointer = input_line_pointer;
        input_line_pointer = initial_line_pointer;
        return false;
    }

    int size = size_from_suffix(insn, 0);
    uint8_t bb = (ie ? 0x80 : 0x00) | 0x40 | Dp | ((size - 1) << 2);

    char *f = s12z_new_insn(3 + n_bytes);
    number_to_chars_bigendian(f++, PAGE2_PREBYTE, 1);
    number_to_chars_bigendian(f++, 0x08 | Dd, 1);
    number_to_chars_bigendian(f++, bb, 1);

    emit_opr(f, buffer, n_bytes, &exp);

    return true;
}



bool bfe_reg_reg_reg(const struct instruction *insn) {
    if (!insn) {
        return false; // Handle null pointer case
    }
    return bf_reg_reg_reg(insn, 0);
}

bool bfi_reg_reg_reg(const struct instruction *insn) {
    if (insn == NULL) {
        return false;
    }
    return bf_reg_reg_reg(insn, 1);
}

bool bf_reg_reg_imm(const struct instruction *insn, int param);

bool bfe_reg_reg_imm(const struct instruction *insn) {
    if (insn == NULL) {
        return false;
    }
    return bf_reg_reg_imm(insn, 0);
}

bool bf_reg_reg_imm(const struct instruction *insn, int immediate);

bool bfi_reg_reg_imm(const struct instruction *insn) {
    if (insn == NULL) {
        return false; // Handle null pointer error case
    }
    return bf_reg_reg_imm(insn, 1);
}


bool bf_reg_opr_reg(const struct instruction *insn, int index);

bool bfe_reg_opr_reg(const struct instruction *insn) {
    if (!insn) {
        return false;
    }
    return bf_reg_opr_reg(insn, 0);
}

static bool bfi_reg_opr_reg(const struct instruction *insn) {
  if (insn == NULL) {
    return false;
  }
  return bf_reg_opr_reg(insn, 1);
}


#include <stdbool.h>

static bool bf_opr_reg_reg(const struct instruction *insn, int flag);

static bool bfe_opr_reg_reg(const struct instruction *insn) {
    if (insn == NULL) {
        return false;
    }
    return bf_opr_reg_reg(insn, 0);
}

bool bfi_opr_reg_reg(const struct instruction *insn) {
    if (insn == NULL) {
        return false; // handle NULL input gracefully
    }
    return bf_opr_reg_reg(insn, 1);
}

static bool bfe_reg_opr_imm(const struct instruction *insn) {
    if (insn == NULL) {
        return false; // Handle null pointer gracefully
    }
    return bf_reg_opr_imm(insn, 0);
}

bool bf_reg_opr_imm(const struct instruction *insn, int flag);

bool bfi_reg_opr_imm(const struct instruction *insn) {
    if (insn == NULL) {
        // Handle error or return appropriate boolean if null instruction is invalid.
        return false;
    }
    return bf_reg_opr_imm(insn, 1);
}

bool bfe_opr_reg_imm(const struct instruction *insn) {
    if (insn == NULL) {
        return false;
    }
    return bf_opr_reg_imm(insn, 0);
}

static bool bfi_opr_reg_imm(const struct instruction *insn) {
    if (insn == NULL) return false;
    return bf_opr_reg_imm(insn, 1);
}




static bool tb_reg_rel(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    bool long_displacement;
    expressionS exp;
    int reg;
    
    if (!(lex_reg_name(REG_BIT_Dn | REG_BIT_XY, &reg) && lex_match(',') && lex_15_bit_offset(&long_displacement, &exp))) {
        input_line_pointer = ilp;
        return false;
    }

    uint8_t lb = 0x00;
    if (reg == REG_X || reg == REG_Y) {
        lb |= 0x08;
    } else {
        lb |= reg;
    }
    if (reg == REG_Y) {
        lb |= 0x01;
    }

    const char *suffix = insn->name + 2;

    if (startswith(suffix, "ne")) {
        lb |= 0x00 << 4;
    } else if (startswith(suffix, "eq")) {
        lb |= 0x01 << 4;
    } else if (startswith(suffix, "pl")) {
        lb |= 0x02 << 4;
    } else if (startswith(suffix, "mi")) {
        lb |= 0x03 << 4;
    } else if (startswith(suffix, "gt")) {
        lb |= 0x04 << 4;
    } else if (startswith(suffix, "le")) {
        lb |= 0x05 << 4;
    }

    if (insn->name[0] == 'd') {
        lb |= 0x80;
    } else if (insn->name[0] != 't') {
        gas_assert(0);
    }

    char *f = s12z_new_insn(long_displacement ? 4 : 3);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, lb, 1);
    emit_15_bit_offset(f, 4, &exp);

    return true;
}


#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static bool tb_opr_rel(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp, exp2;
    bool long_displacement;
    uint8_t lb = 0x0C;

    if (!lex_opr(buffer, &n_bytes, &exp, false) || !lex_match(',') || !lex_15_bit_offset(&long_displacement, &exp2)) {
        fail_line_pointer = input_line_pointer;
        input_line_pointer = ilp;
        return false;
    }

    static const struct {
        const char *name_suffix;
        uint8_t mask;
    } condition_map[] = {
        {"ne", 0x00 << 4}, {"eq", 0x01 << 4}, {"pl", 0x02 << 4},
        {"mi", 0x03 << 4}, {"gt", 0x04 << 4}, {"le", 0x05 << 4}
    };

    for (int i = 0; i < sizeof(condition_map) / sizeof(condition_map[0]); ++i) {
        if (startswith(insn->name + 2, condition_map[i].name_suffix)) {
            lb |= condition_map[i].mask;
            break;
        }
    }

    if (insn->name[0] == 'd') {
        lb |= 0x80;
    } else if (insn->name[0] != 't') {
        gas_assert(0);
    }

    lb |= size_from_suffix(insn, 0) - 1;
    char *f = s12z_new_insn(n_bytes + (long_displacement ? 4 : 3));
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, lb, 1);
    f = emit_opr(f, buffer, n_bytes, &exp);
    emit_15_bit_offset(f, n_bytes + 4, &exp2);

    return true;
}




static bool test_br_reg_reg_rel(const struct instruction *insn) {
    char *ilp = input_line_pointer;
    int Di = 0, Dn = 0;
    uint8_t bm = 0x81, xb = 0xb8;
    
    if (!lex_reg_name(REG_BIT_Dn, &Di) || 
        !lex_match(',') || 
        !lex_reg_name(REG_BIT_Dn, &Dn) || 
        !lex_match(',')) {
        goto fail;
    }
    
    bool long_displacement;
    expressionS exp;
    
    if (!lex_15_bit_offset(&long_displacement, &exp)) {
        goto fail;
    }
    
    bm |= Dn << 4;
    xb |= Di;
    
    char *f = s12z_new_insn(long_displacement ? 5 : 4);
    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    number_to_chars_bigendian(f++, xb, 1);
    
    emit_15_bit_offset(f, 5, &exp);
    
    return true;
    
fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = ilp;
    return false;
}

static bool
test_br_opr_reg_rel(const struct instruction *insn) {
    char *original_input_line_pointer = input_line_pointer;

    uint8_t buffer[4];
    int num_bytes;
    expressionS exp1, exp2;

    if (!lex_opr(buffer, &num_bytes, &exp1, false) || !lex_match(',') || !process_second_part()) {
        handle_fail(original_input_line_pointer);
        return false;
    }
    
    bool long_displacement;
    if (!lex_15_bit_offset(&long_displacement, &exp2)) {
        handle_fail(original_input_line_pointer);
        return false;
    }

    int total_bytes = num_bytes + (long_displacement ? 4 : 3);
    char *instruction_space = s12z_new_insn(total_bytes);
    if (!instruction_space) {
        handle_fail(original_input_line_pointer);
        return false;
    }

    populate_instruction_space(instruction_space, insn, buffer, num_bytes, &exp1, total_bytes, &exp2);
    return true;
}

static bool process_second_part(void) {
    int register_number = 0;
    return lex_reg_name(REG_BIT_Dn, &register_number) && lex_match(',');
}

static void handle_fail(char *original_ilp) {
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_ilp;
}

static void populate_instruction_space(char *f, const struct instruction *insn, uint8_t *buffer, int n_bytes, expressionS *exp, int n, expressionS *exp2) {
    uint8_t bm = 0x81;
    bm |= REPLACEMENT_REGISTER << 4;
    int size = size_from_suffix(insn, 0);
    bm |= (size - 1) << 2;

    number_to_chars_bigendian(f++, insn->opc, 1);
    number_to_chars_bigendian(f++, bm, 1);
    f = emit_opr(f, buffer, n_bytes, exp);
    emit_15_bit_offset(f, n, exp2);
}


bool test_br_opr_imm_rel(const struct instruction *insn) {
    char *original_line_pointer = input_line_pointer;
    uint8_t buffer[4];
    int n_bytes;
    expressionS exp, exp2;
    bool long_displacement;

    if (!lex_opr(buffer, &n_bytes, &exp, false) || !lex_match(','))
        goto fail;
    
    long imm;
    if (!lex_imm(&imm, NULL) || imm < 0 || imm > 31 || !lex_match(','))
        goto fail;

    if (!lex_15_bit_offset(&long_displacement, &exp2))
        goto fail;

    int size = size_from_suffix(insn, 0);
    uint8_t bm = 0x80 | ((imm & 0x07) << 4) | ((imm >> 3) & 0x03);

    bm |= size == 4 ? 0x08 : (size == 2 ? 0x02 : 0);

    char *output = s12z_new_insn(n_bytes + (long_displacement ? 4 : 3));
    number_to_chars_bigendian(output++, insn->opc, 1);
    number_to_chars_bigendian(output++, bm, 1);
    output = emit_opr(output, buffer, n_bytes, &exp);
    emit_15_bit_offset(output, n_bytes + 4, &exp2);

    return true;

fail:
    fail_line_pointer = input_line_pointer;
    input_line_pointer = original_line_pointer;
    return false;
}


static bool
test_br_reg_imm_rel(const struct instruction *insn)
{
  char *ilp = input_line_pointer;

  int Di = 0;
  if (!lex_reg_name(REG_BIT_Dn, &Di) || 
      !lex_match(','))
    goto fail;

  long imm;
  if (!lex_imm(&imm, NULL) || 
      imm < 0 || imm > 31 || 
      !lex_match(','))
    goto fail;

  bool long_displacement;
  expressionS exp;
  if (!lex_15_bit_offset(&long_displacement, &exp))
    goto fail;

  uint8_t bm = Di | (imm << 3);

  char *f = s12z_new_insn(long_displacement ? 4 : 3);
  number_to_chars_bigendian(f++, insn->opc, 1);
  number_to_chars_bigendian(f++, bm, 1);

  emit_15_bit_offset(f, 4, &exp);

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
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define NAME_SIZE 20

void md_assemble(char *str) {
    char *op_start = str;
    char *op_end = str;
    char name[NAME_SIZE] = {0};
    size_t nlen = 0;

    fail_line_pointer = NULL;
    
    while (!is_end_of_stmt(*op_end) && !is_whitespace(*op_end)) {
        if (nlen < NAME_SIZE - 1) {
            name[nlen++] = TOLOWER(*op_end);
        }
        op_end++;
    }

    if (nlen == 0) {
        as_bad(_("No instruction or missing opcode."));
        return;
    }

    input_line_pointer = skip_whites(op_end);
    
    size_t opcodes_len = sizeof(opcodes) / sizeof(opcodes[0]);
    for (size_t i = 0; i < opcodes_len; ++i) {
        const struct instruction *opc = &opcodes[i];
        if (strcmp(name, opc->name) == 0) {
            if (opc->parse_operands(opc)) {
                return;
            }
            break;
        }
    }

    as_bad(_("Invalid instruction: \"%s\""), name);
    as_bad(_("First invalid token: \"%s\""), fail_line_pointer);

    while (*input_line_pointer++) {}
}





/* Relocation, relaxation and frag conversions.  */

/* PC-relative offsets are relative to the start of the
   next instruction.  That is, the address of the offset, plus its
   size, since the offset is always the last part of the insn.  */
long md_pcrel_from(fixS *fixP) {
    if (!fixP || !fixP->fx_frag) {
        return -1; // Error handling for null pointers
    }

    long ret = fixP->fx_size + fixP->fx_frag->fr_address;

    if (fixP->fx_addsy && S_IS_DEFINED(fixP->fx_addsy)) {
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

long s12z_relax_frag(void) {
    return 0;
}

void md_convert_frag(bfd *abfd, asection *sec, fragS *fragP) {
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
int md_estimate_size_before_relax(fragS *fragP, asection *segment) {
    (void)fragP; // Explicitly indicate unused parameter
    (void)segment; // Explicitly indicate unused parameter
    return 0;
}


/* If while processing a fixup, a reloc really needs to be created
   then it is done here.  */
arelent* tc_gen_reloc(asection* section, fixS* fixp) {
    arelent* reloc = notes_alloc(sizeof(arelent));
    if (reloc == NULL) {
        as_bad_where(fixp->fx_file, fixp->fx_line, "Failed to allocate memory for relocation entry.");
        return NULL;
    }

    reloc->sym_ptr_ptr = notes_alloc(sizeof(asymbol*));
    if (reloc->sym_ptr_ptr == NULL) {
        as_bad_where(fixp->fx_file, fixp->fx_line, "Failed to allocate memory for symbol pointer.");
        return NULL;
    }
    
    *reloc->sym_ptr_ptr = symbol_get_bfdsym(fixp->fx_addsy);
    reloc->address = fixp->fx_frag->fr_address + fixp->fx_where;
    reloc->howto = bfd_reloc_type_lookup(stdoutput, fixp->fx_r_type);
    
    if (reloc->howto == NULL) {
        as_bad_where(fixp->fx_file, fixp->fx_line,
                     "Relocation %d is not supported by object file format.",
                     (int) fixp->fx_r_type);
        return NULL;
    }

    reloc->addend = (section->flags & SEC_CODE) ? fixp->fx_addnumber : fixp->fx_offset;

    return reloc;
}

/* See whether we need to force a relocation into the output file.  */
int tc_s12z_force_relocation(fixS *fixP) {
    if (fixP == NULL) {
        return -1; // Return an error code to indicate a NULL pointer
    }
    return generic_force_reloc(fixP);
}

/* Here we decide which fixups can be adjusted to make them relative
   to the beginning of the section instead of the symbol.  Basically
   we need to make sure that the linker relaxation is done
   correctly, so in some cases we force the original symbol to be
   used.  */
#include <stdbool.h>

bool tc_s12z_fix_adjustable(void) {
    return true;
}

void md_apply_fix(fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED) {
    if (!fixP || !valP) {
        as_fatal(_("Invalid parameters."));
        return;
    }

    long value = *valP;

    if (!fixP->fx_addsy) {
        fixP->fx_done = 1;
    }

    if (fixP->fx_subsy) {
        as_bad_subtract(fixP);
    }

    char *where = fixP->fx_frag->fr_literal + fixP->fx_where;

    switch (fixP->fx_r_type) {
        case BFD_RELOC_8:
            where[0] = (char)value;
            break;
        case BFD_RELOC_16:
            bfd_putb16(value, where);
            break;
        case BFD_RELOC_24:
            bfd_putb24(value, where);
            break;
        case BFD_RELOC_S12Z_OPR:
            switch (fixP->fx_size) {
                case 3:
                    bfd_putb24(value, where);
                    break;
                case 2:
                    bfd_putb16(value, where);
                    break;
                default:
                    as_fatal(_("Invalid fx_size for fx_r_type BFD_RELOC_S12Z_OPR."));
                    return;
            }
            break;
        case BFD_RELOC_32:
            bfd_putb32(value, where);
            break;
        case BFD_RELOC_16_PCREL:
            if (value < -0x4000 || value > 0x3FFF) {
                as_bad_where(fixP->fx_file, fixP->fx_line, _("Value out of 16-bit range."));
            }
            bfd_putb16(value | 0x8000, where);
            break;
        default:
            as_fatal(_("Line %d: unknown relocation type: 0x%x."), fixP->fx_line, fixP->fx_r_type);
            return;
    }
}

/* Set the ELF specific flags.  */
void s12z_elf_final_processing(void) {
    // No operations to perform
}
