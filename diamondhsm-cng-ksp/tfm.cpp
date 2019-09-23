/* TomsFastMath, a fast ISO C bignum library.
*
* This project is meant to fill in where LibTomMath
* falls short.  That is speed ;-)
*
* This project is public domain and free for all purposes.
*
* Tom St Denis, tomstdenis@gmail.com
*/
#include "stdafx.h"
#include "tfm.h"

/* reverse an array, used for radix code */
void fp_reverse(unsigned char *s, int len)
{
    int     ix, iy;
    unsigned char t;

    ix = 0;
    iy = len - 1;
    while (ix < iy) {
        t = s[ix];
        s[ix] = s[iy];
        s[iy] = t;
        ++ix;
        --iy;
    }
}

void fp_to_unsigned_bin(fp_int *a, unsigned char *b)
{
    int     x;
    fp_int  t;

    fp_init_copy(&t, a);

    x = 0;
    while (fp_iszero(&t) == FP_NO) {
        b[x++] = (unsigned char)(t.dp[0] & 255);
        fp_div_2d(&t, 8, &t, NULL);
    }
    fp_reverse(b, x);
}

/* c = a / 2**b */
void fp_div_2d(fp_int *a, int b, fp_int *c, fp_int *d)
{
    fp_digit D, r, rr;
    int      x;
    fp_int   t;

    /* if the shift count is <= 0 then we do no work */
    if (b <= 0) {
        fp_copy(a, c);
        if (d != NULL) {
            fp_zero(d);
        }
        return;
    }

    fp_init(&t);

    /* get the remainder */
    if (d != NULL) {
        fp_mod_2d(a, b, &t);
    }

    /* copy */
    fp_copy(a, c);

    /* shift by as many digits in the bit count */
    if (b >= (int)DIGIT_BIT) {
        fp_rshd(c, b / DIGIT_BIT);
    }

    /* shift any bit count < DIGIT_BIT */
    D = (fp_digit)(b % DIGIT_BIT);
    if (D != 0) {
        register fp_digit *tmpc, mask, shift;

        /* mask */
        mask = (((fp_digit)1) << D) - 1;

        /* shift for lsb */
        shift = DIGIT_BIT - D;

        /* alias */
        tmpc = c->dp + (c->used - 1);

        /* carry */
        r = 0;
        for (x = c->used - 1; x >= 0; x--) {
            /* get the lower  bits of this word in a temp */
            rr = *tmpc & mask;

            /* shift the current word and mix in the carry bits from the previous word */
            *tmpc = (*tmpc >> D) | (r << shift);
            --tmpc;

            /* set the carry to the carry bits of the current word found above */
            r = rr;
        }
    }
    fp_clamp(c);
    if (d != NULL) {
        fp_copy(&t, d);
    }
}

/* c = a mod 2**d */
void fp_mod_2d(fp_int *a, int b, fp_int *c)
{
    int x;

    /* zero if count less than or equal to zero */
    if (b <= 0) {
        fp_zero(c);
        return;
    }

    /* get copy of input */
    fp_copy(a, c);

    /* if 2**d is larger than we just return */
    if (b >= (DIGIT_BIT * a->used)) {
        return;
    }

    /* zero digits above the last digit of the modulus */
    for (x = (b / DIGIT_BIT) + ((b % DIGIT_BIT) == 0 ? 0 : 1); x < c->used; x++) {
        c->dp[x] = 0;
    }
    /* clear the digit that is not completely outside/inside the modulus */
    c->dp[b / DIGIT_BIT] &= ~((fp_digit)0) >> (DIGIT_BIT - b);
    fp_clamp(c);
}

void fp_rshd(fp_int *a, int x)
{
    int y;

    /* too many digits just zero and return */
    if (x >= a->used) {
        fp_zero(a);
        return;
    }

    /* shift */
    for (y = 0; y < a->used - x; y++) {
        a->dp[y] = a->dp[y + x];
    }

    /* zero rest */
    for (; y < a->used; y++) {
        a->dp[y] = 0;
    }

    /* decrement count */
    a->used -= x;
    fp_clamp(a);
}

int fp_unsigned_bin_size(fp_int *a)
{
    int     size = fp_count_bits(a);
    return (size / 8 + ((size & 7) != 0 ? 1 : 0));
}

int fp_count_bits(fp_int * a)
{
    int     r;
    fp_digit q;

    /* shortcut */
    if (a->used == 0) {
        return 0;
    }

    /* get number of digits and add that */
    r = (a->used - 1) * DIGIT_BIT;

    /* take the last digit and count the bits in it */
    q = a->dp[a->used - 1];
    while (q > ((fp_digit)0)) {
        ++r;
        q >>= ((fp_digit)1);
    }
    return r;
}