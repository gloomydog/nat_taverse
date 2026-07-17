#include "padding.h"
#include <sodium.h>
#include <string.h>

size_t pad_calc_capacity(size_t msg_len)
{
    /* +1 accounts for the 0x80 termination marker that sodium_pad adds.
     * Even for an exact multiple we still need to roll over to the next
     * block, so always add 1 before rounding up. */
    size_t needed = msg_len + 1;
    size_t blocks = (needed + PAD_BLOCKSIZE - 1) / PAD_BLOCKSIZE;
    return blocks * PAD_BLOCKSIZE;
}

int pad_message(const uint8_t *msg, size_t msg_len,
                 uint8_t *out_buf, size_t out_buf_cap,
                 size_t *out_padded_len)
{
    size_t padded_len = 0;

    if (out_buf_cap < msg_len) return -1;
    memcpy(out_buf, msg, msg_len);

    /* ISO/IEC 7816-4 style: 0x80 + 0x00 padding. Using libsodium's
     * constant-time implementation avoids leaking the message length
     * through a side channel derived from the padding length. */
    if (sodium_pad(&padded_len, out_buf, msg_len, PAD_BLOCKSIZE, out_buf_cap) != 0)
        return -1;

    *out_padded_len = padded_len;
    return 0;
}

int unpad_message(uint8_t *buf, size_t padded_len, size_t *out_msg_len)
{
    size_t msg_len = 0;

    if (sodium_unpad(&msg_len, buf, padded_len, PAD_BLOCKSIZE) != 0)
        return -1; /* padding marker not found = tampering or corruption */

    *out_msg_len = msg_len;
    return 0;
}
