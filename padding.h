#ifndef PADDING_H
#define PADDING_H

#include <stdint.h>
#include <stddef.h>

/* Pad to 128-byte units. That's plenty for a line or two of chat -- most
 * messages will land in one or two buckets.
 * Too large wastes bandwidth; too small leaves the length granularity too
 * fine (e.g. being able to distinguish "hello" from "understood" by size
 * alone), so this is a reasonable middle ground. */
#define PAD_BLOCKSIZE 128

/*
 * Pads msg so its length becomes a multiple of PAD_BLOCKSIZE.
 * out_buf needs at least msg_len rounded up to a multiple of PAD_BLOCKSIZE
 * (the caller can precompute the required size with pad_calc_capacity()).
 * Returns: 0 = success, -1 = failure
 */
int pad_message(const uint8_t *msg, size_t msg_len,
                 uint8_t *out_buf, size_t out_buf_cap,
                 size_t *out_padded_len);

/*
 * Recovers the original message length from a padded buffer.
 * in_buf is expected to be the out_buf produced by pad_message.
 * Returns: 0 = success, -1 = invalid padding (possible tampering, should
 * be discarded)
 */
int unpad_message(uint8_t *buf, size_t padded_len, size_t *out_msg_len);

/* Computes the padded size (a multiple of PAD_BLOCKSIZE) needed to hold msg_len. */
size_t pad_calc_capacity(size_t msg_len);

#endif
