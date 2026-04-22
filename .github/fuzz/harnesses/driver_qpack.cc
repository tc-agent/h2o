/*
 * Copyright (c) 2026 Fastly, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/*
 * Targeted fuzzer for h2o's QPACK (HTTP/3 header compression) implementation.
 *
 * QPACK has two streams: an encoder stream carrying table-update instructions,
 * and per-request header blocks.  The input is split as follows:
 *   byte 0:     length of encoder-stream data (0..255)
 *   bytes 1..N: encoder stream bytes fed to h2o_qpack_decoder_handle_input
 *   bytes N+1..: HEADERS frame payload fed to h2o_qpack_parse_request
 *
 * The decoder is persistent across calls so the fuzzer can accumulate dynamic
 * table state and exercise reference-tracking code paths.
 */

#define H2O_USE_EPOLL 1
#include <string.h>
#include <stdint.h>
#include "h2o.h"
#include "h2o/hpack.h"
#include "h2o/qpack.h"

static h2o_qpack_decoder_t *dec;
static int64_t stream_id_counter;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (dec == NULL)
        dec = h2o_qpack_create_decoder(4096, 100);

    if (Size < 1)
        return 0;

    /* First byte encodes encoder-stream length (capped at remaining input). */
    size_t enc_len = Data[0];
    if (enc_len + 1 > Size)
        enc_len = Size - 1;

    const uint8_t *enc_src = Data + 1;
    const uint8_t *enc_end = enc_src + enc_len;
    const uint8_t *hdr_src = enc_end;
    size_t hdr_len = Size - 1 - enc_len;

    /* Feed encoder stream data into the decoder. */
    if (enc_len > 0) {
        int64_t *unblocked_ids = NULL;
        size_t num_unblocked = 0;
        const char *err_desc = NULL;
        /* unblocked_ids points into the decoder's internal array — do not free it. */
        h2o_qpack_decoder_handle_input(dec, &unblocked_ids, &num_unblocked, &enc_src, enc_end, &err_desc);
    }

    /* Parse request headers from the HEADERS frame payload. */
    if (hdr_len > 0) {
        h2o_mem_pool_t pool;
        h2o_mem_init_pool(&pool);

        h2o_iovec_t method = {NULL, 0}, authority = {NULL, 0}, path = {NULL, 0}, protocol = {NULL, 0};
        const h2o_url_scheme_t *scheme = NULL;
        h2o_headers_t headers = {NULL, 0, 0};
        int pseudo_header_exists_map = 0;
        size_t content_length = SIZE_MAX;
        h2o_iovec_t expect = {NULL, 0};
        h2o_cache_digests_t *digests = NULL;
        h2o_iovec_t datagram_flow_id = {NULL, 0};
        uint8_t outbuf[H2O_HPACK_ENCODE_INT_MAX_LENGTH];
        size_t outbuf_size = 0;
        const char *err_desc = NULL;

        h2o_qpack_parse_request(&pool, dec, stream_id_counter++, &method, &scheme, &authority, &path, &protocol, &headers,
                                &pseudo_header_exists_map, &content_length, &expect, &digests, &datagram_flow_id, outbuf,
                                &outbuf_size, hdr_src, hdr_len, &err_desc);
        if (digests != NULL)
            h2o_cache_digests_destroy(digests);

        h2o_mem_clear_pool(&pool);
    }

    /* Recreate the decoder periodically to avoid unbounded memory growth from
     * a large dynamic table and to explore the initial-state code paths. */
    if (stream_id_counter % 64 == 0) {
        h2o_qpack_destroy_decoder(dec);
        dec = h2o_qpack_create_decoder(4096, 100);
    }

    return 0;
}
