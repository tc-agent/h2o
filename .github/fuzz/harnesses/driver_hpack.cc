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
 * Targeted fuzzer for h2o's HPACK (HTTP/2 header compression) implementation.
 *
 * Exercises h2o_hpack_parse_request and h2o_hpack_parse_response directly,
 * bypassing the full HTTP/2 server stack.  The dynamic table is preserved
 * across invocations so the fuzzer can explore table-update code paths.
 */

#define H2O_USE_EPOLL 1
#include <string.h>
#include <stdint.h>
#include "h2o.h"
#include "h2o/hpack.h"
#include "h2o/http2_common.h"

/* Persistent header table — shared across LLVMFuzzerTestOneInput calls so the
 * fuzzer can accumulate dynamic-table state and trigger table-eviction bugs. */
static h2o_hpack_header_table_t req_header_table;
static h2o_hpack_header_table_t resp_header_table;
static int init_done;

static void reset_table(h2o_hpack_header_table_t *t)
{
    h2o_hpack_dispose_header_table(t);
    memset(t, 0, sizeof(*t));
    t->hpack_capacity = 4096;
    t->hpack_max_capacity = 4096;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (!init_done) {
        memset(&req_header_table, 0, sizeof(req_header_table));
        req_header_table.hpack_capacity = 4096;
        req_header_table.hpack_max_capacity = 4096;
        memset(&resp_header_table, 0, sizeof(resp_header_table));
        resp_header_table.hpack_capacity = 4096;
        resp_header_table.hpack_max_capacity = 4096;
        init_done = 1;
    }

    if (Size == 0)
        return 0;

    /* Alternate between request and response parsing based on first byte. */
    int parse_as_response = Data[0] & 1;
    const uint8_t *src = Data + 1;
    size_t len = Size - 1;

    h2o_mem_pool_t pool;
    h2o_mem_init_pool(&pool);

    if (!parse_as_response) {
        h2o_iovec_t method = {NULL, 0}, authority = {NULL, 0}, path = {NULL, 0}, protocol = {NULL, 0};
        const h2o_url_scheme_t *scheme = NULL;
        h2o_headers_t headers = {NULL, 0, 0};
        int pseudo_header_exists_map = 0;
        size_t content_length = SIZE_MAX;
        h2o_iovec_t expect = {NULL, 0};
        h2o_cache_digests_t *digests = NULL;
        h2o_iovec_t datagram_flow_id = {NULL, 0};
        const char *err_desc = NULL;

        h2o_hpack_parse_request(&pool, h2o_hpack_decode_header, &req_header_table, &method, &scheme, &authority, &path, &protocol,
                                &headers, &pseudo_header_exists_map, &content_length, &expect, &digests, &datagram_flow_id, src,
                                len, &err_desc);
        if (digests != NULL)
            h2o_cache_digests_destroy(digests);
    } else {
        h2o_headers_t headers = {NULL, 0, 0};
        int status = 0;
        h2o_iovec_t datagram_flow_id = {NULL, 0};
        const char *err_desc = NULL;

        h2o_hpack_parse_response(&pool, h2o_hpack_decode_header, &resp_header_table, &status, &headers, &datagram_flow_id, src,
                                 len, &err_desc);
    }

    h2o_mem_clear_pool(&pool);

    /* Reset tables periodically to bound memory use and explore fresh-state paths. */
    if (req_header_table.hpack_size > 65536)
        reset_table(&req_header_table);
    if (resp_header_table.hpack_size > 65536)
        reset_table(&resp_header_table);

    return 0;
}
