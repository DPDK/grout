#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import re
import sys

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <header> [<header>...]', file=sys.stderr)
        sys.exit(1)

    pattern = re.compile(r'^GR_MBUF_PRIV_DATA_TYPE\s*\(\s*(\w+)\s*,')
    all_types = []

    for header in sys.argv[1:]:
        with open(header, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    # The traces must be counted too, and are stored in a private struct
                    # prefixed with __.
                    all_types.append((header, '__' + match.group(1)))

    if not all_types:
        sys.exit(0)

    print('#include <stdio.h>')
    print('#define GR_MBUF_PRIV_SIZE_COMPUTE')
    for header, _ in all_types:
        print(f'#include "{header}"')
    print()
    print('union gr_mbuf_priv_types {')
    for _, type_name in all_types:
        print(f'\tstruct {type_name} {type_name};')
    print('};')
    print()
    print('int main(void) {')
    print('\tprintf("#define GR_MBUF_PRIV_MAX_SIZE %zu\\n", sizeof(union gr_mbuf_priv_types));')
    print('\treturn 0;')
    print('}')
