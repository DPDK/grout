#!/bin/sh

export LC_ALL=C
fail=0

duplicate_service_ids() {
	git --no-pager grep -w SERVICE_ID -- '*.proto' |
	sed -nre 's/^.*[[:space:]]*SERVICE_ID[[:space:]]*=[[:space:]]*([0-9A-Fa-fx]+).*/\1/p' |
	tr [:upper:] [:lower:] | LC_ALL=C sort | LC_ALL=C uniq -d
}

duplicate_ids=$(duplicate_service_ids)
if [ -n "$duplicate_ids" ]; then
	echo "error: duplicate SERVICE_IDs"
	for id in $duplicate_ids; do
		git --no-pager grep -iHn "SERVICE_ID[[:space:]]*=[[:space:]]*$id" -- '*.proto'
	done
	fail=1
fi

exit $fail
