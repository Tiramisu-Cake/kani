# Initialization edge fixtures

These fixtures cover ordinary union constants, raw field stores, immutable origins,
and unsized slot arguments. Each file selects one oracle root.

The initialized nonzero-subrange fixture records a conservative uninitialized-read
failure. The relocation and named-static companions use supported origin paths;
their initialized cases succeed. Hole companions distinguish payload reads from
origin or layout limitations.

By-value unsized slot transfers have an explicit unsupported-size boundary for both
initialized and hole inputs. Borrowed slice companions cover supported reference
access without moving an unsized value.
