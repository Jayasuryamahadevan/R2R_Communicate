# Work item architecture

Every executable unit of work uses the same durable record and lifecycle.
Capability requests and fleet missions keep their own validation and execution
rules; they do not define separate persistence or lifecycle systems.

```text
queued -> running -> succeeded
                  -> failed
                  -> cancelled
```

`queued`, `running`, `succeeded`, `failed`, and `cancelled` are the only
lifecycle states. A `phase` describes work within a state, such as `preflight`,
`assigned`, or `cancel_requested`. It never creates another lifecycle state.
Mission definitions and adapter inputs are payloads; vehicle, preflight, and
fencing details are metadata. Every record also has an owner, a kind, an
idempotency key, timestamps, and optional result, error, or lease data.

`fasp_harness/storage/work_items_repo.py` owns persistence, idempotent creation,
guarded state changes, active-work queries, and stale intent lease handling.
`TasksRepo` and `MissionsRepo` are small protocol-facing projections over that
store. They preserve the current `task.*` and `mission.*` messages; mission
responses also expose the common `status` and `phase` fields. Work IDs include
their kind (`intent:<key>` or `mission:<id>`) so unrelated domains cannot
collide.

The lifecycle is shared, while effects stay in domain services. Intent work
still passes capability policy and grants before the bounded adapter pool
runs it. A timeout does not replay an adapter call after restart; an expired
lease ends as failed. Mission work still checks the safety supervisor,
coordinator leadership, vehicle eligibility, preflight, and reservations
before dispatch. Its running record is reconciled against the fleet vendor.
Queued work can be cancelled before execution starts. Running work becomes
`cancelled` only after its adapter or vendor confirms the stop; otherwise it
remains active and the caller receives its current outcome.

Migration `0008_unified_work_items.sql` copies existing `tasks` and `missions`
into `work_items` before removing the separate tables. Existing mission phase
names and terminal outcomes are kept as phase or result data during that move.
