-- Persist authenticated transport responses for asynchronous CLI agents.
ALTER TABLE outbox ADD COLUMN response_json TEXT;
