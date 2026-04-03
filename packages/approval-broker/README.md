# SafeBrowse Approval Broker

Internal approval-signing broker for `secure_v5` test and audit flows.

This service keeps the Ed25519 private key outside the daemon and signs
capability-bound approval intents over HTTP.
