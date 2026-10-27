// The support agent's Cedar policy (spec section 4). The gate evaluates it
// for every call that passed the manifest's contract.
//
//   principal  Release::"support-agent"
//   action     Action::"<tool>"   (Tool::"<tool>" is accepted too)
//   resource   Call::"<fingerprint>", with the call's arguments as resource.args
//   context    { task: <task-context.json>,
//                counters: { <tool>_1h, <tool>_24h, ... },  // calls forwarded so far
//                time: { unix, hour_utc, weekday } }
//
// Nothing is allowed unless a permit holds, and any forbid that holds wins.

@id("read-ticket")
permit (principal == Release::"support-agent", action == Action::"read_ticket", resource);

@id("send-email")
permit (principal == Release::"support-agent", action == Action::"send_email", resource);

// At most 50 emails an hour, across restarts: the counters are persistent.
@id("email-rate-limit")
forbid (principal, action == Action::"send_email", resource)
when { context.counters.send_email_1h >= 50 };

// Refunds up to 100 go through.
@id("refund-small")
permit (principal == Release::"support-agent", action == Action::"issue_refund", resource)
when { resource.args.amount <= 100 };

// Refunds over 100 and up to 500 need a signed approval receipt; the
// annotation is the route an approval broker sends the request to.
@id("refund-large")
@approval("slack:#support-leads")
permit (principal == Release::"support-agent", action == Action::"issue_refund", resource)
when { resource.args.amount > 100 && resource.args.amount <= 500 };
