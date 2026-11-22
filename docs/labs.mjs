const event = (time, source, message, severity, fields = {}) => ({
  time: `2026-01-15T${time}:00Z`,
  source,
  message,
  severity,
  ...fields,
});

export const LABS = [
  {
    id: 'soc-alert-triage',
    title: 'Triage a sign-in and download cluster',
    category: 'Cybersecurity',
    summary: 'Correlate sign-in events with file activity in a ten-minute window.',
    objective: 'Identify which account needs containment and which alerts lack corroboration.',
    decision: 'What is the most proportionate first response?',
    choices: [
      { id: 'observe', label: 'Close the sign-in alerts as isolated user mistakes' },
      { id: 'contain', label: 'Revoke the affected session and preserve its sign-in and file audit trail' },
      { id: 'disable-all', label: 'Disable every account in the audit stream' },
    ],
    answer: 'contain',
    explanation: 'Five rejected attempts preceded an accepted sign-in and a 128-file transfer on the same account. Contain that session and preserve the linked evidence.',
    events: [
      event('09:00', 'identity', 'Analyst A sign-in rejected.', 'warning', { kind: 'failure', account: 'analyst-a' }),
      event('09:01', 'identity', 'Analyst A sign-in rejected again.', 'warning', { kind: 'failure', account: 'analyst-a' }),
      event('09:02', 'identity', 'Analyst A sign-in rejected.', 'warning', { kind: 'failure', account: 'analyst-a' }),
      event('09:02', 'identity', 'Analyst B sign-in rejected once.', 'warning', { kind: 'failure', account: 'analyst-b' }),
      event('09:03', 'identity', 'Analyst A sign-in rejected.', 'warning', { kind: 'failure', account: 'analyst-a' }),
      event('09:04', 'identity', 'Analyst A sign-in rejected.', 'warning', { kind: 'failure', account: 'analyst-a' }),
      event('09:05', 'identity', 'Analyst A sign-in accepted.', 'info', { kind: 'success', account: 'analyst-a' }),
      event('09:06', 'storage', 'Analyst B downloaded one file.', 'info', { kind: 'download', account: 'analyst-b', count: 1 }),
      event('09:08', 'storage', 'Analyst A downloaded 128 files.', 'critical', { kind: 'download', account: 'analyst-a', count: 128 }),
    ],
  },
  {
    id: 'identity-access-review',
    title: 'Review privileged access after offboarding',
    category: 'Cybersecurity',
    summary: 'Reconcile current role grants with employment status and approval records.',
    objective: 'Find stale and unapproved privileges while preserving confirmed access.',
    decision: 'Which action follows from the access review?',
    choices: [
      { id: 'renew', label: 'Extend active grants until the quarterly review' },
      { id: 'revoke', label: 'Remove the offboarded privilege and suspend the grant with no approval' },
      { id: 'all-roles', label: 'Replace all administrator grants with reader grants' },
    ],
    answer: 'revoke',
    explanation: 'One privileged grant remains active after offboarding and one active operator lacks approval. The current approved administrator and the revoked grant need no change.',
    events: [
      event('10:00', 'people', 'Operator A is offboarded.', 'info', { kind: 'person', account: 'operator-a', active: false }),
      event('10:01', 'people', 'Operators B, C and D remain active.', 'info', { kind: 'active-people', accounts: ['operator-b', 'operator-c', 'operator-d'] }),
      event('10:02', 'directory', 'Operator A retains an administrator grant under approval AC-17.', 'warning', { kind: 'grant', account: 'operator-a', role: 'admin', approval: 'AC-17', enabled: true }),
      event('10:03', 'directory', 'Operator B has a responder grant with no approval reference.', 'warning', { kind: 'grant', account: 'operator-b', role: 'responder', enabled: true }),
      event('10:04', 'directory', 'Operator C has an administrator grant with approval AC-23.', 'info', { kind: 'grant', account: 'operator-c', role: 'admin', approval: 'AC-23', enabled: true }),
      event('10:05', 'directory', 'Operator D administrator grant is revoked.', 'info', { kind: 'grant', account: 'operator-d', role: 'admin', enabled: false }),
    ],
  },
  {
    id: 'cloud-posture',
    title: 'Review storage posture against data policy',
    category: 'Cybersecurity',
    summary: 'Apply visibility, encryption and exception rules to storage inventory.',
    objective: 'Distinguish an approved public assets bucket from unauthorized exposure.',
    decision: 'Which remediation should take priority?',
    choices: [
      { id: 'scope', label: 'Restrict the exposed restricted-data bucket, then enable encryption on the private archive' },
      { id: 'rotate', label: 'Rotate every service identity before reviewing storage' },
      { id: 'shutdown', label: 'Remove public access from all storage, including approved site assets' },
    ],
    answer: 'scope',
    explanation: 'The restricted bucket lacks an applicable exception and is publicly readable. The private archive needs encryption. The approved site-assets exception applies only to the public assets bucket.',
    events: [
      event('11:00', 'policy', 'Restricted data requires encryption and private access. Public assets require an approved exception.', 'info', { kind: 'policy', encryptedClass: 'restricted', publicClass: 'public-assets' }),
      event('11:01', 'inventory', 'Site assets are public and encrypted. Public exception PUB-01 is active.', 'info', { kind: 'storage', resource: 'site-assets', classification: 'public-assets', public: true, encrypted: true, approvedException: true }),
      event('11:02', 'inventory', 'Case exports are classified restricted, encrypted and public. No exception is active.', 'critical', { kind: 'storage', resource: 'case-exports', classification: 'restricted', public: true, encrypted: true, approvedException: false }),
      event('11:03', 'inventory', 'Restricted archive is private with encryption disabled.', 'warning', { kind: 'storage', resource: 'case-archive', classification: 'restricted', public: false, encrypted: false, approvedException: false }),
      event('11:04', 'inventory', 'Restricted audit store is private and encrypted.', 'info', { kind: 'storage', resource: 'audit-store', classification: 'restricted', public: false, encrypted: true, approvedException: false }),
    ],
  },
  {
    id: 'sbom-review',
    title: 'Prioritize a synthetic software advisory',
    category: 'Cybersecurity',
    summary: 'Match a software bill of materials to synthetic advisories and deployment scope.',
    objective: 'Identify the component that should block a release and the finding to track.',
    decision: 'What is the best release decision?',
    choices: [
      { id: 'all-block', label: 'Block every package that appears in the advisory feed' },
      { id: 'ship', label: 'Ship because two other inventory entries differ from the flagged runtime version' },
      { id: 'block-runtime', label: 'Hold for runtime remediation and record the build-only vulnerability for follow-up' },
    ],
    answer: 'block-runtime',
    explanation: 'The runtime package matches the critical advisory by name and version. The build-only package also matches an advisory, while the patched runtime version does not.',
    events: [
      event('12:00', 'sbom', 'Fictional package paperbridge 1.4.0 is deployed at runtime.', 'info', { kind: 'component', name: 'paperbridge', version: '1.4.0', scope: 'runtime' }),
      event('12:01', 'sbom', 'Fictional package inkformatter 0.7.0 is used during the build only.', 'info', { kind: 'component', name: 'inkformatter', version: '0.7.0', scope: 'build' }),
      event('12:02', 'sbom', 'A separate runtime service uses paperbridge 1.4.1.', 'info', { kind: 'component', name: 'paperbridge', version: '1.4.1', scope: 'runtime' }),
      event('12:03', 'advisories', 'Synthetic advisory S-01 is critical for paperbridge 1.4.0 only.', 'critical', { kind: 'advisory', name: 'paperbridge', version: '1.4.0', advisory: 'S-01' }),
      event('12:04', 'advisories', 'Synthetic advisory S-02 covers inkformatter 0.7.0 only.', 'warning', { kind: 'advisory', name: 'inkformatter', version: '0.7.0', advisory: 'S-02' }),
    ],
  },
  {
    id: 'forensic-custody',
    title: 'Validate a chain of custody',
    category: 'Cybersecurity',
    summary: 'Check the continuity of transfers and the recorded integrity of a preserved item.',
    objective: 'Identify where an item stops being suitable as verified evidence.',
    decision: 'How should the analysis team treat the inspection copy?',
    choices: [
      { id: 'use', label: 'Use the copy because it has the original item label' },
      { id: 'hold', label: 'Quarantine the copy and verify a new copy of the sealed original' },
      { id: 'overwrite', label: 'Overwrite the original digest with the latest recorded digest' },
    ],
    answer: 'hold',
    explanation: 'The final transfer has an unexplained custodian change and records a different integrity digest. Preserve the original and investigate both discrepancies.',
    events: [
      event('13:00', 'collection', 'Custodian A sealed item E-1 with synthetic digest A1.', 'info', { kind: 'capture', custodian: 'custodian-a', digest: 'fixture-a1' }),
      event('13:10', 'custody', 'Custodian A handed the item to the evidence locker and recorded digest A1.', 'info', { kind: 'transfer', from: 'custodian-a', to: 'locker', digest: 'fixture-a1' }),
      event('13:30', 'custody', 'The evidence locker released the item to examiner A and recorded digest A1.', 'info', { kind: 'transfer', from: 'locker', to: 'examiner-a', digest: 'fixture-a1' }),
      event('14:00', 'inspection', 'An unrecorded intermediary transferred a copy to the review station with digest B2.', 'critical', { kind: 'transfer', from: 'intermediary', to: 'review-station', digest: 'fixture-b2' }),
    ],
  },
  {
    id: 'backup-restore',
    title: 'Choose a recovery point after an outage',
    category: 'Cybersecurity',
    summary: 'Compare verified backup age and restore duration against recovery objectives.',
    objective: 'Use the most recent verified backup and quantify any missed service objectives.',
    decision: 'Which recovery plan is supported by the evidence?',
    choices: [
      { id: 'recent', label: 'Restore the newest backup even though its verification failed' },
      { id: 'verified', label: 'Restore the newest verified backup and report both recovery-objective misses' },
      { id: 'older', label: 'Use the oldest verified backup and report zero data loss' },
    ],
    answer: 'verified',
    explanation: 'The newest verified backup is 75 minutes older than the outage, exceeding the 60-minute recovery point objective. Its drill took 135 minutes, exceeding the 120-minute recovery time objective.',
    events: [
      event('05:00', 'backup', 'Backup B-07 completed and passed verification. Restore drill took 85 minutes.', 'info', { kind: 'backup', item: 'B-07', verified: true, restoreMinutes: 85 }),
      event('06:45', 'backup', 'Backup B-08 completed and passed verification. Restore drill took 135 minutes.', 'info', { kind: 'backup', item: 'B-08', verified: true, restoreMinutes: 135 }),
      event('07:45', 'backup', 'Backup B-09 completed but failed verification.', 'warning', { kind: 'backup', item: 'B-09', verified: false }),
      event('08:00', 'incident', 'Outage declared. RPO is 60 minutes and RTO is 120 minutes.', 'critical', { kind: 'outage', rpo: 60, rto: 120 }),
    ],
  },
  {
    id: 'email-authentication',
    title: 'Judge sender authentication before delivery',
    category: 'Cybersecurity',
    summary: 'Evaluate simulated SPF and DKIM results under a strict alignment policy.',
    objective: 'Find the incoming messages for which neither authenticated domain matches the From domain.',
    decision: 'What should the mail analyst do?',
    choices: [
      { id: 'accept-spf', label: 'Pass every message with SPF marked pass' },
      { id: 'quarantine', label: 'Quarantine messages that lack any aligned passing authentication and review them' },
      { id: 'require-both', label: 'Quarantine whenever either check fails, even if the other aligns' },
    ],
    answer: 'quarantine',
    explanation: 'A passing check only establishes alignment when its domain matches the From domain under this policy. Either aligned passing check can satisfy evaluation.',
    events: [
      event('14:00', 'gateway', 'M-01 From ledger.example. SPF pass for ledger.example and DKIM fail.', 'info', { kind: 'message', item: 'M-01', fromDomain: 'ledger.example', spf: 'pass', spfDomain: 'ledger.example', dkim: 'fail', dkimDomain: 'ledger.example' }),
      event('14:01', 'gateway', 'M-02 From ledger.example. SPF pass for relay.example and DKIM pass for billing.example.', 'warning', { kind: 'message', item: 'M-02', fromDomain: 'ledger.example', spf: 'pass', spfDomain: 'relay.example', dkim: 'pass', dkimDomain: 'billing.example' }),
      event('14:02', 'gateway', 'M-03 From catalog.example. SPF fail and DKIM pass for catalog.example.', 'info', { kind: 'message', item: 'M-03', fromDomain: 'catalog.example', spf: 'fail', spfDomain: 'relay.example', dkim: 'pass', dkimDomain: 'catalog.example' }),
      event('14:03', 'gateway', 'M-04 From ledger.example. Both SPF and DKIM fail.', 'warning', { kind: 'message', item: 'M-04', fromDomain: 'ledger.example', spf: 'fail', spfDomain: 'ledger.example', dkim: 'fail', dkimDomain: 'ledger.example' }),
    ],
  },
  {
    id: 'privacy-egress',
    title: 'Minimize fields before a metric export',
    category: 'Cybersecurity',
    summary: 'Review synthetic export requests against purpose, fields and retention policy.',
    objective: 'Determine which export can be approved and which requires changes.',
    decision: 'Which proposed export should proceed as specified?',
    choices: [
      { id: 'both', label: 'Send both exports because they use the same destination' },
      { id: 'summary', label: 'Approve the aggregate export with its declared purpose and retention' },
      { id: 'longer', label: 'Approve the enrichment export with extended retention' },
    ],
    answer: 'summary',
    explanation: 'Only the aggregate export matches the declared purpose, allowed fields and retention. The enrichment request exceeds all three limits.',
    events: [
      event('15:00', 'policy', 'The metrics destination allows the capacity purpose, region and count fields, and a one-day retention limit.', 'info', { kind: 'policy', purpose: 'capacity', fields: ['region', 'count'], maxDays: 1 }),
      event('15:01', 'queue', 'Aggregate export requests capacity planning, region and count, with one-day retention.', 'info', { kind: 'export', item: 'aggregate', purpose: 'capacity', fields: ['region', 'count'], retentionDays: 1 }),
      event('15:02', 'queue', 'Enrichment export requests outreach, region, count and customer_id, with 30-day retention.', 'warning', { kind: 'export', item: 'enrichment', purpose: 'outreach', fields: ['region', 'count', 'customer_id'], retentionDays: 30 }),
    ],
  },
  {
    id: 'incident-timeline',
    title: 'Reconstruct an incident from delayed logs',
    category: 'Cybersecurity',
    summary: 'Separate occurrence time from ingestion time before claiming containment.',
    objective: 'Order the events and calculate the delay from detection to verified denial.',
    decision: 'When is containment first supported by the observed evidence?',
    choices: [
      { id: 'at-request', label: 'At 16:04 when the revocation was requested' },
      { id: 'at-denial', label: 'At 16:07 when the service first rejected the session after revocation' },
      { id: 'at-ingestion', label: 'At 16:12 when the older session activity was ingested' },
    ],
    answer: 'at-denial',
    explanation: 'The session was still active at 16:05. The service first showed a denial at 16:07. Late ingestion does not change when the underlying event occurred.',
    events: [
      event('16:02', 'detection', 'Alert opened at 16:02 and was ingested immediately.', 'warning', { kind: 'detected', ingested: '16:02' }),
      event('16:04', 'identity', 'Revocation was requested at 16:04 and ingested at 16:05.', 'info', { kind: 'requested', ingested: '16:05' }),
      event('16:07', 'gateway', 'The service first denied the session at 16:07 and ingested the result at 16:08.', 'info', { kind: 'denied', ingested: '16:08' }),
      event('16:05', 'gateway', 'At 16:05 the session still accessed the service. This event was ingested at 16:12.', 'critical', { kind: 'accepted', ingested: '16:12' }),
    ],
  },
  {
    id: 'ai-trust-boundary',
    title: 'Verify provenance before an AI action',
    category: 'AI Evaluation',
    summary: 'Use declared provenance and a local policy to review simulated action proposals.',
    objective: 'Classify model outcomes by eligible authority and approved scope.',
    decision: 'Which disposition respects the authorization boundary?',
    choices: [
      { id: 'follow', label: 'Permit both actions because their event records arrive from the same service' },
      { id: 'block', label: 'Allow the approved summary and block the untrusted export proposal' },
      { id: 'ignore-all', label: 'Disable the authorized summary review as well' },
    ],
    answer: 'block',
    explanation: 'The local policy only permits a summary requested by a verified operator. Retrieved content has no authority to add a data export to the workflow.',
    events: [
      event('17:00', 'policy', 'Local workflow policy permits summarize for verified operators only.', 'info', { kind: 'policy', allowedActions: ['summarize'], trustedProvenance: 'verified-operator' }),
      event('17:01', 'operator', 'Verified operator requests a summary within the approved workflow.', 'info', { kind: 'proposal', action: 'summarize', provenance: 'verified-operator' }),
      event('17:02', 'retrieval', 'External source ingested as data with provenance marked untrusted.', 'info', { kind: 'source', provenance: 'untrusted-reference' }),
      event('17:03', 'simulation', 'Evaluation fixture records an export proposal attributed to the untrusted reference.', 'warning', { kind: 'proposal', action: 'export', provenance: 'untrusted-reference' }),
    ],
  },
];

const indexesWhere = (events, predicate) =>
  events.flatMap((item, index) => (predicate(item) ? [index] : []));

const elapsed = (start, end) => (Date.parse(end) - Date.parse(start)) / 60_000;
const metric = (label, value) => ({ label, value });
const finding = (severity, title, detail, eventIndexes) => ({ severity, title, detail, eventIndexes });

function analyzeSoc(events) {
  const findings = [];
  for (const successIndex of indexesWhere(events, ({ kind }) => kind === 'success')) {
    const success = events[successIndex];
    const failures = indexesWhere(events, ({ kind, account, time }) =>
      kind === 'failure' && account === success.account &&
      elapsed(time, success.time) >= 0 && elapsed(time, success.time) <= 10);
    const downloads = indexesWhere(events, ({ kind, account, time }) =>
      kind === 'download' && account === success.account &&
      elapsed(success.time, time) >= 0 && elapsed(success.time, time) <= 10);
    const fileCount = downloads.reduce((total, index) => total + events[index].count, 0);
    if (failures.length >= 5 && fileCount >= 100) {
      findings.push(finding('critical', 'Correlated account activity',
        `${success.account} had ${failures.length} failures, an accepted sign-in and ${fileCount} downloads within the defined windows.`,
        [...failures, successIndex, ...downloads]));
    }
  }
  return {
    metrics: [metric('Rejected sign-ins', indexesWhere(events, ({ kind }) => kind === 'failure').length),
      metric('Accounts with corroborated alerts', findings.length)],
    findings,
  };
}

function analyzeIdentity(events) {
  const findings = [];
  const departed = new Map();
  const grants = new Map();
  events.forEach((item, index) => {
    if (item.kind === 'person') {
      if (item.active) departed.delete(item.account);
      else departed.set(item.account, index);
    }
    if (item.kind === 'active-people') item.accounts.forEach((account) => departed.delete(account));
    if (item.kind === 'grant') grants.set(`${item.account}:${item.role}`, index);
  });
  const active = [...grants.values()].filter((index) => events[index].enabled);
  active.forEach((index) => {
    const { account, role, approval } = events[index];
    if (departed.has(account)) {
      findings.push(finding('critical', 'Privilege retained after offboarding',
        `${account} still has the ${role} role.`, [departed.get(account), index]));
    }
    if (!approval) {
      findings.push(finding('warning', 'Approval reference missing',
        `${account} has an enabled ${role} grant with no approval reference.`, [index]));
    }
  });
  return { metrics: [metric('Active grants', active.length), metric('Grant exceptions', findings.length)], findings };
}

function analyzeCloud(events) {
  const policyIndex = events.findIndex(({ kind }) => kind === 'policy');
  const policy = events[policyIndex];
  const storage = indexesWhere(events, ({ kind }) => kind === 'storage');
  const findings = [];
  storage.forEach((index) => {
    const item = events[index];
    if (item.public && !(item.classification === policy.publicClass && item.approvedException)) {
      findings.push(finding('critical', 'Unapproved public storage',
        `${item.resource} is public with no applicable exception.`, [policyIndex, index]));
    }
    if (item.classification === policy.encryptedClass && !item.encrypted) {
      findings.push(finding('warning', 'Encryption required',
        `${item.resource} contains restricted data with encryption disabled.`, [policyIndex, index]));
    }
  });
  return { metrics: [metric('Stores reviewed', storage.length), metric('Policy violations', findings.length)], findings };
}

function analyzeSbom(events) {
  const advisories = new Map();
  indexesWhere(events, ({ kind }) => kind === 'advisory').forEach((index) => {
    const { name, version } = events[index];
    advisories.set(`${name}@${version}`, index);
  });
  const components = indexesWhere(events, ({ kind }) => kind === 'component');
  const findings = components.flatMap((index) => {
    const { name, version, scope } = events[index];
    const advisoryIndex = advisories.get(`${name}@${version}`);
    if (advisoryIndex === undefined) return [];
    const advisory = events[advisoryIndex];
    return [finding(scope === 'runtime' ? advisory.severity : 'warning',
      scope === 'runtime' ? 'Runtime advisory match' : 'Build dependency advisory match',
      `${name} ${version} matches ${advisory.advisory} in the ${scope} scope.`, [index, advisoryIndex])];
  });
  return {
    metrics: [metric('Components reviewed', components.length),
      metric('Critical runtime matches', findings.filter(({ severity }) => severity === 'critical').length)],
    findings,
  };
}

function analyzeCustody(events) {
  const captureIndex = events.findIndex(({ kind }) => kind === 'capture');
  const capture = events[captureIndex];
  const transfers = indexesWhere(events, ({ kind }) => kind === 'transfer');
  const findings = [];
  let previousIndex = captureIndex;
  transfers.forEach((index) => {
    const transfer = events[index];
    const previous = events[previousIndex];
    const expectedFrom = previous.to ?? previous.custodian;
    if (transfer.from !== expectedFrom) {
      findings.push(finding('critical', 'Custody gap',
        `Transfer names ${transfer.from}, but the last recorded custodian was ${expectedFrom}.`,
        [previousIndex, index]));
    }
    if (transfer.digest !== capture.digest) {
      findings.push(finding('critical', 'Integrity digest mismatch',
        'The recorded copy digest differs from the sealed original fixture.', [captureIndex, index]));
    }
    previousIndex = index;
  });
  return { metrics: [metric('Transfers reviewed', transfers.length), metric('Discrepancies', findings.length)], findings };
}

function analyzeRestore(events) {
  const outageIndex = events.findIndex(({ kind }) => kind === 'outage');
  const outage = events[outageIndex];
  const backups = indexesWhere(events, ({ kind, time }) => kind === 'backup' && time <= outage.time)
    .sort((left, right) => events[right].time.localeCompare(events[left].time));
  const bestIndex = backups.find((index) => events[index].verified);
  if (bestIndex === undefined) {
    return {
      metrics: [metric('Verified recovery point', 'Unavailable')],
      findings: [finding('critical', 'No verified backup', 'No listed backup passed verification before the outage.', [outageIndex])],
    };
  }
  const best = events[bestIndex];
  const loss = elapsed(best.time, outage.time);
  const findings = [];
  if (loss > outage.rpo) {
    findings.push(finding('warning', 'Recovery point objective missed',
      `${loss} minutes of data at risk exceeds the ${outage.rpo}-minute objective.`, [bestIndex, outageIndex]));
  }
  if (best.restoreMinutes > outage.rto) {
    findings.push(finding('warning', 'Recovery time objective missed',
      `The ${best.restoreMinutes}-minute drill exceeds the ${outage.rto}-minute objective.`, [bestIndex, outageIndex]));
  }
  return {
    metrics: [metric('Best verified recovery point', best.item), metric('Data at risk (minutes)', loss),
      metric('Restore drill (minutes)', best.restoreMinutes)],
    findings,
  };
}

function analyzeEmail(events) {
  const findings = [];
  events.forEach(({ item, fromDomain, spf, spfDomain, dkim, dkimDomain }, index) => {
    const spfAligned = spf === 'pass' && spfDomain === fromDomain;
    const dkimAligned = dkim === 'pass' && dkimDomain === fromDomain;
    if (!spfAligned && !dkimAligned) {
      findings.push(finding('warning', 'No aligned authentication',
        `${item} has no passing SPF or DKIM result aligned with ${fromDomain}.`, [index]));
    }
  });
  return {
    metrics: [metric('Messages evaluated', events.length), metric('Messages failing alignment', findings.length)],
    findings,
  };
}

function analyzePrivacy(events) {
  const policyIndex = events.findIndex(({ kind }) => kind === 'policy');
  const policy = events[policyIndex];
  const exports = indexesWhere(events, ({ kind }) => kind === 'export');
  const findings = exports.flatMap((index) => {
    const request = events[index];
    const details = [];
    const excludedFields = request.fields.filter((field) => !policy.fields.includes(field));
    if (excludedFields.length) details.push(`Unauthorized fields: ${excludedFields.join(', ')}.`);
    if (request.purpose !== policy.purpose) details.push(`Purpose ${request.purpose} is outside the policy.`);
    if (request.retentionDays > policy.maxDays) details.push(`Retention exceeds ${policy.maxDays} day.`);
    return details.length
      ? [finding('critical', `Export ${request.item} blocked`, details.join(' '), [policyIndex, index])]
      : [];
  });
  return { metrics: [metric('Exports evaluated', exports.length), metric('Exports approved', exports.length - findings.length)], findings };
}

function analyzeTimeline(events) {
  const chronological = events.map((_, index) => index)
    .sort((left, right) => events[left].time.localeCompare(events[right].time));
  const detected = chronological.find((index) => events[index].kind === 'detected');
  const requested = chronological.find((index) => events[index].kind === 'requested');
  const denied = requested === undefined ? undefined : chronological.find((index) =>
    events[index].kind === 'denied' && events[index].time >= events[requested].time);
  const accepted = requested === undefined ? [] : chronological.filter((index) =>
    events[index].kind === 'accepted' && events[index].time > events[requested].time &&
    (denied === undefined || events[index].time < events[denied].time));
  const delay = detected === undefined || denied === undefined
    ? 'Not observed' : elapsed(events[detected].time, events[denied].time);
  const largestLag = Math.max(...events.map(({ time, ingested }) => elapsed(time, ingested)));
  const findings = [];
  if (accepted.length) {
    const evidence = [requested, ...accepted];
    if (denied !== undefined) evidence.push(denied);
    findings.push(finding('warning', 'Session activity after revocation request',
      `${accepted.length} accepted event(s) followed the request before any verified denial.`, evidence));
  }
  if (denied === undefined) {
    findings.push(finding('warning', 'Containment not verified',
      'The supplied records do not show a verified denial after a revocation request.',
      [detected, requested].filter((index) => index !== undefined)));
  }
  return {
    metrics: [metric('Detection to verified denial (minutes)', delay), metric('Largest ingestion delay (minutes)', largestLag)],
    findings,
  };
}

function analyzeAi(events) {
  const policyIndex = events.findIndex(({ kind }) => kind === 'policy');
  const policy = events[policyIndex];
  const proposals = indexesWhere(events, ({ kind }) => kind === 'proposal');
  const findings = proposals.flatMap((index) => {
    const { action, provenance } = events[index];
    const authorized = provenance === policy.trustedProvenance && policy.allowedActions.includes(action);
    if (authorized) return [];
    const sources = indexesWhere(events, (item, sourceIndex) =>
      item.kind === 'source' && item.provenance === provenance && sourceIndex < index);
    return [finding('critical', 'Action proposal blocked',
      `${action} from ${provenance} lacks authorization under the local policy.`, [policyIndex, ...sources, index])];
  });
  return {
    metrics: [metric('Proposals reviewed', proposals.length), metric('Proposals allowed', proposals.length - findings.length),
      metric('Proposals blocked', findings.length)],
    findings,
  };
}

const analyzers = {
  'soc-alert-triage': analyzeSoc,
  'identity-access-review': analyzeIdentity,
  'cloud-posture': analyzeCloud,
  'sbom-review': analyzeSbom,
  'forensic-custody': analyzeCustody,
  'backup-restore': analyzeRestore,
  'email-authentication': analyzeEmail,
  'privacy-egress': analyzePrivacy,
  'incident-timeline': analyzeTimeline,
  'ai-trust-boundary': analyzeAi,
};

function getLab(id) {
  const lab = LABS.find((item) => item.id === id);
  if (!lab) throw new RangeError(`Unknown lab: ${id}`);
  return lab;
}

const maxRecords = 2_000;
const maxInputSize = 2_000_000;
const nonempty = (value) =>
  typeof value === 'string' && value.trim().length > 0 && value.length <= 4_000 &&
  !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(value);
const nonnegative = (value) => Number.isSafeInteger(value) && value >= 0;
const boolean = (value) => typeof value === 'boolean';
const strings = (values) => Array.isArray(values) && values.length <= 100 && values.every(nonempty);
const optionalString = (value) => value == null || nonempty(value);
const optionalNumber = (value) => value == null || nonnegative(value);
const oneOf = (...values) => (value) => values.includes(value);

const schemas = {
  'soc-alert-triage': {
    failure: { account: nonempty },
    success: { account: nonempty },
    download: { account: nonempty, count: nonnegative },
  },
  'identity-access-review': {
    person: { account: nonempty, active: boolean },
    'active-people': { accounts: strings },
    grant: { account: nonempty, role: nonempty, enabled: boolean, approval: optionalString },
  },
  'cloud-posture': {
    policy: { encryptedClass: nonempty, publicClass: nonempty },
    storage: { resource: nonempty, classification: nonempty, public: boolean, encrypted: boolean, approvedException: boolean },
  },
  'sbom-review': {
    component: { name: nonempty, version: nonempty, scope: oneOf('runtime', 'build') },
    advisory: { name: nonempty, version: nonempty, advisory: nonempty },
  },
  'forensic-custody': {
    capture: { custodian: nonempty, digest: nonempty },
    transfer: { from: nonempty, to: nonempty, digest: nonempty },
  },
  'backup-restore': {
    backup: { item: nonempty, verified: boolean, restoreMinutes: optionalNumber },
    outage: { rpo: nonnegative, rto: nonnegative },
  },
  'email-authentication': {
    message: {
      item: nonempty, fromDomain: nonempty, spf: oneOf('pass', 'fail', 'none', 'softfail', 'neutral', 'temperror', 'permerror'),
      spfDomain: optionalString, dkim: oneOf('pass', 'fail', 'none', 'temperror', 'permerror'), dkimDomain: optionalString,
    },
  },
  'privacy-egress': {
    policy: { purpose: nonempty, fields: strings, maxDays: nonnegative },
    export: { item: nonempty, purpose: nonempty, fields: strings, retentionDays: nonnegative },
  },
  'incident-timeline': {
    detected: { ingested: nonempty },
    requested: { ingested: nonempty },
    denied: { ingested: nonempty },
    accepted: { ingested: nonempty },
  },
  'ai-trust-boundary': {
    policy: { allowedActions: strings, trustedProvenance: nonempty },
    source: { provenance: nonempty },
    proposal: { action: nonempty, provenance: nonempty },
  },
};

const singletonKinds = {
  'cloud-posture': 'policy',
  'forensic-custody': 'capture',
  'backup-restore': 'outage',
  'privacy-egress': 'policy',
  'ai-trust-boundary': 'policy',
};

function normalizeTimestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/u.test(value)) {
    return undefined;
  }
  const localDay = Date.parse(`${value.slice(0, 10)}T00:00:00Z`);
  const stamp = Date.parse(value);
  if (!Number.isFinite(localDay) || !Number.isFinite(stamp) ||
      new Date(localDay).toISOString().slice(0, 10) !== value.slice(0, 10) || Number(value.slice(11, 13)) > 23) {
    return undefined;
  }
  return new Date(stamp).toISOString();
}

function validateEvents(id, events) {
  if (!Array.isArray(events) || !events.length || events.length > maxRecords) {
    throw new TypeError(`Expected 1 to ${maxRecords} events for ${id}`);
  }
  const schema = schemas[id];
  const list = Array.from(events, (record, index) => {
    const fail = (message) => { throw new TypeError(`Event ${index + 1}: ${message}`); };
    if (!record || typeof record !== 'object' || Array.isArray(record)) fail('expected an object');
    const time = normalizeTimestamp(record.time);
    if (!time) fail('time must be an ISO 8601 timestamp with a timezone');
    for (const field of ['source', 'message']) {
      if (!nonempty(record[field])) fail(`${field} must be a nonempty string of up to 4,000 characters`);
    }
    if (!oneOf('info', 'warning', 'critical')(record.severity)) fail('severity must be info, warning or critical');
    if (typeof record.kind !== 'string' || !Object.hasOwn(schema, record.kind)) {
      fail(`kind must be one of ${Object.keys(schema).join(', ')}`);
    }
    for (const [field, check] of Object.entries(schema[record.kind])) {
      if (!check(record[field])) fail(`missing or invalid ${field} for ${record.kind}`);
    }
    const normalized = { ...record, time };
    if (id === 'backup-restore' && record.kind === 'backup' && record.verified && !nonnegative(record.restoreMinutes)) {
      fail('restoreMinutes is required for a verified backup');
    }
    if (id === 'email-authentication') {
      for (const field of ['fromDomain', 'spfDomain', 'dkimDomain']) {
        if (record[field]) normalized[field] = record[field].trim().toLowerCase().replace(/\.$/u, '');
      }
      if ((record.spf === 'pass' && !normalized.spfDomain) || (record.dkim === 'pass' && !normalized.dkimDomain)) {
        fail('a passing authentication result requires its corresponding domain');
      }
    }
    if (id === 'incident-timeline') {
      const original = /^\d{2}:\d{2}$/u.test(record.ingested)
        ? `${time.slice(0, 11)}${record.ingested}:00Z`
        : record.ingested;
      normalized.ingested = normalizeTimestamp(original);
      if (!normalized.ingested || normalized.ingested < time) {
        fail('ingested must be a valid timestamp at or after the event time');
      }
    }
    return normalized;
  });
  const singleton = singletonKinds[id];
  if (singleton && indexesWhere(list, ({ kind }) => kind === singleton).length !== 1) {
    throw new TypeError(`Expected exactly one ${singleton} event for ${id}`);
  }
  return list;
}

export function parseLabInput(id, text) {
  getLab(id);
  if (typeof text !== 'string' || !text.trim() || text.length > maxInputSize) {
    throw new TypeError(`Expected nonempty JSON or JSONL input of up to ${maxInputSize} characters`);
  }
  const input = text.trim();
  if (input.startsWith('[')) {
    return validateEvents(id, JSON.parse(input));
  }
  const lines = input.split(/\r?\n/u).filter((line) => line.trim());
  if (lines.length > maxRecords) throw new TypeError(`Expected no more than ${maxRecords} JSONL records`);
  return validateEvents(id, lines.map((line, index) => {
    try {
      return JSON.parse(line);
    } catch {
      throw new SyntaxError(`Invalid JSON on record line ${index + 1}`);
    }
  }));
}

export function evaluateLab(id, suppliedEvents) {
  const lab = getLab(id);
  return analyzers[lab.id](validateEvents(lab.id, suppliedEvents ?? lab.events));
}

export function scoreDecision(id, choiceId) {
  const lab = getLab(id);
  if (!lab.choices.some((choice) => choice.id === choiceId)) {
    throw new RangeError(`Unknown choice for ${id}: ${choiceId}`);
  }
  return { correct: choiceId === lab.answer, explanation: lab.explanation };
}
