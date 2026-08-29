export function isOpen(now, openAt) {
  return new Date(now).getTime() >= new Date(openAt).getTime();
}

export function isLocked(now, lockAt) {
  return new Date(now).getTime() >= new Date(lockAt).getTime();
}

export function eventPhase(now, buildDeadlineAt, portalOpenAt, lockAt) {
  const stamp = new Date(now).getTime();
  if (!Number.isFinite(stamp)) return 'BUILDING';
  if (stamp < new Date(buildDeadlineAt).getTime()) return 'BUILDING';
  if (stamp < new Date(portalOpenAt).getTime()) return 'REVIEW';
  if (stamp < new Date(lockAt).getTime()) return 'LIVE';
  return 'LOCKED';
}

export function isBefore(now, deadlineAt) {
  return new Date(now).getTime() < new Date(deadlineAt).getTime();
}

export function scoreForSolved(rows) {
  const solved = rows.filter((row) => row.correct === 1 || row.correct === true).sort((a, b) => String(a.submitted_at).localeCompare(String(b.submitted_at)));
  const points = solved.reduce((sum, row) => sum + 100 + (row.first_blood ? 10 : 0), 0);
  // Tie-break by the moment the player's final total was reached, not by account order.
  const firstReachedAt = solved.length ? solved.reduce((stamp, row) => row.submitted_at || stamp, null) : null;
  return { points, solved: solved.length, firstReachedAt };
}
