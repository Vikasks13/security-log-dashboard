-- =============================================================================
-- Rule 4: Off-Hours Login Detection
-- MITRE ATT&CK: T1078 (Valid Accounts)
-- Severity: Medium
-- Logic: Accepted authentication occurring outside normal business hours
--        (before 09:00 or at/after 18:00 server time).
-- =============================================================================

INSERT INTO alerts (ts, src_ip, rule, severity, mitre_id, details)
SELECT
    ts,
    src_ip,
    'Off-Hours Login' AS rule,
    'Medium' AS severity,
    'T1078' AS mitre_id,
    FORMAT(
        'Accepted off-hours login for user "%s" at %s (outside 09:00-18:00 window)',
        username,
        TO_CHAR(ts, 'HH24:MI:SS')
    ) AS details
FROM events
WHERE event_type = 'accepted_password'
  AND (EXTRACT(HOUR FROM ts) < 9 OR EXTRACT(HOUR FROM ts) >= 18)
ORDER BY ts DESC;
