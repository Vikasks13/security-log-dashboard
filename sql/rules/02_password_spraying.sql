-- =============================================================================
-- Rule 2: SSH Password Spraying Detection
-- MITRE ATT&CK: T1110.003 (Brute Force: Password Spraying)
-- Severity: High
-- Logic: A single source IP attempts authentication against 10 or more
--        distinct usernames across failed/invalid login events.
-- =============================================================================

INSERT INTO alerts (ts, src_ip, rule, severity, mitre_id, details)
SELECT
    MAX(ts) AS ts,
    src_ip,
    'Password Spraying' AS rule,
    'High' AS severity,
    'T1110.003' AS mitre_id,
    FORMAT(
        'Source IP targeted %s distinct usernames across %s failed authentication attempts',
        COUNT(DISTINCT username),
        COUNT(*)
    ) AS details
FROM events
WHERE event_type IN ('failed_password', 'invalid_user')
GROUP BY src_ip
HAVING COUNT(DISTINCT username) >= 10
ORDER BY COUNT(DISTINCT username) DESC;
