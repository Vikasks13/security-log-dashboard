-- =============================================================================
-- Rule 3: Post-Compromise Login Detection
-- MITRE ATT&CK: T1078 (Valid Accounts)
-- Severity: Critical
-- Logic: Accepted authentication immediately following one or more failed
--        login attempts from the same source IP.
-- =============================================================================

INSERT INTO alerts (ts, src_ip, rule, severity, mitre_id, details)
WITH accepted_logins AS (
    SELECT
        id,
        ts,
        src_ip,
        username
    FROM events
    WHERE event_type = 'accepted_password'
),
preceding_failures AS (
    SELECT
        a.id AS accepted_id,
        a.ts AS accepted_ts,
        a.src_ip,
        a.username AS accepted_user,
        COUNT(f.id) AS prior_failures,
        MIN(f.ts) AS first_fail_ts,
        MAX(f.ts) AS last_fail_ts
    FROM accepted_logins a
    JOIN events f
        ON f.src_ip = a.src_ip
       AND f.event_type IN ('failed_password', 'invalid_user')
       AND f.ts <= a.ts
    GROUP BY a.id, a.ts, a.src_ip, a.username
    HAVING COUNT(f.id) >= 1
)
SELECT
    accepted_ts AS ts,
    src_ip,
    'Post-Compromise Login' AS rule,
    'Critical' AS severity,
    'T1078' AS mitre_id,
    FORMAT(
        'Accepted login for user "%s" immediately following %s prior failed authentication attempt(s) from the same IP',
        accepted_user,
        prior_failures
    ) AS details
FROM preceding_failures
ORDER BY accepted_ts DESC;
