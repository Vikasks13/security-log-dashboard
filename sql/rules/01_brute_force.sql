-- =============================================================================
-- Rule 1: SSH Brute Force Detection
-- MITRE ATT&CK: T1110.001 (Brute Force: Password Guessing)
-- Severity: High
-- Logic: 10+ failed authentication attempts from a single IP within a 5-minute
--        sliding window.
-- =============================================================================

INSERT INTO alerts (ts, src_ip, rule, severity, mitre_id, details)
WITH failure_windows AS (
    SELECT
        ts,
        src_ip,
        username,
        COUNT(*) OVER (
            PARTITION BY src_ip
            ORDER BY ts
            RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
        ) AS failures_in_5m
    FROM events
    WHERE event_type IN ('failed_password', 'invalid_user')
),
flagged_ips AS (
    SELECT
        src_ip,
        MIN(ts) AS first_breach_ts,
        MAX(ts) AS last_breach_ts,
        MAX(failures_in_5m) AS max_5m_failures,
        COUNT(DISTINCT username) AS targeted_users
    FROM failure_windows
    WHERE failures_in_5m >= 10
    GROUP BY src_ip
)
SELECT
    last_breach_ts AS ts,
    src_ip,
    'Brute Force' AS rule,
    'High' AS severity,
    'T1110.001' AS mitre_id,
    FORMAT(
        'Detected %s failed login attempts within a 5-minute sliding window (targeting %s distinct username(s))',
        max_5m_failures,
        targeted_users
    ) AS details
FROM flagged_ips
ORDER BY max_5m_failures DESC;
