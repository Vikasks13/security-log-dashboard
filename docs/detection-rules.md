# Security Detection Rules & MITRE ATT&CK Mapping

This document details the four SQL-based detection rules implemented in `sql/rules/`, the analytical reasoning behind their thresholds, false-positive tuning considerations, and manual spot-check findings against the OpenSSH dataset.

---

## 1. Summary Matrix

| Rule File | Rule Name | Logic / Condition | Severity | MITRE ATT&CK ID | Technique Name |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `01_brute_force.sql` | **Brute Force** | `10+` failed attempts from a single IP within a **5-minute sliding window** | **High** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Brute Force: Password Guessing |
| `02_password_spraying.sql` | **Password Spraying** | Single IP attempts authentication against `10+` **distinct usernames** | **High** | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Brute Force: Password Spraying |
| `03_post_compromise_login.sql` | **Post-Compromise Login** | `accepted_password` event immediately following `1+` prior failed attempts from the same IP | **Critical** | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts |
| `04_off_hours_login.sql` | **Off-Hours Login** | `accepted_password` event occurring outside standard business hours (`09:00–18:00`) | **Medium** | [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts |

---

## 2. Rule Logic & Threshold Reasoning

### Rule 1: Brute Force (`sql/rules/01_brute_force.sql`)
- **MITRE ATT&CK:** `T1110.001` — *Brute Force: Password Guessing*
- **Severity:** `High`
- **SQL Sliding Window Pattern:**
  ```sql
  COUNT(*) OVER (
      PARTITION BY src_ip
      ORDER BY ts
      RANGE BETWEEN INTERVAL '5 minutes' PRECEDING AND CURRENT ROW
  )
  ```
- **Why this threshold (`>= 10` failures in 5 minutes)?**
  A legitimate human user who mistypes a password or has an expired SSH key typically fails 1 to 3 times before pausing to verify credentials or reset their password. Even an improperly configured automated script or IDE remote-SSH plugin rarely exceeds 5 retries in 5 minutes. Setting the threshold at **10 failed attempts within a rolling 5-minute window** eliminates human fat-finger noise while catching high-velocity automated tools (`Hydra`, `Medusa`, `patator`). Using a `RANGE BETWEEN INTERVAL '5 minutes' PRECEDING` window rather than fixed 5-minute buckets (`DATE_TRUNC`) ensures attacks straddling minute boundaries (e.g., `09:03` to `09:07`) are never split or missed.

---

### Rule 2: Password Spraying (`sql/rules/02_password_spraying.sql`)
- **MITRE ATT&CK:** `T1110.003` — *Brute Force: Password Spraying*
- **Severity:** `High`
- **SQL Aggregation Pattern:**
  ```sql
  GROUP BY src_ip
  HAVING COUNT(DISTINCT username) >= 10
  ```
- **Why this threshold (`>= 10` distinct usernames)?**
  Sophisticated adversaries often throttle their connection rate per account to evade per-user lockout policies, instead testing one common password across dozens of accounts (`root`, `admin`, `postgres`, `ubuntu`, `oracle`, `git`, `test`, `webmaster`). A legitimate engineer connects with 1 (occasionally 2) usernames from a single workstation IP. Any single IP probing **10 or more distinct usernames** is unambiguously performing account enumeration or password spraying.

---

### Rule 3: Post-Compromise Login (`sql/rules/03_post_compromise_login.sql`)
- **MITRE ATT&CK:** `T1078` — *Valid Accounts*
- **Severity:** `Critical`
- **SQL Correlation Pattern:**
  Correlates every `accepted_password` event (`a`) with preceding `failed_password` or `invalid_user` events (`f`) from the same `src_ip` (`f.src_ip = a.src_ip AND f.ts <= a.ts`).
- **Why this threshold (`Critical` severity)?**
  While Brute Force and Password Spraying represent *attempted* intrusion, an `accepted_password` event following failed attempts from the same IP indicates the attacker **succeeded** in guessing or spraying valid credentials and gained interactive shell access. While a small number of prior failures (1–2) can occasionally be a legitimate user mistyping their password, any login preceded by a burst of failures requires immediate SOC triage and host isolation.

---

### Rule 4: Off-Hours Login (`sql/rules/04_off_hours_login.sql`)
- **MITRE ATT&CK:** `T1078` — *Valid Accounts*
- **Severity:** `Medium`
- **SQL Filter Pattern:**
  ```sql
  WHERE event_type = 'accepted_password'
    AND (EXTRACT(HOUR FROM ts) < 9 OR EXTRACT(HOUR FROM ts) >= 18)
  ```
- **Why this threshold (`Outside 09:00–18:00`, `Medium` severity)?**
  Attackers frequently operate from different time zones or schedule automated credential-stuffing and post-exploitation tasks overnight when defenders are offline. Because legitimate on-call engineers or global teams may occasionally log in after 18:00 or before 09:00, this rule is assigned **Medium** severity to provide contextual enrichment and surface anomalous access times without causing high-severity alert fatigue.

---

## 3. Manual Spot-Check Findings

Running `python sql/run_rules.py` generates **13 alerts** across all four rules. Below is the manual verification of the top findings against the raw log events:

1. **`183.62.140.253` (Guangzhou, China) — Brute Force (`T1110.001`) & Password Spraying (`T1110.003`)**
   - **Spot-Check:** Between `10:54:43` and `11:04:43`, this IP generated **295 failed login events** (peaking at **150 failures in a single 5-minute window**) across **10 distinct usernames** (`root`, `admin`, `user`, `test`, etc.).
   - **Verdict:** High-velocity automated brute-force + dictionary attack.

2. **`187.141.143.180` (Mexico City, Mexico) — Password Spraying (`T1110.003`) & Brute Force (`T1110.001`)**
   - **Spot-Check:** Between `09:13:38` and `09:20:02`, this IP probed **28 distinct usernames** across **109 failed attempts** (up to **84 attempts in 5 minutes**).
   - **Verdict:** Classic SSH dictionary/username spray scanning common service accounts.

3. **`103.99.0.122` (Hanoi, Vietnam) — Password Spraying (`T1110.003`) & Brute Force (`T1110.001`)**
   - **Spot-Check:** Probed **19 distinct usernames** across **81 failed attempts** (peaking at **53 attempts in 5 minutes**).
   - **Verdict:** Sustained automated credential spraying.

4. **`112.95.230.3` (China), `5.188.10.180` (Russia), `185.190.58.151` (Singapore) — Brute Force (`T1110.001`)**
   - **Spot-Check:** Generated **28**, **27**, and **22** rapid failed attempts respectively within 1–3 minute windows targeting `root`, `pgadmin`, and `0101`.

5. **Post-Compromise & Off-Hours Validations (`T1078`)**
   - **Spot-Check:** Because the raw 2,000-line `OpenSSH_2k.log` slice only spans `06:55`–`11:04` on Dec 10 with a single benign login (`119.137.62.142` at `09:32:20`), `sql/run_rules.py` seeds 3 benchmark `openssh_benchmark` events (can be disabled via `--no-benchmark`) to validate end-to-end alerting for `Post-Compromise Login` (`183.62.140.253` and `185.190.58.151`) and `Off-Hours Login` (`23:14:05` and `03:42:10`).
