# Reviewer demo
Read example.txt. It describes a synthetic service where anonymous callers can read all records. Score the proposed vector:

    python triage.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N

Expected result is 7.5 High. Now suppose the reporter clarifies that a normal user account is required:

    python triage.py --vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N --review-vector CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

The comparison shows PR changing from N to L and the score falling to 6.5. Ask participants which sentence supports that change.

    python triage.py --report example.txt --model llama3.2

Inspect the rationale and each metric. A model may abstain or return an invalid vector. Discuss what evidence an analyst would request. For a validation exercise remove the final availability metric from the first command. The tool should refuse to score the incomplete vector.
