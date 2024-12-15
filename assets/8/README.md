# Task

We received a logfile from a webserver with strange content. There were
thousands of requests made to our encryption webservice, but we cannot make
sense of them. Perhaps this has something to do with our encryption mode.

We are using **Cipher Block Chaining** (CBC) with a **PKCS7** padding scheme.
The logfile from our webservice in a cleaned-up version can be found here:
[logfile](./logfile-clean-short).

*Just in case, we also updated our webservice and changed our encryption key.
*Perhaps someone found the key and used it?\*

Could you please analyze our webservice under
[http://vmar01.mni.thm.de:5000](http://vmar01.mni.thm.de:5000) and check if we
are still vulnerable to this attack.

You can use our new [**message**](./message.txt) and [**IV**](./iv.txt) to test our webservice.

---

## Submission and Bonus Points

### Submission

Submit your solution via Moodle as an archive (`.tar.gz` or `.zip`) file, that
contains your dockerized program and a docker environment to execute your
program.

You can get **5 bonus points** for this task! Provide the three files as
follows:

1. **explanation.txt** — Explain in your own words how to solve the problem
   you found. Also explain if there are additional technical precautions one
   can use to prevent those kinds of attacks.
   _(awards **1 bonus point**)_
2. **solution-logfile.txt** — Output of your program.
   _(awards **2 bonus points**)_
3. **solution-webservice.txt** — Output of your program, must use the online
   webservice at
   [http://vmar01.mni.thm.de:5000](http://vmar01.mni.thm.de:5000).
   _(awards **2 bonus points**)_

---
