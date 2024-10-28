# Caesar Cipher

## Task

The messages in
[this file](./ciphertext.txt)
are encrypted with the Caesar cipher,
and all messages are separated with newlines.
Each line uses a different letter for the
Caesar-shifting. Your task is to decrypt all messages.
Of course, this can be done by brute-forcing each line
and manually selecting the correct sentence.
However, your task is to automate the selection of the correct messages.

The file
[letter frequencies](./english_freq.txt)
contains the standard distribution of letters for the English language. 
The first line corresponds to `a`, the last line corresponds to `z`. 
Enhance your Frequency Analyzer and write a function that
determines how well a plaintext aligns with the standard distribution. 
Use the so-called _chi-square_ test:

```math
\chi^2 = \sum_{i=0}^{k=25} \frac{(observed_i - expected_i)^2}{expected_i}
```

In each case, select the plaintext with the lowest score from the chi-square test.
