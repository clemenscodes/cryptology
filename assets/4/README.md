# Vigenere cipher

## Task

The content of [this file](./ciphertext.txt) is encrypted with a Vigenere cipher.
(The key length is limited to 20 letters)

Your task is to decrypt the content.
Please note that you do not know the length of the key in this task!

Your solution will only be accepted if you find a better approach than simply trying all
possible combinations for every possible key length
(w.r.t. brute force) paired with a simple frequency analysis.

A more intelligent approach will solve this task in roughly quadratic time
$`O = n^2`$, whereas trying all possible combinations, i.e. brute force,
needs exponential time $`O = c^n \leftarrow c > 1`$.

## Submission

Submit your solution via Moodle as an archive (.tar.gz or .zip) file that contains your
dockerized program and a docker environment to execute your program. The name of the output
file must be `solution.txt`.
Assume that the name of the input file is `ciphertext.txt`.

## Help

_Note: The values used in this example are artificial and not the real values.
For a very short text, the solution is not accurate enough!_

1. You need to guess the key length, thus you know it is not longer than 20 letters,
   try every possible key length $`2 \leq \text{length} \leq 20`$.
2. For every key length analyze the ciphertext statistically to derive the best plaintext.

   a. You have to crack the key two letters at a time if the length is 3:

   ```
   VHEEMCRD (<- note that this is the plaintext for the example)
   ABCABCAB
   ```

You observe that the letters VH, EM, and RD are encrypted with the first two letters of the key.

a. Cut the ciphertext to strings with the size of the key length. Each column is then encoded with one letter.

Example:
Suppose the key is **ABC**. The ciphertext **VIGENERE** should be cut into:

    VIG
    ENE
    RE

1. By combining the first string with the second, the second with the third and so on.
   The last string should be combined with the first.
   This gives us:

   ```
   01 01 01  (key_index)
   -------
   VI EN RE  # letters encrypted with key[0] and key[1]

   12 12     (key_index)
   -----
   IG NE     # letters encrypted with key[1] and key[2]

   20 20     (key_index)
   -----
   GV EE     # letters encrypted with key[2] and key[0]
   ```

2. For each sequence of two consecutive letters
   try all possible two letter keys (AA, AB, AC, ..., ZY, ZZ).

   ```
   VI EN RE decrypted with AA gives VI EN RE
   VI EN RE decrypted with AB gives VH EM RD
   ...
   VI EN RE decrypted with ZZ gives WJ FO SF
   ```

3. Using the Bigram Frequencies (the frequencies are sorted alphabetically)
   give each key a score by multiplying the frequencies of the bigrams in the plaintext:

   ```
   CIPHER | KEY | PLAIN
   ---------------------
   VI EN RE | AB | VH EM RD

   score(AB) = (frequency(VH) + frequency(EM) + frequency(RD))
   ```

- Normally, you would calculate the score by multiplication:

  `score(AB) = frequency(VH) * frequency(EM) * frequency(RD)`.

  However, with the given bigram frequencies,
  which are provided as logarithmic values,
  you can use an addition instead.

- This means, the calculation using the numbers from the provided bigram Frequencies is as follows:

  `score(AB) = frequency(VH) + frequency(EM) + frequency(RD)`.

  - The higher the calculated value, the better is the score for that particular bigram pair.

1. Select for each string the key with the best score:

| PLAIN    | KEY | k_index | SCORE     |
| -------- | --- | ------- | --------- |
| VH EM RD | AB  | 01      | 151125528 |
| DA IY    | FG  | 12      | 119393088 |
| EI CR    | CN  | 20      | 122328401 |

2. Form the final key from these keys:

```
key[0] is either A or N, since score(AB) > score(CN), take A
key[1] is either B or F, since score(AB) > score(FG), take B
key[2] is either G or C, since score(CN) > score(FG), take C
=> the best key of length 3 is **ABC**
```

3. Do this process for key lengths 2 to 20.
4. By using frequency analysis, find the best fit of the 19 keys.
