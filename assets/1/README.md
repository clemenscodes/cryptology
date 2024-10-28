# Frequency Analyzer

## Task

Implement a program that analyzes arbitrary text files by counting the occurrence of letters.
All special characters (e.g., `., -_!\n`) and numbers should be ignored.
The program should treat all letters as case-insensitive and output:

- The letter,
- The number of occurrences, and
- A percentage value in relation to all letters in the text.

For example, the following text should generate a similar output as shown below:

| Letter | Occurrences | Percentage |
| ------ | ----------- | ---------- |
| s      | 4           | 23.529 %   |
| i      | 3           | 17.647 %   |
| t      | 3           | 17.647 %   |
| e      | 2           | 11.765 %   |
| a      | 1           | 5.882 %    |
| g      | 1           | 5.882 %    |
| h      | 1           | 5.882 %    |
| l      | 1           | 5.882 %    |
| n      | 1           | 5.882 %    |

Design your program such that you can easily reuse the frequency-analysis component in other programs as well.
You can use any programming language you want.
We will need the frequency analyzer for some other challenges as well. So choose wisely!

## Example Output

Example output of a frequency analyzer program using the input `test.txt`:

```bash
$ python solution.py ../test.txt
E 562 0.1148
T 407 0.09480
I 428 0.08968
A 423 0.08887
O 306 0.08283
S 356 0.07226
H 344 0.06963
N 299 0.06009
R 292 0.05927
L 277 0.05623
D 246 0.04993
Z 247 0.04912
C 197 0.02781
P 140 0.02111
G 77  0.01653
Y 67  0.01490
B 52  0.01055
M 38  0.00771
K 28  0.00568
X 24  0.00487
F 22  0.00446
J 12  0.00243
U 11  0.00223
Q 10  0.00203
V 8   0.00158
W 4   0.00081
```
