# AES (Bonuspunkte)

The image [cipher.jpg](./cipher.jpg) is encrypted with the AES algorithm using the so called Propagating Cipher Block Chaining (PCBC) mode.

![PCBC encryption](./PCBC_encryption.svg)
![PCBC decryption](./PCBC_decryption.svg)

You have access to both the [Key](./key.txt) and the [Initialization Vector](./iv.txt).

Your task is to decrypt the image!

For this you need to solve 2 tasks:

- First, implement an AES decryption mechanism

- Second, use the decryption mechanism and apply PCBC decryption

You can find a source skeleton for python in [this file](./AES.py) to get you started.

Remember, you can use any programming language you want!

_NOTE_: Remember to remove possible padding bytes at the end of the decrypted plaintext.

The implementation uses PKCS7 padding.

There is no need to implement the multiplication used in AES.

The provided lookup tables can be used for this purpose.

That means for every possible input you can lookup the corresponding output (w.r.t. the multiplication operation)
without doing the calculation yourself.

_NOTE_: the 02 and 03 multiplication tables are only needed in the encryption process and thus not necessary for the decryption


Following a list of the used abbreviations and their meaning in the table file:

- IN ⇒ Input
- SB ⇒ S-Box
- SI ⇒ Inverse S-Box
- 02 ⇒ Multiplication with 0x02
- 03 ⇒ Multiplication with 0x03
- 09 ⇒ Multiplication with 0x09
- 0B ⇒ Multiplication with 0x0B
- 0D ⇒ Multiplication with 0x0D
- 0E ⇒ Multiplication with 0x0E

