# Challenge 16

[Link](http://cryptopals.com/sets/2/challenges/16)

By manipulating individual bytes in one block of the cipher, we can manipulate the
corresponding individual bytes in the next block of the cipher. In particular,
each byte in each block of the cipher text is xor'ed onto the corresponding
decrypted byte in the next block, as illustrated
[here](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC).

We craft an input text that contains the string `AAAAAAAAAAAAAAAAAadminAtrue`.
Note that there are 16 'A's in front of `AadminAtrue`. That means, we can go
through the scrambled text, and replace each byte such that if it is xor'ed onto
the corresponding byte in the next decrypted block, and the byte in the next
block is `A`, we get `;`. The same goes for `=`.

Of course, we can be unlucky that, for instance `Aadmin` and `Atrue` are in
different blocks, which could cause the current implementation to fail, but
fixing that is just a simple matter of applying the appropriate padding.
