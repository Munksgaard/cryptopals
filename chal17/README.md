# Challenge 17

[Link](http://cryptopals.com/sets/2/challenges/17)

This was a very cool attack. It's sort of the combination between challenge 15
and challenge 16, in that we depend on padding validation to identify the bytes
of a block in reverse order, and we tamper with individual bytes in the previous
block (or IV) to manipulate the individual bytes in the current block.

The most important function is the `find_byte` function, which, assuming that
we've already found the last `n` bytes, identifies the `n+1` last byte by
finding one that gives a valid padding.
