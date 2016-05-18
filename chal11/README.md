# Challenge 11

[Link](http://cryptopals.com/sets/2/challenges/11)

I haven't really touched this file since I originally wrote it back in 2014,
except updating it to make it run with the current version of Rust. The
`random_encrypt` function and the `ecb_encrypted` function could probably be
cleaned up a little bit. The `random_encrypt` function also doesn't take into
account whether or not it's input actually aligns to 16 bytes: No padding is
used.

TODO: Properly pad the input and clean up `ecb_encrypted` and `random_encrypt`.
