# Challenge 1

[Link](http://cryptopals.com/sets/1/challenges/1)

I implemented base64 encoding and decoding for this task. The resulting library
(which is used heavily in the other challenges) is available
[here](https://github.com/Munksgaard/base64).

Additionally, the [hexstr](https://github.com/Munksgaard/hexstr) library handles
the hex encoded strings.

Additionally, it should be noted that the string that they ask us to encode
should be read as bytes. For example, the first 4 letters `4927` of the string
is in fact the byte sequence `[0x49, 0x27]`. The `as_bytes` and `to_byte`
functions take care of this translation.
