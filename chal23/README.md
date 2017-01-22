# Challenge 23

[Link](http://cryptopals.com/sets/3/challenges/23)

The challenge here is creating the reverse shift functions. The key is to
realize that for each of the shifts, a part of the original value is retained,
and that part can be used to calculate the rest of the original value.

Consider the following right shift:

```rust
let new_x = x ^ (x >> 1)
```

The leftmost bit of `new_x` will be exactly the same as the first bit of `x`. We
can use a simple bitmap to extract it. Let's call it `b` Now that we have the
leftmost bit of `x`, we can calculate the second leftmost bit of `x` as follows:

```rust
let second = (b >> 1) ^ (x_b)
```

Where `x_b` is the result of applying a bitmask that selects the second bit
from the left to `x`.

Now it's just a matter of generalizing this to shifts of arbitrary sizes.
