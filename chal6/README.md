# Challenge 6

[Link](http://cryptopals.com/sets/1/challenges/6)

As it turns out, it's not really necessary to guess the keysize, at least for
problems of this size. Instead we can just brute force our way to the correct
solution. However, for bigger problems, that might not be feasible.

My first implementation for this challenge was rather messy. Enamored with
iterators, I'd written some quite complicated iterators for returning every
`n` element, for jumping between entries and so on and so forth. I believe the
current implementation is a lot simpler, although it might be possible to
simplify it even more with the use of the standard iterators.

TODO: Actually guess the keysize instead of brute forcing.
