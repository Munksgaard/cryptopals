# Challenge 22

[Link](http://cryptopals.com/sets/3/challenges/22)

Here, the trick is simply that it is cheap to test if a given seed returns the
correct "random" number. If we know that the twister was seeded withing the last
30 minutes, and it was only used to generate one random number, we can easily
brute-force the seed.
