# Challenge 8

[Link](http://cryptopals.com/sets/1/challenges/8)

Here, the trick is simply that two identical blocks is a pretty good indication
that a given cipher-text has been encoded under ECB. We sort and deduplicate the
list of blocks in each decoded line and find a line where the total number of
blocks has been reduced.
