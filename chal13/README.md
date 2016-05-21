# Challenge 13

[Link](http://cryptopals.com/sets/2/challenges/13)

The trick here is to realize that you can mix and match cipher blocks from
different plaintexts as you wish. By manipulating the input value, we can create
blocks that fulfill our needs.

In this case, we first create a block that ends with "role=", and then another
block that begins with "admin". Putting those two together, we have an encrypted
string that includes the phrase "role=admin". We could've just used the rest of
the `admin_profile` vector, but then we'd have two "role=" phrases. The system
might detect this as an attack. Instead we create an additional block ssuch that
it says "rol=user" at the end of the string.
