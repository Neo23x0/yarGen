Overview
========

A sample program I wrote to detect gibberish.  It uses a 2 character markov chain.

http://en.wikipedia.org/wiki/Markov_chain

This is a nice (IMO) answer to this guys question on stackoverflow.
http://stackoverflow.com/questions/6297991/is-there-any-way-to-detect-strings-like-putjbtghguhjjjanika/6298040#comment-7360747

Usage
=====

First train the model:

python gib_detect_train.py

Then try it on some sample input

python gib_detect.py

my name is rob and i like to hack True

is this thing working? True

i hope so True

t2 chhsdfitoixcv False

ytjkacvzw False

yutthasxcvqer False

seems okay True

yay! True

How it works
============
The markov chain first 'trains' or 'studies' a few MB of English text, recording how often characters appear next to each other. Eg, given the text "Rob likes hacking" it sees Ro, ob, o[space], [space]l, ... It just counts these pairs. After it has finished reading through the training data, it normalizes the counts. Then each character has a probability distribution of 27 followup character (26 letters + space) following the given initial.

So then given a string, it measures the probability of generating that string according to the summary by just multiplying out the probabilities of the adjacent pairs of characters in that string. EG, for that "Rob likes hacking" string, it would compute prob['r']['o'] * prob['o']['b'] * prob['b'][' '] ... This probability then measures the amount of 'surprise' assigned to this string according the data the model observed when training. If there is funny business with the input string, it will pass through some pairs with very low counts in the training phase, and hence have low probability/high surprise.

I then look at the amount of surprise per character for a few known good strings, and a few known bad strings, and pick a threshold between the most surprising good string and the least surprising bad string. Then I use that threshold whenever to classify any new piece of text.

Peter Norvig, the director of Research at Google, has this nice talk about "The unreasonable effectiveness of data" here, http://www.youtube.com/watch?v=9vR8Vddf7-s. This insight is really not to try to do something complicated, just write a small program that utilizes a bunch of data and you can do cool things.

