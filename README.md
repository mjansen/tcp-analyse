tcp-analyse
===========

look at some tcp connections

This is early days, so I do not recommend you look at this as yet.

The idea eventually is to compute some interesting properties of tcp connections,
with a view towards trouble-shooting.

The language is haskell.

We use the pcap library, and network-data.

split.hs
--------

When monitoring traffic from a given set of ip addresses, we can
capture the data as follows:

tcpdump -i eth? -nn -w cfm-dump -W 10 -C 100 host ...

and collect all the files that result.

The purpose of split.hs is to go through a list of such pcap files and
split the traffic into individual tcp sessions, writing each session
to a separate file.  This will make it easier to look at these sessions.
