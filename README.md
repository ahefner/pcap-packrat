Packrat
=======

This is a program which can print reports and filter tcpdump PCAP
files in various quasi-useful ways.

Direct Dependencies
-------------------

  * Steel Bank Common Lisp (version 1.0.21.35 or higher) - http://sbcl.org/
  * Plokami library - http://www.suspicious.org/~night/plokami/
  * inotify-toools (needed for launcher script)

Transitively, it also depends on CFFI, Alexandria, trivial-features,
and babel, at a minimum.

Build instructions
------------------

First, ensure SBCL is installed and visible in your $PATH, and install
Plokami so that ASDF can find it (typically, this means creating a
symlink from ~/.sbcl/systems/plokami.asd to the plokami.asd file in
its directory).

Running the build.sh script will compile a stand-alone executable
called "packrat". Alternatively, packrat can be loaded into a running
image via ASDF and called from lisp.

Installation instructions
-------------------------

There's no automated installation yet. Add or copy the compiled
'packrat' binary and the packrat-custodian script into root's path,
or run it via sudo.

Running
-------

Run "packrat --help" for a list of commands.

A few useful commands:

    packrat strip INFILE OUTFILE [FACTOR=0.5]

      Selectively filter packet data from the input capture to achive the
      desired reduction in size.

    packrat minimize INFILE OUTFILE

      Drop all packet contents from the input capture, producing an output
      capture containing only headers.

    packrat flows FILENAME

      Print a table of the largest TCP flows in a packet capture.

    packrat tcp-flags-test FILENAME

      Prints a table of TCP packets and their flags (SYN,ACK,etc). Not
      generally useful, but interesting to see when and where the PSH and
      URG flags turn up. With the addition of timestamps, might be
      interesting for illustrating delayed ACKs.

    packrat tcp-port-traffic FILENAME

      Reports number of bytes transferred per TCP source port.

    packrat protocols FILENAME

      Reports number of packets per IP and ethernet protocol.


To monitor/compress logs as they are recorded:

    tcpdump -i eth1 -C 100 -w log -s 0
    packrat-custodian --unit-size 100 --size-bound 800


