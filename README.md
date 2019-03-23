This package provides a library for the [NewHope key exchange
protocol](https://newhopecrypto.org/). It has been made via
examination of the official NewHope project's [public domain C
reference code](https://github.com/newhopecrypto/newhope) and the
author is not affiliated with that team or with NIST.

This codebase has not yet been reviewed by anyone other than the
author.  Until such time as it has been competently reviewed, please
consider it as a draft implementation only, and do not rely on it for
actual securtiy in practice. Judged by comparison with the reference
library, it does produce correct results but could contain subtle (or
obvious!) flaws.  In addition, it has not been optimized for
performance and at this stage is probably quite a bit slower than the
reference C implementation on any given platform.

This project uses the build manager "stack" to produceː

 * `Crypto.NewHope`, a library intended for general use.

 * `PQCgenKAT` -- a binary which generates KAT (Known Answer Test)
  files in the format required by the NIST PQC project. Invoke this
  binary with the single argument "all" to generate all of the KAT
  files.

 * `speed` -- a binary which runs performance tests of some of the
  NewHope functionality. These tests correspond to largely equivalent
  tests in the reference NewHope C code.

In addition, the project contains a fair number of
automatically-evaluated tests that cover a large swath of the important
functionality implemented, including that tested by the "test"
binaries built by the reference C source, and including comparison
between the KAT output that we produce and that produced by the
reference C implementation. To run the tests and view the results,
execute `stack test` at a command line.

लोकाः समस्ताः सुखिनोभवंतु

Patches, comments, and discussion are welcome. The most appropriate
place for these for the time being is probably the Github repository.
