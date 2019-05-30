Compile the kernel
============

Use `make menuconfig` and select `TRANSLATION_RANGER`, which help select
necessary kernel modules. (Use `/` to search for the option)

Related information
============

This is the kernel of "Translation Ranger: Operating System Support for
Contiguity-Aware TLBs". Its companion userspace applications can be find at:
https://github.com/ysarch-lab/translation_ranger_userspace.

Technical details on the kernel are documented at:
https://normal.zone/blog/2019-06-24-translation-ranger/.

Linux kernel
============

This file was moved to Documentation/admin-guide/README.rst

Please notice that there are several guides for kernel developers and users.
These guides can be rendered in a number of formats, like HTML and PDF.

In order to build the documentation, use ``make htmldocs`` or
``make pdfdocs``.

There are various text files in the Documentation/ subdirectory,
several of them using the Restructured Text markup notation.
See Documentation/00-INDEX for a list of what is contained in each file.

Please read the Documentation/process/changes.rst file, as it contains the
requirements for building and running the kernel, and information about
the problems which may result by upgrading your kernel.
