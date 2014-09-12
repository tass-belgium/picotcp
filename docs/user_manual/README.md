Downloading the manual
----------------------

With every git commit, we rebuild the documentation and make the [user_doc.pdf](http://162.13.84.104/user_doc.pdf) file (click to download) publicly available.

If for some reason, you're looking for an older version of the documentation, please check out the wanted commit in git, and compile the manual as described below.

Compiling the manual
--------------------

The picoTCP user manual is written in LaTeX, which needs to be compiled to get a readable version.
First and foremost you need the compiler and some packages:
* sudo apt-get install texlive
* sudo apt-get install texlive-latex-extra

Now, cd into docs/user_manual and do
* ./build.sh

A user_doc.pdf should be generated in the current directory

