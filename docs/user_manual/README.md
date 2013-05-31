Compiling the manual
--------------------

The PicoTCP user manual is written in LaTeX, which needs to be compiled to get a readable version.
First and foremost you need the compiler and some packages:
* sudo apt-get install texlive
* sudo apt-get install texlive-latex-extra

Now, cd into docs/user_manual and do
* ./build.sh

A user_doc.pdf should be generated in the current directory

