## Background

This Python Training site was created to document and share a family project undertaken by a father and son team to explore a different approach to learning a new programming language. The language of choice is Python which was selected for a number of reasons including, popularity in the software development community, object oriented architecture, interpreted scripting language, online documentation, and ease of access to install and execute. 

The next challenge is an approach to learning this new programming language Python. The pool of Python documentation on the internet combined with published texts is deep and wide. A traditional academic programming language course might follow a textbook of some type designed to give an overall view of the Python language using primarily abstract exercises. A lab execution environment is a requirement, but, well within reach of any home computing environment today. We can easily get a Python installation up on a Windows, Mac, Linux desktop, or virtual machine on a cloud installation like AWS. Armed with all the tools the question arose as to what problem  space do we want to use to explore this new language.

The team chose to use the cryptography space as an entry level introduction into Python. The reality is the team also needs to learn a bit about cryptography in general for this exercise. The problem domain chosen is documented on the [Cryptopals.com](https://cryptopals.com) website. The Cryptopals guys recommend getting your hands dirty with some code, therefore, the team is going to do just that with Python. In this way we look at several things in paralell which is more akin to the real world. We pick a particular programming language, we learn what we need to know about the problem space, we learn how to learn a new language from scratch, and we learn a bit about modern development tools like git. 

The approach used here is informal and uses the following background and guidelines:

* The senior member of the team is a career software engineer with a background in software development using a number languages. The senior does not have a background developing in Python and is, hence, learning Python from scratch.
* The senior member of the team has a background in mathematics and statistics.
* The senior member of the team has a background in hardware architectures and machine language programming.
* The junior member of the team is a rising systems network administrator with a background in firewalls and desktop administration.
* The junior member of the team has programmed in multiple scripting languages, but is new to a more full featured language like Python.
* The problem space defined by the Cryptopals challenges determines the boundary of exploration into the Python language for this project. Only those Python features needed to solve the challenges are explored. 
* This is a self learning environment where existing knowledge is used to learn new concepts using the modern aids available from available websites. Common problems are researched for the specific language construct and adapted to original code in this repo.
* Expect to see commented out print statements previously used to examine statistical calculations.

## Repository Structure 

* The structure of this repo is based on the problem sets with python scripts named after the specific challenges documented on the [Cryptopals Set 1 challenges](https://cryptopals.com/sets/1) website.
* After working through the challenges a file of reusable functions was developed to illustrate a simple example of how to write and use functions in python. 
* Examples of how to document source code are embedded in the code files. The minimal standard is to at least provide the original author of the code memory of why a piece of code was written the way it was. This is particularly helpful when using language specific idioms. This particular problem domain lends itself to idioms that are most concise and useful, but as cryptic as the data strings they analyze, therefore comments do help even if you wrote the code.

## Repository Use 

* Currently the repository is read-only to the public. 

## Problem Domain
While it is fair to say that programming languages in general have an abstract structure, there is nothing like applying that abstract structure to a particular problem domain and seeing what happens. Afterall, the programming language is a tool to solve a problem. The field of cryptography is arguably an abstract discipline. Rooted in mathematics, we find many of the cryptographic procedures we follow, provided by the experts, requiring only a set of steps to carefully follow. Get them right and all will be fine. No need to understand what is under the hood.

Writing code to solve a problem, unfortunately, requires that there be some understanding of what is under the hood. After completing Set1: Challenge 6, the team decided to begin sharing work with the public. The challenges were found to be carefully constructed, i.e crawl before you walk and so on to build a foundation. The team used that introduction to build out an include file of common routines to reuse. There are a number of features of Python that we explore without getting into the depth object oriented design and programming. As we did a deeper dive into the problem domain we found that it touches on binary arithmetic, rudimentary statistical analysis, the gory details of understanding low level data types in a high level language, and how to convert between various encoding schemes. Really good stuff and cudos for the Cryptopals guys for their great work!

## Links
The following links were visited while working on the code. It is a mixed bag of python coding idioms and crypto math. There is a whole lot of "bit twiddlin'" goin on.

* https://cryptopals.com/sets/1
* https://cryptopals.com/
* https://www.digitalocean.com/community/tutorials/how-to-write-modules-in-python-3
* https://pythonexamples.org/python-bytes/
* https://realpython.com/lessons/operations-bytes-objects/
* https://crypto.stackexchange.com/questions/8845/finding-a-keylength-in-a-repeating-key-xor-cipher
* https://en.wikipedia.org/wiki/Index_of_coincidence
* https://linuxhint.com/hamming-distance-calculation/
* https://www.geeksforgeeks.org/python-program-to-convert-ascii-to-binary/
* https://stackoverflow.com/questions/43207978/python-converting-from-base64-to-binary
* https://stackoverflow.com/questions/14267452/iterate-over-individual-bytes-in-python-3
* https://www.dotnetperls.com/bytes-python
* https://stackoverflow.com/questions/9829578/fast-way-of-counting-non-zero-bits-in-positive-integer
* https://www.geeksforgeeks.org/how-to-convert-int-to-bytes-in-python/
* https://www.geeksforgeeks.org/how-to-convert-bytes-to-string-in-python/
* https://docs.github.com/en/get-started/getting-started-with-git/about-remote-repositories#cloning-with-https-urls
* https://www.dataquest.io/blog/documenting-in-python-with-docstrings/
* https://www.codementor.io/@arpitbhayani/deciphering-single-byte-xor-ciphertext-17mtwlzh30
* https://stackoverflow.com/questions/14267452/iterate-over-individual-bytes-in-python-3
* https://en.wikipedia.org/wiki/Fitting_length
* https://en.wikipedia.org/wiki/Nilpotent
* https://pythonexamples.org/python-split-string-into-specific-length-chunks/
* https://docs.python.org/3/glossary.html#term-bytes-like-object
* https://docs.python.org/3/library/base64.html
* https://www.geeksforgeeks.org/encoding-and-decoding-base64-strings-in-python/
* https://stackabuse.com/encoding-and-decoding-base64-strings-in-python/
* https://en.wikipedia.org/wiki/Base64
* https://www.geeksforgeeks.org/python-split-string-in-groups-of-n-consecutive-characters/
* https://www.geeksforgeeks.org/python-debugger-python-pdb/
* https://docs.python.org/3/library/pdb.html
* https://www.activestate.com/blog/python-debugger-showdown/
* https://learnbyexample.github.io/python-regex-cheatsheet/
* https://stackoverflow.com/questions/5658369/how-to-input-a-regex-in-string-replace
* https://stackoverflow.com/questions/2637592/perl-like-regex-in-python
* https://www.datacamp.com/tutorial/python-data-type-conversion
* https://www.geeksforgeeks.org/count-set-bits-using-python-list-comprehension/
* https://stackoverflow.com/questions/1523465/binary-numbers-in-python
* 

## License 
