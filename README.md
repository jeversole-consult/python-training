## Background

This Python Training site was created to document and share a family project undertaken by a father and son team to explore a different approach to learning a new programming language. The language of choice is Python which was selected for a number of reasons including, popularity in the software development community, object oriented architecture, interpreted scripting language, online documentation, and ease of access to install and execute. 

The next challenge is an approach to learning this new programming language Python. The pool of Python documentation on the internet combined with published texts is deep and wide. A traditional academic programming language course might follow a textbook of some type designed to give an overall view of the Python language using primarily abstract exercises. A lab execution environment is a requirement, but, well within reach of any home computing environment today. We can easily get a Python installation up on a Windows, Mac, Linux desktop, or virtual machine on a cloud installation like AWS. Armed with all the tools what problem do we want to use.

The team chose to use cryptography to learn something about Python. The brutal reality is the team would need to learn a bit about both. The problem domain is documented on the [Cryptopals.com](https://cryptopals.com.com) website. The Cryptopals guys recommend getting your hands dirty with some code, therefore, the team is going to do just that with a language unknown to the team, Python. In this way we look at how a particular programming language can be used to solve problems, and maybe how to learn a programming language.

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

* The structure of this repo is based on the problem sets with python scripts named after the specific challenges.
* After working through the challenges a file of reusable functions was developed to illustrate a simple example of how to write and use functions in python. 
* Examples of how to document source code are embedded in the code files. The minimal standard is to at least provide the original author of the code memory of why a piece of code was written the way it was. This is particularly helpful when using language specific idioms. This particular problem domain lends itself to idioms that are most concise and useful, but cryptic as the data strings they analyze so comments do help even if you wrote the code.

## Repository Use 

* Currently the repository is read-only to the public. 

## Problem Domain
While it is fair to say that programming languages in general have an abstract structure, there is nothing like applying that abstract structure to a particular problem domain and seeing what happens. Afterall, the programming language is a tool to solve a problem. The field of cryptography is arguably an abstract discipline. Rooted in mathematics, we find many of the cryptographic procedures we follow, provided by the experts, to require only a set of steps to carefully follow. Get them right and all will be fine. No need to understand what is under the hood.

Writing code to solve a problem, unfortunately, requires that there be some understanding of what is under the hood. After completing Set1: Challenge 6 the team decided to share work with the public. The challenges were found to be carefully constructed to crawl before you walk and so on to build a foundation. The team used that introduction to build out a rudimentary include file of routines that are reused. A bit of warning is in order. The problem domain involves binary arithmetic, rudimentary statistical analysis, the gory details of understanding low level data types in a high level language, and how to convert between various encoding schemes. Really good stuff and cudos for the Cryptopals guys for their great work!



## License 


