# Installation
1. `wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py`
2. `python install.py --deps --tool --ot`
    1. You can use `--ot=[release]` to install a particular branch or release
    2. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
    3. No sudo? Change [`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/v2.8.8/cmake.html#variable%3aCMAKE_INSTALL_PREFIX).

## Test

* If you want to test the code in local machine, type

   `./run ./bin/[binaries] 12345 [more opts]`
* IF you want to test the code over two machine, type

  `./bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP addresses are hardcoded in the test files.

* example_semi_honest should run as 
	`./bin/example 1 12345 123 & ./bin/example 2 12345 124`
	
	because different parties need different numbers
