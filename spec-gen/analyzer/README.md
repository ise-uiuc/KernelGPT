## Kernel Analyze Script

This scripts requires LLVM and Clang libraries to be installed. The script is used to analyze the kernel code to collect the information about the file operation handler, functions, types, and usage information.

```bash
make all # This will generate the kernel analyze script `analyze` and `usage`
```

More specifically, we need the following Clang libraries:

```makefile
CLANG_LIBS := -lclangTooling -lclangFrontend -lclangDriver -lclangSerialization \
             -lclangParse -lclangSema -lclangAnalysis -lclangAST -lclangBasic \
             -lclangEdit -lclangLex -lclangASTMatchers \
						 -lclangRewrite
```

For more information, please refer to the [Makefile](Makefile).


### Prerequisites

```bash
sudo apt-get install clang-14 libclang-dev-14
```