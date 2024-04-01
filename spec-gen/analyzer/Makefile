# Variables
LLVM_INCLUDE := $(shell llvm-config-14 --includedir)
LLVM_FLAGS := $(shell llvm-config-14 --cxxflags --ldflags --libs core)
CLANG_LIBS := -lclangTooling -lclangFrontend -lclangDriver -lclangSerialization \
             -lclangParse -lclangSema -lclangAnalysis -lclangAST -lclangBasic \
             -lclangEdit -lclangLex -lclangASTMatchers \
						 -lclangRewrite
CXXFLAGS := --std=c++17 -pthread
LOG_FILE := analyze-compile.log

# Object files
OBJ_FILES=helper.o

# Default target
all: analyze usage

analyze: analyze.cpp $(OBJ_FILES)
	@clang++ $^ -o $@ -I$(LLVM_INCLUDE) $(LLVM_FLAGS) $(CLANG_LIBS) $(CXXFLAGS) 2>&1 | tee $(LOG_FILE)

usage: usage.cpp $(OBJ_FILES)
	@clang++ $^ -o $@ -I$(LLVM_INCLUDE) $(LLVM_FLAGS) $(CLANG_LIBS) $(CXXFLAGS) 2>&1 | tee $(LOG_FILE)

# Compiling helper.cpp to an object file
helper.o: helper.cpp helper.hpp
	@$(CXX) -c $< -o $@ -I$(LLVM_INCLUDE) $(LLVM_FLAGS) $(CLANG_LIBS) $(CXXFLAGS) 2>&1  | tee -a $(LOG_FILE)

clean:
	@rm -f analyze usage $(LOG_FILE)

.PHONY: all clean