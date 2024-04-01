#ifndef HELPER_HPP
#define HELPER_HPP

#include "json.hpp"
#include "clang/AST/Decl.h"
#include "clang/AST/TemplateName.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <unistd.h>
#include <vector>

class Semaphore {
public:
  Semaphore(int count) : count(count) {}

  inline void notify() {
    std::unique_lock<std::mutex> lock(mtx);
    count++;
    cv.notify_one();
  }

  inline void wait() {
    std::unique_lock<std::mutex> lock(mtx);
    while (count == 0) {
      cv.wait(lock);
    }
    count--;
  }

private:
  std::mutex mtx;
  std::condition_variable cv;
  int count;
};

std::string get_decl_code(const clang::NamedDecl *);
void output_decl(const clang::NamedDecl *decl, std::string output_file_name,
                 bool is_typedef = false, std::string alias_name = "");

#endif
