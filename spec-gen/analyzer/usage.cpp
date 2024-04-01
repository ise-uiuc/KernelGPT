#include "helper.hpp"

using namespace clang;
using namespace clang::tooling;
using json = nlohmann::json;

std::set<std::string> handler_names;

bool ProcessParents(const clang::DynTypedNode &Node, ASTContext *context,
                    std::string referred_name) {
  auto parents = context->getParents(Node);
  if (parents.empty()) {
    return false; // Reached the root or a node with no parents
  }

  for (const auto &parent : parents) {
    if (auto *FD = parent.get<FunctionDecl>()) {
      // Try cast the FunctionDecl to a NamedDecl
      if (auto *ND = dyn_cast<NamedDecl>(FD)) {
        output_decl(ND, "usage.jsonl", true, referred_name);
        return true;
      }
    } else if (const auto *VD = parent.get<VarDecl>()) {
      output_decl(VD, "usage.jsonl", true, referred_name);
      return true;
    } else {
      // Recurse to process the parents of this parent
      if (ProcessParents(parent, context, referred_name)) {
        return true;
      }
    }
  }
  return false;
}

bool is_handler_name(std::string name) {
  // Check whether the name is in the handler names
  if (handler_names.find(name) != handler_names.end()) {
    return true;
  }
  return false;
}

class StructVisitor : public RecursiveASTVisitor<StructVisitor> {
public:
  explicit StructVisitor(ASTContext *context, bool collect_enum = false,
                         bool collect_struct = false, bool collect_func = false,
                         bool collect_handler = false)
      : context(context), collect_enum(collect_enum),
        collect_struct(collect_struct), collect_func(collect_func),
        collect_handler(collect_handler) {}

  bool VisitDeclRefExpr(DeclRefExpr *expr) {
    std::string name = expr->getNameInfo().getAsString();
    if (is_handler_name(name)) {
      ProcessParents(clang::DynTypedNode::create(*expr), context, name);
    }
    return true;
  }

private:
  ASTContext *context;
  bool collect_enum;
  bool collect_struct;
  bool collect_func;
  bool collect_handler;
};

class StructConsumer : public clang::ASTConsumer {
public:
  explicit StructConsumer(ASTContext *context, bool collect_enum = true,
                          bool collect_struct = true, bool collect_func = true,
                          bool collect_handler = false)
      : visitor(context, collect_enum, collect_struct, collect_func,
                collect_handler) {}

  void HandleTranslationUnit(clang::ASTContext &context) override {
    visitor.TraverseDecl(context.getTranslationUnitDecl());
  }

private:
  StructVisitor visitor;
};

class StructAction : public clang::ASTFrontendAction {
public:
  std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &compiler,
                    llvm::StringRef) override {
    return std::make_unique<StructConsumer>(&compiler.getASTContext());
  }
};

int main(int argc, const char **argv) {
  llvm::cl::OptionCategory MyToolCategory("my-tool options");
  llvm::cl::opt<std::string> OptCompileCommands(
      "p", llvm::cl::desc("Specify path compile_commands.json"),
      llvm::cl::Required, llvm::cl::cat(MyToolCategory));
  llvm::cl::ParseCommandLineOptions(argc, argv);

  // Load compile_commands.json manually
  std::string ErrorMessage;
  auto CompilationDatabase = JSONCompilationDatabase::loadFromFile(
      OptCompileCommands, ErrorMessage,
      clang::tooling::JSONCommandLineSyntax::AutoDetect);

  if (!CompilationDatabase) {
    llvm::errs() << "Error loading compile_commands.json: " << ErrorMessage
                 << "\n";
    return 1;
  }

  // Extract source files from the loaded database
  std::vector<std::string> sources;
  for (const auto &command : CompilationDatabase->getAllCompileCommands()) {
    // Only add .c and .h files
    if (command.Filename.find(".c") == std::string::npos &&
        command.Filename.find(".h") == std::string::npos)
      continue;
    sources.push_back(command.Filename);
  }

  // Load the handler names
  std::ifstream handler_file("handler_names.txt");
  std::string line;
  while (std::getline(handler_file, line)) {
    handler_names.insert(line);
  }
  std::cout << "Loaded " << handler_names.size() << " handler names"
            << std::endl;

  auto frontendAction = newFrontendActionFactory<StructAction>();
  std::vector<std::future<void>> futures;
  int maxThreads = 100;
  Semaphore sem(maxThreads);
  // Assuming 'sources' is a vector of strings containing source paths
  for (const auto &sourcePath : sources) {
    sem.wait(); // Wait for an available slot

    // Capture necessary variables by reference
    futures.push_back(
        std::async(std::launch::async, [&sem, &sourcePath, &CompilationDatabase,
                                        &frontendAction]() {
          std::cout << sourcePath << std::endl;

          // Processing logic with ClangTool
          std::vector<std::string> currentSource = {sourcePath};
          ClangTool tool(*CompilationDatabase, currentSource);
          tool.run(frontendAction.get());

          sem.notify(); // Signal that this thread is done
        }));
  }

  for (auto &fut : futures) {
    fut.wait();
  }
}