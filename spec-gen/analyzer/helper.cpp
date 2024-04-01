#include "helper.hpp"

using namespace clang;
using namespace clang::tooling;
using json = nlohmann::json;

std::mutex mutex;
std::set<std::string> existing_filenames;

std::string get_decl_code(const NamedDecl *decl) {
  SourceManager &srcMgr = decl->getASTContext().getSourceManager();
  SourceLocation startLoc = decl->getBeginLoc();
  SourceLocation endLoc = decl->getEndLoc();

  if (!startLoc.isInvalid() && !endLoc.isInvalid()) {
    // Convert the source locations to file locations
    startLoc = srcMgr.getSpellingLoc(startLoc);
    endLoc = srcMgr.getSpellingLoc(endLoc);

    // Get file path and line number
    std::string filePath = srcMgr.getFilename(startLoc).str();
    unsigned int lineNumber = srcMgr.getSpellingLineNumber(startLoc);

    // Extract the source code text
    bool invalid = false;
    StringRef text =
        Lexer::getSourceText(CharSourceRange::getTokenRange(startLoc, endLoc),
                             srcMgr, LangOptions(), &invalid);

    if (!invalid) {
      std::string sourceCode = text.str();
      // Now you have filePath, lineNumber, and sourceCode
      // Store or process them as needed
      return sourceCode;
    }
  }
  return "";
}

void output_decl(const NamedDecl *decl, std::string output_file_name,
                 bool is_typedef, std::string alias_name) {
  // Add a lock
  std::lock_guard<std::mutex> lock(mutex);

  auto name = decl->getNameAsString();
  std::string sourceCode = get_decl_code(decl);

  std::ofstream output_file;
  output_file.open(output_file_name, std::ios_base::app);
  json j;
  j["name"] = name;
  j["source"] = sourceCode;

  // Get the SourceLocation for the beginning of the declaration
  SourceLocation beginLoc = decl->getBeginLoc();

  // Retrieve the SourceManager from the AST context
  SourceManager &sourceManager = decl->getASTContext().getSourceManager();

  std::stringstream filenameWithLine;
  if (const FileEntry *fileEntry =
          sourceManager.getFileEntryForID(sourceManager.getFileID(beginLoc))) {
    filenameWithLine << fileEntry->tryGetRealPathName().str();
  } else {
    filenameWithLine << decl->getBeginLoc().printToString(
        decl->getASTContext().getSourceManager());
  }
  // Append line number
  unsigned lineNumber = sourceManager.getSpellingLineNumber(beginLoc);
  filenameWithLine << ":" << lineNumber;

  std::string filename = filenameWithLine.str();
  std::string key_name =
      filename + "+" + name + "+" + output_file_name + "+" + alias_name;
  if (existing_filenames.find(key_name) == existing_filenames.end()) {
    existing_filenames.insert(key_name);
  } else {
    return;
  }
  j["filename"] = filename;

  if (is_typedef) {
    j["alias"] = alias_name;
  }

  auto json_str = j.dump();
  output_file << json_str << std::endl;
  output_file.flush();
  output_file.close();
}