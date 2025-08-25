# KernelGPT: Enhanced Kernel Fuzzing via Large Language Models

<p align="left">
    <a href="https://arxiv.org/abs/2401.00563"><img src="https://img.shields.io/badge/arXiv-2401.00563-b31b1b.svg?style=for-the-badge">
</p>

**KernelGPT** is a novel approach that leverages Large Language Models (LLMs) to automatically infer and refine [Syzkaller](https://github.com/google/syzkaller) specifications, significantly enhancing Linux kernel fuzzing capabilities.

> [!IMPORTANT]
> We are keeping improving the documents and adding more implementation details. Please stay tuned at [README-DEV.md](README-DEV.md) for more information.

**Contact:** [Chenyuan Yang](https://yangchenyuan.github.io/), [Zijie Zhao](https://zijie.cs.illinois.edu/), [Lingming Zhang](https://lingming.cs.illinois.edu).

## ✨ Key Features & Achievements
  * **Automated Specification Inference:** Uses LLMs to generate Syzkaller specifications from kernel source code analysis.
  * **Iterative Refinement:** Employs validation feedback to automatically repair and improve generated specifications.
  * **Proven Effectiveness:**
      * Detected **24 new bugs** 🐛 in the Linux kernel.
      * **11 bugs assigned CVEs**❗ (12 fixed so far).
      * Numerous KernelGPT-generated specifications have been merged into the official Syzkaller repository.

## ⚙️ Prerequisites

Before you begin, ensure you have the following installed and configured:

1.  **Python:** \>= 3.8 (Check `requirements.txt` for specific library versions).
2.  **Git & Git Submodules:** To clone the repository and its dependencies.
3.  **Build Tools:** `make`, a C compiler (like `gcc` for host tools), `bear`.
    ```bash
    sudo apt-get update && sudo apt-get install build-essential make bear git
    ```
4.  **Clang:** Version 14 is required for the analysis tools.
    ```bash
    # Example for Debian/Ubuntu
    sudo apt-get install clang-14 libclang-14-dev
    # Ensure clang-14 is the default or adjust paths in subsequent steps
    # Example: export CC=clang-14 CXX=clang++-14
    ```
    See the [analyzer README](https://www.google.com/search?q=spec-gen/analyzer/README.md) for more details.
5.  **Syzkaller:** A working Syzkaller setup targeting the Linux kernel. Follow the official [Syzkaller setup guide](https://github.com/google/syzkaller/blob/master/docs/linux/setup.md). You'll need this for specification validation and fuzzing.
6.  **Linux Kernel Source:** You need a local copy of the Linux kernel source code that you intend to analyze.

## 🛠️ Installation

1.  **Clone the Repository:**

    ```bash
    # Replace with your actual repository URL if it's hosted elsewhere
    git clone https://github.com/KernelGPT/KernelGPT.git
    cd KernelGPT
    ```

2.  **Initialize Submodules (Linux & Syzkaller):**

    ```bash
    git submodule update --init --recursive
    ```

    *This will clone the specific Linux kernel version used in the paper and Syzkaller into the `linux/` and `syzkaller/` subdirectories.*

3.  **Install Python Dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Prepare Syzkaller Image (Optional but Recommended):**
    Follow the instructions in `image/` to create a suitable VM image for fuzzing.

    ```bash
    cd image
    # Modify create-image.sh if needed (e.g., target architecture)
    bash create-image.sh
    cd ..
    ```

## 🚀 Usage

The core workflow involves analyzing the kernel source, generating specifications using the LLM, and then validating/refining them.

### Step 1: Kernel Preparation & Static Analysis

This step analyzes the Linux kernel source code to extract information needed by the LLM.

1.  **Navigate to the Linux Submodule:**

    ```bash
    cd linux
    ```

2.  **Configure the Kernel:** `allyesconfig` is recommended for broad analysis coverage.

    ```bash
    # Recommended: Use the commit tested in the paper (d2f51b35)
    # git checkout d2f51b35 # Or your desired commit/tag

    # Apply patch if using commit d2f51b35 (see details below)
    # patch -p1 < ../spec-eval/linux-d2f51b35.patch

    # Ensure clang-14 is used (e.g., export CC=clang-14 HOSTCC=clang)
    make CC=clang HOSTCC=clang allyesconfig
    ```

3.  **Build the Kernel with `bear`:** This intercepts compiler calls to generate `compile_commands.json`.

    ```bash
    # Ensure clang-14 is used (e.g., export CC=clang-14 HOSTCC=clang)
    bear -- make CC=clang HOSTCC=clang -j$(nproc)
    ```

    *This command generates `compile_commands.json` in the `linux/` directory.*

    <details>
    <summary>⚠️ Potential Build Issues (Linux `d2f51b35`)</summary>

    The specific Linux kernel commit `d2f51b35` used in the paper may have compilation errors with `allyesconfig`. Apply the provided patch *before* building:

    ```bash
    # Run from the linux/ subdirectory
    patch -p1 < ../spec-eval/linux-d2f51b35.patch
    ```

    The patch fixes minor issues in `net/ipv4/tcp_output.c` and `sound/soc/codecs/aw88399.c`.

    </details>

4.  **Build Analysis Tools:**

    ```bash
    cd ../spec-gen/analyzer
    # Ensure Clang-14 dev libraries are installed and accessible
    make all
    ```

    *This creates `analyze` and `usage` executables.*

5.  **Run Analysis & Processing:**

    ```bash
    # Ensure you are in spec-gen/analyzer/
    # Analyze structures, functions, enums, etc.
    ./analyze -p ../../linux/compile_commands.json

    # Process the analyzer output
    python process_output.py --linux-path ../../linux

    # Analyze usage patterns
    ./usage -p ../../linux/compile_commands.json

    # Process the usage output
    python process_output.py --linux-path ../../linux --usage
    ```

    *This generates several `processed_*.json` files in `spec-gen/analyzer/`, which serve as input for the LLM.*

### Step 2: Generate Specifications with KernelGPT

1.  **Set OpenAI API Key:**
    Create a file named `openai.key` in the `spec-gen/` directory and place your OpenAI API key inside it.

    ```bash
    echo "YOUR_API_KEY_HERE" > spec-gen/openai.key
    ```

2.  **Run Specification Generation:**

    ```bash
    # Ensure you are in the spec-gen/ directory
    # Generate N specifications (e.g., 1 for a quick test)
    # Input: processed_handlers.json from the analysis step
    # Output: JSON specifications in spec-output/
    python gen_spec.py -d analyzer/processed_handlers.json -o spec-output -n 1

    # For full-scale generation (might take time and cost $$)
    # python gen_spec.py -d analyzer/processed_handlers.json -o spec-output -n 1000
    ```

### Step 3: Validate and Repair Specifications

This step uses Syzkaller's tools (`syz-check`) to validate the generated specifications and feeds back errors to the LLM for repair (if enabled).

1.  **Run Evaluation Script:**
    ```bash
    # Ensure you are in the spec-gen/ directory
    # Input: Generated specs from spec-output/_generated
    # Output: Validation results and potentially repaired specs in eval-output/
    python eval_spec.py -u -s spec-output/_generated --output-name debug -o eval-output
    cd .. # Back to KernelGPT root
    ```
    *This script invokes `spec-eval/run-specs.py` internally. Check the script and `eval-output/` for detailed logs and results.*

## Reuse the Generated Specifications

If you want to reuse our generated specifications for drivers (or sockets), you could use `eval_spec.py`:

```bash
# Under the directory `spec-gen`
python eval_spec.py -u -s ../generated-specs/specs-6.7/correct-driver-spec --output-name debug -o eval-output --merge
```
This command will translate all specification written in `json` to `syzkaller` format and run the syzkaller.
The log for this process is `spec-eval/debug/merged.log`.

Then, all the textural specifications will be under `spec-eval/debug/default-tmp/syzkaller/sys/linux` directory, with `gpt4_`as the prefix.

## 📝 Citation

```bibtex
@inproceedings{kernelgpt,
    author = {Yang, Chenyuan and Zhao, Zijie and Zhang, Lingming},
    title = {KernelGPT: Enhanced Kernel Fuzzing via Large Language Models},
    year = {2025},
    isbn = {9798400710797},
    publisher = {Association for Computing Machinery},
    address = {New York, NY, USA},
    url = {https://doi.org/10.1145/3676641.3716022},
    doi = {10.1145/3676641.3716022},
    pages = {560–573},
    numpages = {14},
    location = {Rotterdam, Netherlands},
    series = {ASPLOS '25}
}
```
