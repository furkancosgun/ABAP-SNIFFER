# ABAP Sniffer (Code Scanner)

**ABAP Sniffer** is an ABAP-based tool for scanning various SAP program objects (such as reports, function groups, classes, interfaces, enhancements, etc.) to find occurrences of specific patterns in the code.

## Features

-   **Search Across Multiple Object Types:** The tool can search through reports, function groups, classes, interfaces, enhancements, and more.
-   **Pattern Matching:** Supports both plain text and regular expression search.

## Usage

To use **ABAP Sniffer**, follow these steps:

1. **Run the Program**  
   - Execute the program **ZABAP_P_SNIFFER** from transaction `SE38`.

2. **Configure Search Parameters**  
   - Specify the required search parameters in the selection screen:
     - **Pattern:** Enter the text or regular expression to search for in the source code.
     - **Program Type & Name:** Filter the search by report type or name.
     - **Package:** Restrict the search to specific SAP packages.
     - **Function/Function Group:** Limit the search to specific function groups or function names.
     - **Class/Interface:** Search within specific classes or interfaces.
     - **Enhancement:** Include specific enhancement points in the search.
     - **With Modifications:** Optionally include modifications made to standard objects.

3. **Execute the Search**  
   - Press the **Execute** button to start the scanning process.

4. **View Results**  
   - The results will be displayed in a hierarchical ALV table. Use the links to navigate directly to the relevant source code lines.

## Installation

You can install ABAP Sniffer using one of the following methods:
### 1. Using ABAPGit

-  Install **ABAPGit** in your SAP system if it's not already installed.
-  Open the **ABAPGit** application in your system.
-  Clone the repository URL of this project into **ABAPGit**.
-  Pull the code into your system. **ABAPGit** will automatically create the necessary objects in your package.

### 2. Manual Installation

-  Copy the main program **[ZABAP_P_SNIFFER](src/zabap_p_sniffer.prog.abap)** and its associated objects.
-  Go to transaction **SE38** in your SAP system.
-  Create a new program named **ZABAP_P_SNIFFER**.
-  Paste the code into the editor and activate it.

## License

This tool is released under the **MIT License**. See the [LICENSE](LICENSE) file for more details.
