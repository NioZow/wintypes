#!/usr/bin/env python3
import pefile
import os
from typing import List, Dict
from sys import argv
import json

def get_exported_functions(dll_path: str) -> List[str]:
    """
    Extract all exported functions from a DLL file using pefile.

    Args:
        dll_path (str): Path to the DLL file

    Returns:
        List[str]: List of exported function names

    Raises:
        FileNotFoundError: If the DLL file doesn't exist
        Exception: If there's an error parsing the DLL
    """
    if not os.path.exists(dll_path):
        raise FileNotFoundError(f"DLL file not found: {dll_path}")

    try:
        #
        # load the DLL
        #
        pe = pefile.PE(dll_path)

        #
        # check if the DLL has an export directory
        #
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []

        #
        # extract function names
        #
        exported_functions = []
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name:
                exported_functions.append(export.name.decode('utf-8'))

        return sorted(exported_functions)

    except Exception as e:
        raise Exception(f"Error parsing DLL: {str(e)}")

    finally:
        if 'pe' in locals():
            pe.close()

def get_dll_exports(dlls: List[str]) -> Dict[str, List[str]]:
    """
    Print all exported functions from a DLL file in a formatted way.

    Args:
        :param dlls: List of DLL files
    """

    exported_functions = {}

    for dll in dlls:
        try:
            name = os.path.splitext(os.path.basename(dll))[0]
            functions = get_exported_functions(dll)

            exported_functions[name] = functions

        except Exception as e:
            print(f"Error: {str(e)}")

    return exported_functions

if __name__ == "__main__":

    if len(argv) < 2:
        print("usage: ./parse_dll_exports.py <dll_path1> <dll_path2> ... <dll_pathn>")
        exit()

    exported_functions = get_dll_exports(argv[1:])
    print(json.dumps(exported_functions, indent=2))