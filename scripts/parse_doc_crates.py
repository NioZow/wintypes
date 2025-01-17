#!/usr/bin/env python3

import json
import os.path
import re
import subprocess
import sys
import threading
import time
from itertools import chain
from itertools import cycle
from sys import argv
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Self

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

DEFAULT_RUST_TYPES = [
    "bool", "char",
    "i8", "i16", "i32", "i64", "i128", "isize",
    "u8", "u16", "u32", "u64", "u128", "usize",
    "f32", "f64",

    "str", "String",
]


class Spinner:
    def __init__( self ):
        self.spinner = cycle( [ '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏' ] )
        self.busy = False
        self.delay = 0.1

    def spinner_task( self, message ):
        while self.busy:
            sys.stdout.write( f'\r{next( self.spinner )} {message}' )
            sys.stdout.flush()
            time.sleep( self.delay )

    def start( self, message ):
        self.busy = True
        threading.Thread( target = self.spinner_task, args = (message,) ).start()

    def stop( self, message ):
        self.busy = False
        time.sleep( self.delay )

        # clear the line
        sys.stdout.write( '\r\033[K' )
        sys.stdout.flush()

        # print new message
        print( message )


class DocScraper:

    def __init__( self, base_path: str ) -> None:
        options = webdriver.ChromeOptions()
        options.add_argument( '--headless' )

        self.driver = webdriver.Chrome( options = options )
        self.base_path = base_path

        self.docs_path = [
            f"{self.base_path}/winapi/all.html",
            f"{self.base_path}/ntapi/all.html",
        ]

        self.docs = { }
        self.exports: Dict[ str, List[ str ] ] = { }

    def __enter__( self ) -> Self:
        return self

    def __exit__( self, exc_type, exc_val, exc_tb ):
        self.driver.quit()

    def parse_rust_docs( self ):

        for doc_path in self.docs_path:

            self.driver.get( f"file://{doc_path}" )

            docs = { }

            try:
                # wait for content to load
                WebDriverWait( self.driver, 10 ).until(
                    EC.presence_of_element_located( (By.ID, "main-content") )
                )

                # sections to extract (based on the HTML structure shown)
                sections = [
                    "structs",
                    "macros",
                    "functions",
                    "types",
                    "constants",
                    "enums",
                ]

                for section in sections:

                    # find the section header
                    section_items = [ ]

                    try:
                        # find the ul element that follows the h3 with the specific id
                        items_ul = self.driver.find_element( By.CSS_SELECTOR, f'h3[id="{section}"] + ul.all-items' )
                        items = items_ul.find_elements( By.CSS_SELECTOR, 'li' )

                        # extract text from each item
                        for item in items:
                            item_text = item.text.strip()
                            if item_text:
                                section_items.append( item_text )

                    except Exception as e:
                        print( f"Error processing {section}: {e}" )

                    # add to our docs dictionary
                    docs[ section ] = section_items

            except Exception as e:
                raise e

            self.docs[ doc_path.split( "/" )[ -2 ] ] = docs

    def load_docs_from_disk( self, doc_path: str ) -> None:
        with open( doc_path, "r" ) as f:
            self.docs = json.load( f )

    def export_docs_to_disk( self, doc_path: str ) -> None:
        with open( doc_path, "w" ) as f:
            json.dump( self.docs, f )

    def get_function_definition( self, crate: str, function: str ) -> str:

        function_modules = function.split( "::" )[ :-1 ]
        function_name = function.split( "::" )[ -1 ]
        path = f'file://{self.base_path}/{crate}/{"/".join( function_modules )}/fn.{function_name}.html'

        self.driver.get( path )

        WebDriverWait( self.driver, 10 ).until(
            EC.presence_of_element_located( (By.CLASS_NAME, "item-decl") )
        )

        function_def = self.driver.find_element( By.CSS_SELECTOR, "pre.rust.item-decl" )
        definition = function_def.text

        return definition

    def convert_function_definition_to_type( self, fn_definition: str ) -> (str, List[ str ], Optional[ str ]):
        pattern_with_extern = r'pub\s+unsafe\s+extern\s+(?:"system"|"C")\s+fn\s+(\w+)\s*\(([\s\S]*?)\)(?:\s*->\s*(\w+))?'
        pattern_without_extern = r'pub\s+unsafe\s+fn\s+(\w+)\s*\(([\s\S]*?)\)(?:\s*->\s*(\w+))?'

        match = re.match( pattern_with_extern, fn_definition.strip() ) or re.match( pattern_without_extern, fn_definition.strip() )

        if not match:
            raise ValueError( f"Invalid function declaration format: {fn_definition}" )

        fn_name, params_str, return_type = match.groups()
        return_type = return_type if return_type else "()"

        # process parameters
        params = [ ]
        if params_str.strip():
            # handle pointer types and more complex type declarations
            param_pattern = r'(\w+)\s*:\s*((?:\*mut\s+|\*const\s+)?\w+(?:::\w+)*)'
            param_matches = re.findall( param_pattern, params_str )
            params = [ param_type for _, param_type in param_matches ]

        # construct the type declaration - always use system for windows API
        # some windows are declared with extern "C" using extern "system" shouldn't cause problems
        # however leaving this as a comment if I find myself troubleshooting weird stuff someday
        params_joined = ", ".join( params )
        type_declaration = f'pub type Fn{fn_name} = unsafe extern "system" fn({params_joined}) -> {return_type};'

        # get the path of params
        params_path = [ ]
        for param in params:

            if param in DEFAULT_RUST_TYPES:
                continue

            if (param.startswith( '*mut ' ) or param.startswith( '*const ' )) and param.count( ' ' ) == 1:
                param = param.split( " " )[ 1 ]

            param_path = self.get_parameter_import_path( param )
            if param_path is not None:
                params_path.append( param_path )
            else:
                raise Exception( f"Did not found path of {param}" )

        return_type_path = None
        if return_type != "()":
            return_type_path = self.get_parameter_import_path( return_type )
            if return_type_path is None:
                raise Exception( f"Did not found path of return type {return_type}" )

        return type_declaration, params_path, return_type_path

    @staticmethod
    def get_import_lines( dependencies: dict, parents: Optional[ List[ str ] ] = None ) -> Iterator[ str ]:
        if parents is None:
            parents = [ ]

        for dependency in dependencies:
            if isinstance( dependencies[ dependency ], dict ):
                parents.append( dependency )
                yield from DocScraper.get_import_lines( dependencies[ dependency ], parents = parents )
                parents.pop()
            elif isinstance( dependencies[ dependency ], set ) and dependency == "wintypes":
                yield f"use {'::'.join( parents )}::{{{', '.join( dependencies[ dependency ] )}}};"
            else:
                raise Exception( f"unintended path: {dependency} of type {type( dependencies[ dependency ] )}" )

    @staticmethod
    def upgrade_tree_imports( tree: dict, branches: List[ str ] ):
        """
        create a tree view of imports. Directly modifies the tree passed a parameter.
        """
        if len( branches ) == 1:
            type_name = branches[ 0 ]

            # last branch just append to array or create the array and append
            if tree.get( "wintypes" ) is None:
                tree[ "wintypes" ] = set()

            if type_name not in tree[ "wintypes" ]:
                tree[ "wintypes" ].add( type_name )
        else:
            branch = branches[ 0 ]
            if tree.get( branch ) is None:
                tree[ branch ] = { }

            DocScraper.upgrade_tree_imports( tree = tree[ branch ], branches = branches[ 1: ] )

    def generate_lib_rs( self, dlls: List[ str ] ):
        with open( "src/lib.rs", "w" ) as f:
            f.writelines( f'#[cfg(feature = "{dll}")]\npub mod {dll};\n\n' for dll in dlls )

    def generate_cargo_features( self ) -> str:
        text = "[features]\n"
        for dll in self.exports:
            text += f'{dll} = []\n'
        return text

    def filter_export( self, export: str, tree: dict, defs: set ) -> None:

        # loop through the winapi and ntapi crates functions
        for crate in self.docs:

            for func in self.docs[ crate ][ "functions" ]:

                func_name = func.split( "::" )[ -1 ]

                # check if the dll exported func is the one we're seeing from the crate doc
                if func_name == export:
                    # extract the crate function definition
                    fn_definition = self.get_function_definition( crate, func )

                    # convert the crate function definition to a type definition
                    # and get the dependencies in a tree structure
                    type_definition, params, return_type = self.convert_function_definition_to_type( fn_definition )

                    for param in params:
                        DocScraper.upgrade_tree_imports( tree, param.split( "::" ) )

                    if return_type is not None:
                        DocScraper.upgrade_tree_imports( tree, return_type.split( "::" ) )

                    defs.add( type_definition )
                    return

    def filter_exports( self, export_path: str ) -> None:

        with open( export_path ) as f:
            exports = json.load( f )

        self.exports = exports

        # iterate through all dlls
        # cuz i want to sort my crate by dll
        for dll in exports:

            tree = { }
            defs = set()

            # iterate through all dll exported functions
            for export in exports[ dll ]:
                self.filter_export( export, tree, defs )

            with open( f"src/{dll}.rs", "w" ) as f:
                # write the imports
                f.writelines( f"{line}\n" for line in DocScraper.get_import_lines( tree ) )

                f.write( "\n\n" )

                # write the types
                f.writelines( f"{type}\n" for type in sorted( defs ) )

        self.generate_lib_rs( list( exports.keys() ) )

    def get_parameter_import_path( self, parameter: str ) -> Optional[ str ]:
        # loop through the winapi and ntapi crates
        for crate in self.docs:

            docs = self.docs[ crate ]

            # loop through all of the types from the crate
            for type in chain( docs[ "types" ], docs[ "structs" ], docs[ "enums" ] ):

                # check if the type matches
                type_name = type.split( "::" )[ -1 ]

                if parameter == type_name:
                    return f"{crate}::{type}"

        return None


if __name__ == "__main__":

    if len( argv ) < 2:
        print( "usage: ./parse_doc_crates.py <exports.json>" )
        exit()

    with open( argv[ 1 ], "r" ) as f:
        exports = json.load( f )

    spinner = Spinner()
    spinner.start( "Running `cargo doc`..." )

    #
    # run cargo doc
    #
    result = subprocess.run( [ 'cargo', 'doc' ], capture_output = True, text = True )
    if result.returncode != 0:
        print( result.stderr )
        exit()

    spinner.stop( "Doc was exported!" )

    t1 = time.time()

    with DocScraper( os.path.abspath( "./target/x86_64-pc-windows-gnu/doc" ) ) as scraper:
        spinner.start( "Parsing rust docs..." )
        scraper.parse_rust_docs()
        spinner.stop( "Parsed rust docs..." )

        spinner.start( "Parsing dll exports..." )
        scraper.filter_exports( argv[ 1 ] )
        spinner.stop( "Parsed dll exports..." )

        print( "Add this to your Cargo.toml:", scraper.generate_cargo_features(), sep = "\n\n" )

    t2 = time.time()
    print( f"Done in {round( t2 - t1, 2 )} seconds" )
