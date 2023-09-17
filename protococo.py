#!/usr/bin/env python3
"""protococo.

Usage:
  protococo check  <message_name> [<message_hex_string> ...]
                      [--cocofile=<file> --format=<option>] 
                      [--verbose --decode --decode-no-newlines]
  protococo find   [<message_hex_string> ...]
                      [--cocofile=<file> --format=<option>]
                      [--dissect | --dissect-fields=<comma_separated_fields>]
                      [--list --verbose --decode --decode-no-newlines --long-names]
  protococo create (<message_name> | --from-json=<json_file>)
                      [--cocofile=<file>]
  protococo json-recipe <message_names> ...
                      [--cocofile=<file>]
  protococo tree   [--cocofile=<file>]

Options:
  -h --help                 Show this screen.
  --version                 Show version.
  --cocofile=<file>         Specify the protococo rules file [default: default.coco].
  --verbose                 Enable verbose output.
  --format=<option>         Print message disection in different formats [default: compact].
                                Options: oneline, multiline, compact.
  --dissect                 Include message field dissection in find results.
  --decode                  Decodes fields with encodedas parameters in message dissection
  --decode-no-newlines      Replaces new lines in decoded fields of message dissections with \'\\n\' for a more compact output
  --long-names              Prints the full mangled message names if a name mangling preprocess has been made during cocofile parsing
  --list                    Include a list of the most fitting messages in find results.
  
"""

__version__ = "0.2.0"

from pprint import *
from collections import OrderedDict
import re
import os
import sys
import json
import copy
from docopt import docopt
from parser import *
from analyzer import *


class AnsiColors:
    PURPLE = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKCYAN = '\033[96m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    FAIL2 = '\033[38;5;196m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    UNDERLINE_OFF = '\033[24m'
    
def get_message_explanation_string_compact(validation_result, filter_fields = None, decode=False, no_newlines=False):
    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result
    
    result_string = ""
    odd = 0
    for k, v in validation_result_dict.items():
        if filter_fields is not None and k not in filter_fields:
            continue
        
        odd ^= 1
        
        field_complies = validation_diff_dict[k]
        
        k_adj, v_adj = k, v
        
        if decode == True and k in validation_decoded_dict.keys():
            v_adj = validation_decoded_dict[k]
        
        fail_color = AnsiColors.FAIL if odd == 1 else AnsiColors.FAIL2
        ok_color = AnsiColors.OKGREEN if odd == 1 else AnsiColors.OKCYAN
        if not field_complies:
            color = fail_color
        else:
            color = ok_color
        
        v_adj = AnsiColors.BOLD + color + v_adj + AnsiColors.ENDC
            
        if decode == True and k in validation_decoded_dict.keys():
            if no_newlines:
                v_adj = f"({v_adj})".replace("\r", "").replace("\n", f"{AnsiColors.PURPLE}\\n{AnsiColors.UNDERLINE_OFF + AnsiColors.BOLD + color}")
            else:
                v_adj = f"({v_adj})"
            
        if k_adj is not None:
            result_string += f"{v_adj}"
        else:   # Overflowing bytes field
            result_string += f"|+{v_adj}"
    

    
    return result_string

def get_message_explanation_string_oneline(validation_result, filter_fields = None, decode=False, no_newlines=False):
    
    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result
    
    fail_color = AnsiColors.FAIL
    ok_color = AnsiColors.OKGREEN

    result_string = ""
    for k, v in validation_result_dict.items():
        if filter_fields is not None and k not in filter_fields:
            continue
        
        field_complies = validation_diff_dict[k]
        
        k_adj, v_adj = k, v
        
        if decode == True and k in validation_decoded_dict.keys():
            v_adj = validation_decoded_dict[k]
        
        if not field_complies:
            color = fail_color
        else:
            color = ok_color
        
        v_adj = AnsiColors.BOLD + color + v_adj + AnsiColors.ENDC
            
        if decode == True and k in validation_decoded_dict.keys():
            if no_newlines:
                v_adj = f"({v_adj})".replace("\r", "").replace("\n", f"{AnsiColors.PURPLE}\\n{AnsiColors.UNDERLINE_OFF + AnsiColors.BOLD + color}")
            else:
                v_adj = f"({v_adj})"
            
        if k_adj is not None:
            k_adj = AnsiColors.BOLD + k_adj + AnsiColors.ENDC
            result_string += f"|{k_adj}: {v_adj}"
        else:   # Overflowing bytes field
            result_string += f"|+{v_adj}"
    
    if len(result_string) > 0:
        result_string += "|"
    
    return result_string

def get_message_explanation_string_multiline(validation_result, filter_fields = None, decode=False, no_newlines=False):
    
    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result
    
    fail_color = AnsiColors.FAIL
    ok_color = AnsiColors.OKGREEN

    result_string_field_names = ""
    result_string_field_values = ""
    for k, v in validation_result_dict.items():
        if filter_fields is not None and k not in filter_fields:
            continue
        
        field_complies = validation_diff_dict[k]
        
        k_adj, v_adj = k, v
        
        if decode == True and k in validation_decoded_dict.keys():
            v_adj = validation_decoded_dict[k]
        
        if k_adj is None:
            k_adj = "+"
            v_adj = "+" + v
        
        lendiff = len(k_adj) - len(v_adj)

        if decode == True and k in validation_decoded_dict.keys():
            lendiff-=2  #To compensate the fact that we are adding 2 parenthesis
            if no_newlines:
                v_adj = f"({v_adj})".replace("\r", "").replace("\n", f"{AnsiColors.PURPLE}\\n{AnsiColors.UNDERLINE_OFF + AnsiColors.BOLD + color}")
            else:
                v_adj = f"({v_adj})"
        
        if not field_complies:
            color = fail_color
        else:
            color = ok_color
        
        v_adj = AnsiColors.BOLD + color + v_adj + AnsiColors.ENDC
            
        if lendiff < 0:
            prefix = " " * ((-lendiff)//2)
            suffix = " " * ((-lendiff)//2 + (-lendiff)%2)
            k_adj = prefix + k_adj + suffix
            #k_adj += " " * (-lendiff)
        elif lendiff > 0:
            prefix = " " * (lendiff//2)
            suffix = " " * (lendiff//2 + (-lendiff)%2)
            v_adj = prefix + v_adj + suffix
            #v_adj += " " * lendiff
        k_adj = "|" + k_adj
        v_adj = "|" + v_adj
        
        result_string_field_names += k_adj
        result_string_field_values += v_adj
    
    if len(result_string_field_names) >0:
        result_string_field_names += "|"
        result_string_field_values += "|"
    
    return result_string_field_names + "\n" + result_string_field_values

def get_message_explanation_string(validation_result, validation_log_dict = None, fmt="oneline", filter_fields = None, decode = False, no_newlines=False):
    
    _, validation_result_dict, validation_diff_dict, __, ___ = validation_result
    
    if fmt == "oneline":
        result_string = get_message_explanation_string_oneline(validation_result, filter_fields, decode=decode, no_newlines=no_newlines)
    elif fmt == "compact":
        result_string = get_message_explanation_string_compact(validation_result, filter_fields, decode=decode, no_newlines=no_newlines)
    else:
        result_string = get_message_explanation_string_multiline(validation_result, filter_fields, decode=decode, no_newlines=no_newlines)

    logs_string = ""
    if validation_log_dict is not None and len(validation_log_dict) > 0:
        for field_name, log_message_list in validation_log_dict.items():
            logs_string += f"- {field_name}:\n"
                        
            #print([f"    - {log_message}" for log_message in log message_list])
            logs_string += "\n".join([f"    - {log_message}" for log_message in log_message_list])
            logs_string += "\n"
    
    return logs_string + result_string

def find_message_rules(message_name, cocodoc):
    for message_rules in cocodoc.all_messages_rules_tokenized:
        assert(rule_is_title([message_rules[0][0]]))
        if message_name == title_rule_get_name(message_rules[0]):
            return message_rules

def split_fields_for_create_message(message_name, message_rules_tokenized):
    needed_input_fields = []
    length_fields = []
    fixed_fields = []
    
    for rule in message_rules_tokenized[1:]:
        if rule_is_field(rule):
            byte_symbol = field_rule_get_byte_symbol(rule)

            
            if field_rule_is_lengthof(rule):
                length_fields.append(field_rule_get_field_name(rule))
            elif byte_symbol_is_valid_hex(byte_symbol):
                fixed_fields.append(field_rule_get_field_name(rule))
            else:
                needed_input_fields.append(field_rule_get_field_name(rule))
    

    return needed_input_fields, length_fields, fixed_fields

def create_message(message_name, cocodoc, input_dict = None):

    message_rules = find_message_rules(message_name, cocodoc.all_messages_rules_tokenized)
    message_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules
    message_rules = perform_subtypeof_overrides(message_rules, cocodoc.all_messages_rules_tokenized)
    
    needed_input_fields, length_fields, fixed_fields = split_fields_for_create_message(message_name, message_rules)
        
    message_fields_dict = OrderedDict()
    lengths_dict = {}
    
    multifield_names_stack = []
    accumulated_multifield_lengths = {}
    
    if input_dict is not None:
        input_fields_stack = input_dict["message_fields"][::-1]
            
    for rule in message_rules:
        if rule_is_field(rule):
            
            field_name = field_rule_get_field_name(rule)
            byte_symbol = field_rule_get_byte_symbol(rule)
            
            if field_name in fixed_fields:
                message_fields_dict[field_name] = byte_symbol.lower()
                
                for multifield in multifield_names_stack:
                    accumulated_multifield_lengths[multifield] += len(byte_symbol)//2
                    
            elif field_name in length_fields:
                message_fields_dict[field_name] = None
                
                for multifield in multifield_names_stack:
                    accumulated_multifield_lengths[multifield] += len(byte_symbol)//2
                    
            elif field_name in needed_input_fields:
                if input_dict is not None:
                    field_recipe = input_fields_stack.pop()
                    
                    value = ""
                    
                    if "value_is_hex_string" not in field_recipe:
                        field_recipe["value_is_hex_string"] = not field_recipe["value_is_file_path"]
                    
                    if field_recipe["value_is_file_path"] == True:
                        if field_recipe["value_is_hex_string"] == False:
                            with open(field_recipe["value"], mode="rb") as f:
                                value = f.read()
                        else:
                            with open(field_recipe["value"]) as f:
                                value = f.read()
                    else:
                        value = field_recipe["value"]
                    
                    if field_recipe["value_is_hex_string"] == False:
                        value = value.hex()
                    
                    if field_recipe["should_encode"] == True:
                        value = field_encode(rule, value)
                        
                    hex_string = value #TODO assert rule complies parent
                    
                else:
                    hex_string = input(f"Enter hex string for field '{field_name}': ") 
                    
                assert is_valid_message_input(hex_string), f"Malformed hex string for '{field_name}': '{hex_string}'"
                message_fields_dict[field_name] = hex_string.lower()
                lengths_dict[field_name] = len(hex_string)//2
                
                for multifield in multifield_names_stack:
                    accumulated_multifield_lengths[multifield] += len(hex_string)//2
                
            else:
                raise RuntimeError(f"Unexpected {rule=} in message rules for message {title_rule_get_name(message_rules[0])}")
        elif rule_is_multifieldstart(rule):
            multifield_name = get_multifieldstart_full_name(rule[1])
            multifield_names_stack.append(multifield_name)
            accumulated_multifield_lengths[multifield_name] = 0
        elif rule_is_multifieldend(rule):
            mfs_name = multifield_names_stack[-1]
            mfe_name = get_multifieldend_full_name(rule[1])
            
            assert mfs_name == mfe_name, f"Unexpected multifield end, {rule=}, {multifield_names_stack[-1]=}"
            
            multifield_names_stack.pop()
    
    for k, v in accumulated_multifield_lengths.items():
        # For now we will use the short names to keep it simple, SHOULD FIX it in the future
        mf_name = k[k.find(".")+1:].strip()
        lengths_dict[mf_name] = v

    #FILL LENGTHOF FIELDS:
    for field_name in length_fields:
        for i, rule in enumerate(message_rules):
            if rule_is_field(rule) and field_rule_is_lengthof(rule):
                field_name = field_rule_get_field_name(rule)
                target_field_for_length = lengthof_rule_get_target_field_name(rule)
                
                length = lengths_dict[target_field_for_length]
                
                byte_symbol = field_rule_get_byte_symbol(rule)
                assert byte_symbol_is_XX_rule_type(byte_symbol)
                length_field_strlength = len(byte_symbol)
                
                #get_length_hex_string = lambda x: (hex(x)[2:] if len(hex(x))%2 == 0 else "0" + hex(x)[2:]).lower()
                #length_hex_string = get_length_hex_string(length) #BIGENDIAN
                length_hex_string = field_encode(rule, str(length))
                #print(f"HOLA : {length_hex_string=}")
                
                #raise RuntimeError("ASDFASDF")
                
                if len(length_hex_string) > length_field_strlength:
                    raise RuntimeError(f"length {length_hex_string} for {rule=} would overflow the length field")
                elif len(length_hex_string) < length_field_strlength:
                    length_hex_string = "0"*(length_field_strlength-len(length_hex_string)) + length_hex_string
                elif len(length_hex_string) == length_field_strlength:
                    pass
                
                #SWAP IF LITTLE ENDIAN:
                #params = rule[2:]
                #for param in params:
                    #if "lengthof " in param:
                        #if "littleendian:lengthof " in param or "le:lengthof " in param:
                            #length_hex_string = "".join(re.findall('..',length_hex_string)[::-1])
                
                message_fields_dict[field_name] = length_hex_string

    #pprint(message_fields_dict)
    
    
    ## Check if all generated fields comply with the rules
    for rule in message_rules:
        if rule_is_field(rule):
            field_name = field_rule_get_field_name(rule)
            message_field_aux_rule = [message_fields_dict[field_name], field_name]
            
            if not field_rule_complies_parent(message_field_aux_rule, rule):
                raise ValueError(f"Input Error: field rule {message_field_aux_rule} doesn't comply with parent rule {rule}")
            
            
    ## Build message
    message = ""
    for v in message_fields_dict.values():
        message += v
        
    ##REDUNDANT CHECK: We already checked fields comply with rules, but we validate the full message just in case
    validate_result = validate_message_by_name(message_name, message, cocodoc)
    
    if validate_result[0] == False:
        raise RuntimeError(f"Invalid message generated. Call protococo check {message_name} {message} to see dissection")

    return message

def get_input_schema(message_name, cocodoc):    
    message_rules = find_message_rules(message_name, cocodoc)
    message_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules
    message_rules = perform_subtypeof_overrides(message_rules, cocodoc)
    
    needed_input_fields, length_fields, fixed_fields = split_fields_for_create_message(message_name, message_rules)

    fields_schema = []
    for field_name in needed_input_fields:
        fields_schema.append({
            "field_name" : field_name,
            "value" : "input field value or path/to/file (relative to script execution dir)",
            "value_is_file_path" : False,
            "should_encode" : False
            #"value_is_hex_string" : True,
        })
    
    schema = [{"message_name" : message_name,
               "message_fields" : fields_schema}]
    
    
    return schema

"""

        DEFAULT ENTRYPOINT

"""
def cli_main():
    args = docopt(__doc__, version=f"protococo {__version__}")
    #print(args)

    #with open("default.coco") as f:
        #all_messages_string = f.read()

    with open(args["--cocofile"]) as f:
        all_messages_string = f.read()
    
    ret = 0
        
    cocodoc = CocoDocument(all_messages_string)
    
    if args["tree"] == True:
        cocodoc.print_tree()
    elif args["check"] == True:
        messages_input = [sys.stdin.read()] if not args["<message_hex_string>"] else args["<message_hex_string>"]
        
        for message_hex_string in messages_input:
            validate_result = validate_message_by_name(args["<message_name>"], message_hex_string, cocodoc)
            
            explanation_logs = None
            if args["--verbose"] == True:
                explanation_logs = validate_result[3]
                
            print(get_message_explanation_string(validate_result, explanation_logs, fmt=args["--format"], decode=args["--decode"], no_newlines=args["--decode-no-newlines"]))
            
            if validate_result[0] == False:
                ret = 1
        
    elif args["find"] == True:
        messages_input = sys.stdin.read().split() if not args["<message_hex_string>"] else args["<message_hex_string>"]
        for message_hex_string in messages_input:
            ordered_message_names, validate_results_by_message_name = identify_message(message_hex_string, cocodoc)
            for i, match in enumerate(ordered_message_names):
                color = AnsiColors.BOLD + AnsiColors.OKGREEN if validate_results_by_message_name[match][0] == True else AnsiColors.BOLD + AnsiColors.FAIL
                
                filter_fields = [i.strip() for i in args["--dissect-fields"].split(",")] if args["--dissect-fields"] is not None else None
                                
                explanation = ""
                if args["--dissect"] == True or filter_fields is not None:
                    validate_result = validate_message_by_name(match, message_hex_string, cocodoc)
                    
                    if args["--verbose"] == True:
                        explanation = "\n" + get_message_explanation_string(validate_result, validate_result[3], fmt=args["--format"], filter_fields=filter_fields, decode=args["--decode"], no_newlines=args["--decode-no-newlines"])
                    else:
                        explanation = get_message_explanation_string(validate_result, None, fmt=args["--format"], filter_fields=filter_fields, decode=args["--decode"], no_newlines=args["--decode-no-newlines"])
                        
                    if validate_result[0] == False:
                        ret = 1
                
                name_string = match
                if args["--long-names"] == False:
                    name_string = get_short_message_name(match)
                number_of_whitespaces = get_max_message_name_length(cocodoc.all_messages_rules_tokenized, args["--long-names"]) - len(name_string) + 2
                    
                if args["--list"] == False:
                    if args["--format"] == "oneline" or args["--format"] == "compact":
                        print(color  + f"[{name_string}]" + AnsiColors.ENDC + " "*number_of_whitespaces + explanation)
                    else:
                        print(color  + f"[{name_string}]" + AnsiColors.ENDC)
                        print(explanation)
                        print()
                    break
                else:
                    if args["--format"] == "oneline" or args["--format"] == "compact":
                        print(color  + f"{str(i): >8}: [{name_string}]" + AnsiColors.ENDC + " "*number_of_whitespaces + explanation)
                    else:
                        print(color  + f"- {i}: [{name_string}]" + AnsiColors.ENDC)
                        print(explanation)
                        print()
    elif args["create"] == True:
        
        if args["<message_name>"] is not None and args["<message_name>"] != []:
            try:
                message = create_message(args["<message_name>"], cocodoc.all_messages_rules_tokenized)
                print(message)
            except ValueError as e:
                print(e)
        elif args["--from-json"] is not None:
            json_file_path = args["--from-json"]
            
            with open(json_file_path) as f:
                full_recipe = json.load(f)
            
            for message_recipe in full_recipe:
                try:
                    message = create_message(message_recipe["message_name"], cocodoc.all_messages_rules_tokenized, input_dict=message_recipe)
                    print(message)
                except ValueError as e:
                    print(e)
            
            
            
        #else:
            
    elif args["json-recipe"] == True:
        message_names = args["<message_names>"]
        
        schema = []
        
        for message_name in message_names:
            schema += get_input_schema(message_name, cocodoc.all_messages_rules_tokenized)
        
        print(json.dumps(schema, indent = 2))
        #print(yaml.dump(schema))
                
        
        
    sys.stdout.flush()
    os._exit(ret)
    

    
    
    
    



#TODO warnings: 2 equivalent messages in rules
#TODO error: 2 fields with same name in rules
#TODO feature: complete tree in multiline check/dissect
#TODO ?: identificación certera del mensaje en función del message_type???
#TODO fix: falla cuando un lengthof cae dentro de una ellipsis o más allá del fin del mensaje en mensajes incompletos
#TODO improvement: cambiar el --dissect-fields por un arg adicional opcional filter-fields que tb funcione con el check
#TODO feature: #include message, #includepart message
#TODO feature: X16
#TODO improvement: N field of missing length could be OK sometimes
#TODO feature: endswith instead of length
#TODO feature: --input-format=bin, --input-format=hex-string
#TODO feature: create message
#TODO feature: regex matcher for ascii rule
#TODO tests: Bash diff tests
#TODO fix: Logger for --verbose fix
#TODO feature: --input-format=json
#TODO feature: output-format==ptable
#TODO optimization: don't tokenize rules for each validation
#TODO fix: overriden fields with different params, like encodedas
#TODO optimization: if a parent rule fails, don't check subtypes. --list'd not be possible
#TODO refactor: CocoDocument, CocoMessageSpec, CocoRule, CocoParser, CocoAnalyzer, CocoCLI
#TODO improvement: cocofile checks: no "." in any rule
#TODO fix: problem decoding littleendian from rule between parenthesis, example: (0)   #encodedas littlendian
#TODO fix: override a 4 byte field with a 1 byte field. example: (0)   #encodedas littlendian with parent like XXXXXXXX
#TODO feature: add encodedas json
#TODO fix?: override field from different parent levels
#TODO fix: throw parse error if can't override subtype (overriden field not existing in parent)
#TODO fix: create fails with multi-subtypeof

            
if __name__ == "__main__":
    cli_main()
