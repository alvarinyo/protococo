#!/usr/bin/python3
"""Protococo.

Usage:
  protococo.py check  <message_name> [<message_hex_string> ...]
                      [--cocofile=<file> --format=<option>] 
                      [--verbose --decode]
  protococo.py find   [<message_hex_string> ...]
                      [--cocofile=<file> --format=<option>]
                      [--dissect | --dissect-fields=<comma_separated_fields>]
                      [--list --verbose --decode]
  protococo.py create (<message_name> | --from-json=<json_file>)
                      [--cocofile=<file>]
  protococo.py json-recipe <message_names> ...
                      [--cocofile=<file>]

Options:
  -h --help             Show this screen.
  --version             Show version.
  --cocofile=<file>     Specify the protococo rules file [default: default.coco].
  --verbose             Enable verbose output.
  --format=<option>     Print message disection in different formats [default: oneline].
                            Options: oneline, multiline.
  --dissect             Include message field dissection in find results.
  --list                Include a list of the most fitting messages in find results.
  
"""

__version__ = "0.0.1"

from pprint import *
from collections import OrderedDict
import re
import os
import sys
import json
from docopt import docopt

# TODO: Esto pide a gritos como mínimo 3 clases: FieldRule (con byte_symbol, field_name y params), SpecialRule (con params), TitleRule (con message_name)

def tokenize_rules(rules_string):
    lines = [line.strip() for line in rules_string.splitlines() if len(line.strip()) > 0]

    tokenized_lines = []
    for line in lines:
        tokenized_line = []
        
        if line.count('#') == 0:
            if (rule_is_title([line])):
                tokenized_line += [line]
            else:
                raise RuntimeError("Non-title rule without '#' character")
        else:
        
            #left hand side
            lhs = line[:line.index('#')].strip()
            tokenized_line.append(lhs)
            #right hand side
            rhs = line[line.strip().index('#')+1:]
            tokenized_rhs = [token.strip() for token in rhs.split(',')]
            tokenized_line += tokenized_rhs
        
        tokenized_lines.append(tokenized_line)
    
    return tokenized_lines

def rule_is_special(tokenized_rule):
    return tokenized_rule[0] == ""

def rule_is_field(tokenized_rule):
    #print(f"-----> {tokenized_rule}")
    return not rule_is_special(tokenized_rule) and len(tokenized_rule) > 1

def rule_is_override(tokenized_rule):
    return rule_is_special(tokenized_rule) and tokenized_rule[1][:9] == "override "

def rule_is_subtypeof(tokenized_rule):
    return rule_is_special(tokenized_rule) and tokenized_rule[1][:10] == "subtypeof "

def rule_is_title(tokenized_rule):
    title_with_brackets = tokenized_rule[0]
    #print(f"{len(title_with_brackets)=}, {tokenized_rule[0]=}, {tokenized_rule[-1]=}")
    if len(tokenized_rule) != 1 or title_with_brackets[0] != '[' or title_with_brackets[-1] != ']':
        return False
    elif tokenized_rule.count('#') > 0 or tokenized_rule.count(',') > 0:
        raise RuntimeError("Unexpected character in title rule={tokenized_rule}")
    else:
        return True

def field_rule_is_encoded(rule):
    assert rule_is_field(rule)
    
    for param in rule[1:]:
        if "encodedas" in param:
            return True
    
    return False

def field_rule_is_lengthof(rule):
    assert rule_is_field(rule)
    
    for param in rule[1:]:
        if "lengthof " in param:
            return True
    
    return False

def lengthof_rule_get_target_field_name(rule):
    assert field_rule_is_lengthof(rule)
    
    for param in rule[1:]:
        if "lengthof " in param:
            return param[param.find("lengthof ") + len("lengthof "):].strip()
    
    raise RuntimeError("lengthof not found in lengthof rule")

def field_rule_get_field_name(tokenized_field_rule):
    return tokenized_field_rule[1]

def field_rule_get_byte_symbol(tokenized_field_rule):
    return tokenized_field_rule[0]

def byte_symbol_is_XX_rule_type(byte_symbol):
    return len(byte_symbol)%2 == 0 and set(byte_symbol) == {"X"}

def field_rule_complies_parent(tokenized_child_field_rule, tokenized_parent_field_rule):
    assert(rule_is_field(tokenized_child_field_rule))
    assert(rule_is_field(tokenized_parent_field_rule))
    #print(f"Checking if {tokenized_child_field_rule=} complies with {tokenized_parent_field_rule=}")
    parent_byte_symbol = tokenized_parent_field_rule[0]
    parent_field_name = tokenized_parent_field_rule[1]
    parent_params = tokenized_parent_field_rule[2:]
    
    child_byte_symbol = tokenized_child_field_rule[0]
    child_field_name = tokenized_child_field_rule[1]
    child_params = tokenized_child_field_rule[2:]
    
    if byte_symbol_is_valid_hex(parent_byte_symbol):
        if "..." in child_byte_symbol:
            s_before_ellipsis, s_after_ellipsis = child_byte_symbol.split("...")
            #print(f"{s_before_ellipsis=}, {s_after_ellipsis=}")
            
            for i, c in enumerate(s_before_ellipsis):
                if c.lower() == parent_byte_symbol[i].lower():
                    pass
                else:
                    return False
            
            for i, c in enumerate(reversed(s_after_ellipsis)):
                print (i,c,parent_byte_symbol[-i-1])
                if c.lower() == parent_byte_symbol[-i-1].lower():
                    pass
                else:
                    return False
            
            return True
        else:
            return child_byte_symbol.lower() == parent_byte_symbol.lower()
    elif byte_symbol_is_XX_rule_type(parent_byte_symbol):
        field_length = len(parent_byte_symbol)//2
        
        return len(parent_byte_symbol) == len(child_byte_symbol) or "..." in child_byte_symbol and len(parent_byte_symbol) > len(child_byte_symbol.replace(".", ""))
    elif parent_byte_symbol == "N":
        if "-" in child_byte_symbol:
            return False
        else:
            return True
    else:
        raise RuntimeError(f"Unexpected parent rule {tokenized_parent_field_rule=}")

        
def title_rule_get_name(title_rule):
    assert(rule_is_title(title_rule))
    return title_rule[0][1:-1]

def subtypeof_rule_get_parent(subtypeof_rule):
    assert(rule_is_subtypeof)
    return subtypeof_rule[1][10:]

def override_rules(parent_rules, child_rules):
    tokenized_parent_rules = tokenize_rules(parent_rules) if isinstance(parent_rules, str) else parent_rules
    tokenized_child_rules = tokenize_rules(child_rules) if isinstance(child_rules, str) else child_rules
    
    parent_name = tokenized_parent_rules[0][0][1:-1] #TODO should this be before the 2 next statements to avoid too long parent name? include subtype name in parent_name or not?
    
    tokenized_overriden_rules = [i for i in tokenized_parent_rules]
    #tokenized_overriden_rules[0][0] = tokenized_parent_rules[0][0][:-1] + ":" + tokenized_child_rules[0][0][1:] # The expanded message name should be the_parent_one:the_child_one
    
    override_dict = {}
    
    i=0
    while i < len(tokenized_child_rules):
        child_rule = tokenized_child_rules[i]
        if rule_is_override(child_rule):
            overriden_field_name = child_rule[1][9:].strip()
        
            start_multifield_rule = ["", f"startmultifield {parent_name}.{overriden_field_name}"]
            end_multifield_rule = ["", f"endmultifield {parent_name}.{overriden_field_name}"]

            override_dict[overriden_field_name] = [start_multifield_rule]
        
            j = 1
            ijrule = tokenized_child_rules[i+j]
            while i+j < len(tokenized_child_rules) and not rule_is_override(ijrule):
                override_dict[overriden_field_name].append(ijrule)
                j+=1
                if i+j < len(tokenized_child_rules):
                    ijrule = tokenized_child_rules[i+j]
            
            override_dict[overriden_field_name].append(end_multifield_rule)
                
        i+=1
    #print("OVERRIDE DICT:")
    #pprint(override_dict)
    
    for overriden_field_name, subfields in override_dict.items():
        for i, parent_rule in enumerate(tokenized_overriden_rules):
            #print(f"{parent_rule=}")
            if rule_is_field(parent_rule) and overriden_field_name == field_rule_get_field_name(parent_rule):
                tokenized_overriden_rules = tokenized_overriden_rules[:i] + subfields + tokenized_overriden_rules[i+1:]
                break
    
    #pprint(tokenized_overriden_rules)
    
    return tokenized_overriden_rules

def perform_subtypeof_overrides(child_tokenized_rules, all_messages_rules_tokenized):
    expanded_child_rules = child_tokenized_rules
    i = 0
    while i < len(expanded_child_rules):
        rule = expanded_child_rules[i]
        if rule_is_subtypeof(rule):
            #pprint(f"{rule=} is subtypeof rule")
            parent_rules = None
            for message_rules_tokenized in all_messages_rules_tokenized:
                if title_rule_get_name(message_rules_tokenized[0]) == subtypeof_rule_get_parent(rule):
                    parent_rules = message_rules_tokenized
                    break
            if parent_rules == None:
                raise RuntimeError(f"Couldn't find parent of subtype for {rule=}")
            else:
                #pprint(f"found parent {parent_rules[0]=} of subtype for {rule=}")
                
                #pprint(f"before overide: {expanded_child_rules=}")
                #print(f"{expanded_child_rules[i]=}")
                expanded_child_rules = override_rules(parent_rules, expanded_child_rules)
                #pprint(f"after override: {expanded_child_rules=}")
                #print(f"{expanded_child_rules[i]=}")

            i = 0
        i = i+1
    return expanded_child_rules

def full_field_names_refer_to_same(a, b):
    return re.sub(":[^\.]*", "", a) == re.sub(":[^\.]*", "", b)

#print(full_field_names_refer_to_same("general_message_format:data_to_component.MESSAGE BODY", "general_message_format.MESSAGE BODY"))

def rule_is_multifieldstart(rule):
    return len(rule) == 2 and rule[1][:15] == "startmultifield"

def rule_is_multifieldend(rule):
    return len(rule) == 2 and rule[1][:13] == "endmultifield"

def get_multifieldstart_full_name(multifieldstart_param):
    return multifieldstart_param[16:].strip()

def get_multifieldend_full_name(multifieldend_param):
    return multifieldend_param[14:].strip()

def _get_subtype_parents(subtypename, all_messages_rules_tokenized, parents_list):
    found_parent = False
    parent_name = None
    
    for message_rules in all_messages_rules_tokenized:
        assert(rule_is_title(message_rules[0]))
        if title_rule_get_name(message_rules[0]) == subtypename:
            for rule in message_rules[1:]:
                if rule_is_subtypeof(rule):
                    parent_name = subtypeof_rule_get_parent(rule)
                    found_parent = True
                    break
                
        if found_parent:
            break
    
    if found_parent:
        parents_list.append(parent_name)
        _get_subtype_parents(parent_name, all_messages_rules_tokenized, parents_list)

def get_subtype_parents(subtypename, all_messages_rules_tokenized, include_subtypename):
    parents = []
    if include_subtypename == True:
        parents.append(subtypename)
    _get_subtype_parents(subtypename, all_messages_rules_tokenized, parents)
    return parents



def identify_message(message, all_messages_rules_tokenized):
    assert is_valid_message_input(message), "Malformed message, invalid hex string"
    assert(len(all_messages_rules_tokenized) > 0) 
    
    validate_results = OrderedDict()

    for message_rules in all_messages_rules_tokenized:
        assert(rule_is_title(message_rules[0]))
        validate_results.update({title_rule_get_name(message_rules[0]) : validate_message(message_rules, message, all_messages_rules_tokenized)})
    #pprint(validate_results)
    
    message_names = [k for k in validate_results.keys()]
    
    def total_bytes_matching(validate_result):
        _, result_dict, diff_dict, __, ___ = validate_result
        
        result = 0
        for k in result_dict.keys():
            #print(k, diff_dict[k])
            if diff_dict[k] == True:
                clean_bytes = re.sub("...\(.*\)...", "", result_dict[k])
                clean_bytes = re.sub("-*", "", clean_bytes)
                clean_bytes = re.sub("\(.*\)", "", clean_bytes)
                result += len(clean_bytes)//2
            #TODO ELSE get how many bytes match
        
        return result
    
    def total_fields_matching(validate_result):
        _, result_dict, diff_dict, __, ___ = validate_result
        
        result = 0
        for k in result_dict.keys():
            #print(k, diff_dict[k])
            if diff_dict[k] == True:
                #print(result_dict[k])
                result += 1
        
        return result

    ordered_message_names = sorted(message_names, key=lambda x: (total_bytes_matching(validate_results[x]), total_fields_matching(validate_results[x])), reverse=True)

    #return True, ordered_message_names
    return ordered_message_names, validate_results



def byte_symbol_is_valid_hex(byte_symbol):
    try:
        int(byte_symbol, 16)
    except ValueError:
        return False
    return True

def validate_message_by_name(message_name, message, all_messages_rules_tokenized):
    for message_rules in all_messages_rules_tokenized:
        assert(rule_is_title([message_rules[0][0]]))
        if message_name == title_rule_get_name(message_rules[0]):
            return validate_message(message_rules, message, all_messages_rules_tokenized)
    
    raise RuntimeError(f"Message with {message_name=} not found")

def is_valid_message_input(message):
    try:
        int(message.replace("...", ""), 16)
    except ValueError:
        return False
    return (isinstance(message, str) and len(message)%2 == 0 == message.count("...") == 0) or (len(message)%2 == 1 and message.count("...") == 1)


def get_length_from_length_param(param, message):
    
    rule = param["rule"]
    
    rule_params = rule[1:]
    
    
    is_little_endian = False
    for rule_param in rule_params:
        if rule_param.split() == ["encodedas", "littleendian"]:
            is_little_endian = True
            break
    
    is_big_endian = False
    for rule_param in rule_params:
        if rule_param.split() == ["encodedas", "bigendian"]:
            is_big_endian = True
            break
    
    assert not (is_little_endian and is_big_endian)
    
    #TODO: refactor using field_decode
    if is_little_endian:
        length_value_message_offset = param["value_offset"]
        length_value_length = param["value_length"]
        
        if len(message) < length_value_message_offset+length_value_length*2:
            raise LookupError(f"Can't look up length for param {param['param']} because the message is not long enough and doesn't contain that length field")
        
        length_value_string_input = message[length_value_message_offset:length_value_message_offset+length_value_length*2]
        
        length_value_string_swapped = "".join(re.findall('..',length_value_string_input)[::-1])
        current_length = int(length_value_string_swapped, 16)
        return current_length
    
    elif is_big_endian:
        length_value_message_offset = param["value_offset"]
        length_value_length = param["value_length"]
        
        if len(message) < length_value_message_offset+length_value_length*2:
            raise LookupError(f"Can't look up length for param {param['param']} because the message is not long enough and doesn't contain that length field")
        
        length_value_string_input = message[length_value_message_offset:length_value_message_offset+length_value_length*2]
        
        current_length = int(length_value_string_input, 16)
        return current_length
        

    elif "lengthof " in param["param"]:
        length_value_message_offset = param["value_offset"]
        length_value_length = param["value_length"]
        
        if length_value_length != 1:
            raise RuntimeError(f"Error in rules: '{param['param']}' field of more than 1 byte doesn't specify its endianness")
        
        if len(message) < length_value_message_offset+length_value_length*2:
            raise LookupError(f"Can't look up length for param {param['param']} because the message is not long enough and doesn't contain that length field")
        
        length_value = message[length_value_message_offset:length_value_message_offset+length_value_length*2]
        #print ("length_value_message_offset:", length_value_message_offset)
        #print ("length_value_length:", length_value_length)
        #print ("length_value:", length_value)
        current_length = int(length_value, 16)
        return current_length
    else:
        raise RuntimeError(f"Unexpected {length_param=}")

def get_field_name_from_length_param(param):
    pstring = param["param"]
    pstring = pstring.replace("littleendian:lengthof", "")
    pstring = pstring.replace("le:lengthof", "")
    pstring = pstring.replace("bigendian:lengthof", "")
    pstring = pstring.replace("be:lengthof", "")
    pstring = pstring.replace("lengthof", "").strip()
    return pstring

def get_full_field_name_from_length_param(param):
    return param["parent_message_name"] + "." + get_field_name_from_length_param(param)

def field_decode(field_rule, hex_string):
    assert(rule_is_field(field_rule))
    
    result = hex_string
    
    for param in field_rule[1:][::-1]:
        param_tokens = param.split()
        if param_tokens[0] == "encodedas":
            if param_tokens[1] == "ascii":
                try:
                    result = bytes.fromhex(result).decode()
                except UnicodeDecodeError:
                    return "--(can't decode)--"
            elif param_tokens[1] == "bigendian":
                result = int(result, 16)
            elif param_tokens[1] == "littleendian":
                #SWAP BYTES:
                result = "".join(re.findall('..',result)[::-1])
                result = int(result, 16)
            else:
                RuntimeError(f"Unknown encoding {param_tokens[1]} in rule {field_rule}")
    
    return result

def field_encode(field_rule, unencoded):
    assert(rule_is_field(field_rule))
    
    result = unencoded
    
    def to_hex_string(x):
        x = int(x)
        short_hex_string = hex(x)[2:]
        additional_zeros = len(field_rule[0]) - len(short_hex_string)
        return ("0"*additional_zeros + short_hex_string).lower()
    
    for param in field_rule[1:]:
        param_tokens = param.split()
        if param_tokens[0] == "encodedas":
            if param_tokens[1] == "ascii":
                try:
                    result = result.encode().hex()
                except UnicodeDecodeError:
                    return "--(can't decode)--"
            elif param_tokens[1] == "bigendian":
                result = to_hex_string(result)
            elif param_tokens[1] == "littleendian":
                result = to_hex_string(result)
                result = "".join(re.findall('..',result)[::-1])
            else:
                RuntimeError(f"Unknown encoding {param_tokens[1]} in rule {field_rule}")
    
    return result

#def calculate_multifield_minimum_lengths(message_rules):
    

    
    #for rule in message_rules:
        #if rule_is_field(rule):

def field_get_expected_bytes_length(field_rule, previous_length_params_list, active_multifields, message, current_offset, rule_index, message_rules_tokenized):
    
    assert rule_is_field(field_rule)
    
    byte_symbol = field_rule[0]
    field_name = field_rule[1]
    params = field_rule[2:]
    
    if byte_symbol_is_valid_hex(byte_symbol):
        current_length = len(byte_symbol) //2
        return current_length
    elif byte_symbol_is_XX_rule_type(byte_symbol):
        field_length = len(byte_symbol)//2      
        current_length = field_length
        return current_length
    elif byte_symbol == "N":
        
        foundLength = False
        
        byte_symbol = field_rule[0]
        
        for param in previous_length_params_list:
            #length_param_full_field_name =  get_full_field_name_from_length_param(param)
            #print(f"{length_param_full_field_name=}")
            
            #print(f"Checking in not-multifields, {field_name=}, {get_field_name_from_length_param(param)=}")
            
            if field_name == get_field_name_from_length_param(param):
                foundLength = True
                return get_length_from_length_param(param, message)
        
        ## Length with target=this N field not found
        ## Is this part of a multifield that has a specified length?
        
        for param in previous_length_params_list:
            length_param_full_field_name =  get_full_field_name_from_length_param(param)
            
            multifields = active_multifields
            for multifield in multifields:
                #print(f"{multifield=}")
                multifield_full_name = get_multifieldstart_full_name(multifield["param"])
                multifield_offset = multifield["offset"]
                #print(f"{multifield_full_name=}")
                #print(f"Checking if are same {get_full_field_name_from_length_param(param)} and {multifield_full_name}: {full_field_names_refer_to_same(length_param_full_field_name, multifield_full_name)}")
                if full_field_names_refer_to_same(length_param_full_field_name, multifield_full_name):
                    #print(f"found multifield {multifield_full_name} for field rule {field_rule}")
                    foundLength = True
                    max_current_length = get_length_from_length_param(param, message) - (current_offset - multifield_offset)//2 # this is the length until the end of the multifield
                    
                    ## Search in rest of multifield rules to get the rest of the length
                    length_of_rest_of_multifield = 0
                    for i, post_Nfield_rule in enumerate(message_rules_tokenized[rule_index+1:]):
                        if rule_is_multifieldend(post_Nfield_rule) and get_multifieldend_full_name(post_Nfield_rule[1]) == multifield_full_name:
                            break
                        elif rule_is_field(post_Nfield_rule):
                            if post_Nfield_rule[0] == "N":
                                raise RuntimeError(f"Found N field in rule {post_Nfield_rule} after another multifield-inferable N field in rule {field_rule}. Can't deduce length")
                            else:
                                length_of_rest_of_multifield += field_get_expected_bytes_length(post_Nfield_rule, previous_length_params_list, active_multifields, message, current_offset, rule_index+1+i, message_rules_tokenized)
                        
                    #print(length_of_rest_of_multifield)
                    
                    current_length = max_current_length - length_of_rest_of_multifield
                    #print(f"{get_length_from_length_param(param, message)=}")
                    #print(f"{multifield_offset=},{current_offset=},{current_length=}")
                    
                    #if current_length <= 0:
                        #raise RuntimeError(f"Unexpected {current_length=} <= 0 in N field inside multifield for {field_rule=}")
                    
                    return current_length
                
    if not foundLength:
        raise RuntimeError(f"Length of N field not found in previous fields for rule: {field_rule}")


def validate_message(message_rules, message, all_messages_rules_tokenized):
    assert is_valid_message_input(message), "Malformed message, invalid hex string"
    
    tokenized_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules
    #pprint(f"before overriding: {tokenized_rules=}")

    tokenized_rules = perform_subtypeof_overrides(tokenized_rules, all_messages_rules_tokenized)
    ## FROM THIS POINT ON WE HAVE OUR TOKENIZED RULES FULLY EXPANDED
    #pprint(tokenized_rules)
    
    title_rule = None
    title = None
    
    is_valid = True
    expected_lengths_dict = OrderedDict()
    result_dict = OrderedDict()
    decoded_result_dict = OrderedDict()
    diff_dict = OrderedDict()
    log_dict = OrderedDict()
    
    current_offset = 0
    current_length = None
    length_params = []
    unmatched_multifieldstart_params = []
    
    unknown_length_fields = []
    
    i = 0
    while i < len(tokenized_rules):
        rule = tokenized_rules[i]
        
        if i==0:
            assert(rule_is_title(rule))
            title_rule = rule
            title = title_rule[0][1:-1]
        elif rule_is_multifieldstart(rule):
            unmatched_multifieldstart_params.append({"param" : rule[1], "offset" : current_offset})
            #print(f"A {unmatched_multifieldstart_params=}")
        elif rule_is_multifieldend(rule):
            unmatched_multifieldstart_params = list(filter(lambda p: p["param"] != "start" + rule[1][3:], unmatched_multifieldstart_params))
            #print(f"B {unmatched_multifieldstart_params=}")
        elif rule_is_field(rule):
            
            ## UPDATE DICTS INFO AND LENGTH PARAMS
            byte_symbol = rule[0]
            field_name = rule[1]
            params = rule[2:]
            
            try:
                current_length = field_get_expected_bytes_length(rule, length_params, unmatched_multifieldstart_params, message, current_offset, i, tokenized_rules)
            except LookupError:
                # If there's a LookupError we can't deduce the length of the rest of fields, so we'll just return errors (----)
                #print(f"unknown_length for {field_name}")
                unknown_length_fields.append(field_name)
            except RuntimeError as e:
                pprint(length_params)
                pprint(e)
            
            
            expected_lengths_dict[field_name] = current_length
            
            if byte_symbol_is_valid_hex(byte_symbol):
                pass
            elif byte_symbol_is_XX_rule_type(byte_symbol):
                #print (f"'{byte_symbol}' (expected) == '{message[current_offset:current_offset+2]}' (actual)")
                for param in params:
                    if "lengthof " in param:
                        length_params.append({
                            "rule" : rule,
                            "param" : param, 
                            "value_offset" : current_offset, 
                            "value_length" : current_length,
                            "parent_message_name" : title
                        })
                        #print(length_params)
            elif byte_symbol == "N":
                pass
            else:
                raise RuntimeError(f"Unexpected byte symbol for rule: {rule}")
        
            current_offset+=current_length * 2
            
        i=i+1
            
    i = 0
    current_offset = 0
    current_length = 0
    while i < len(tokenized_rules):
            
        rule = tokenized_rules[i]
        
        if rule_is_field(rule):
            
            byte_symbol = rule[0]
            field_name = rule[1]
            params = rule[2:]
            
            if field_name in unknown_length_fields:
                result_dict[field_name] = "(?)"
                diff_dict[field_name]  = False
                log_message = "Can't deduce this field length"
                try:
                    log_dict[field_name].append(log_message)
                except KeyError:
                    log_dict[field_name] = [log_message]
                i+=1
                continue
            
            current_length = expected_lengths_dict[field_name]
            
            #print(f"{current_offset=},{current_length=}, '{message[current_offset:current_offset + current_length * 2]}'")
            
            if not "." in message[current_offset:current_offset + current_length * 2] and current_offset + current_length * 2 > len(message):
                result_dict[field_name] = message[current_offset:]
                
                number_of_missing_bytes = current_length - len(result_dict[field_name])//2
                if number_of_missing_bytes <= 16:
                    result_dict[field_name] += "--" * number_of_missing_bytes
                else:
                    result_dict[field_name] += f"---({number_of_missing_bytes} bytes missing)---"
                
                diff_dict[field_name] = False
                current_offset = len(message)
            
            elif "." in message[current_offset:current_offset + current_length * 2]: # and not message[current_offset:current_offset+3] == "...":
                
                ellipsis_offset = message.find("...")
                assert ellipsis_offset%2 == 0, "Malformed message: Invalid hex string before ellipsis"
                after_ellipsis_offset = ellipsis_offset + len("...")
                
                this_field_expected_length = 0
                total_expected_length = 0
                expected_length_after_this_field = 0
                for j, r in enumerate(tokenized_rules):
                    if (rule_is_field(r)):
                        r_length = expected_lengths_dict[field_rule_get_field_name(r)]
                        total_expected_length += r_length
                        if j==i:
                            this_field_expected_length = r_length
                        elif j>i:
                            expected_length_after_this_field += r_length
                #print(f"{total_expected_length=}")
                #print(f"{expected_length_after_this_field=}")

                result_dict[field_name] = message[current_offset:ellipsis_offset]
                diff_dict[field_name] = True
                
                inserted_length = len(message[current_offset:ellipsis_offset])//2
                                
                ## NOW WE PROCESS FROM THE ELLIPSIS
                if len(message[after_ellipsis_offset:]) > expected_length_after_this_field:
                    RuntimeError("Message too long from ellipsis")
                
                length_to_insert = len(message[after_ellipsis_offset:])//2 - expected_length_after_this_field
                #print(f"{length_to_insert=}")
                if length_to_insert < 0:
                    number_of_missing_bytes = this_field_expected_length - inserted_length
                    if number_of_missing_bytes > 0:
                        result_dict[field_name] += f"...({number_of_missing_bytes} bytes)..."
                    
                    result_without_missing_bytes_info = re.sub("...\(.*\)...", "...", result_dict[field_name])
                    diff_dict.update({field_name: field_rule_complies_parent([result_without_missing_bytes_info, field_name], rule)})
                    
                    current_offset = ellipsis_offset
                    
                else:
                    number_of_missing_bytes = this_field_expected_length - (inserted_length + length_to_insert)
                    if number_of_missing_bytes >= 0:
                        if number_of_missing_bytes > 0:
                            result_dict[field_name] += f"...({number_of_missing_bytes} bytes)..."
                        result_dict[field_name] += message[after_ellipsis_offset:after_ellipsis_offset+length_to_insert*2]
                        
                        result_without_missing_bytes_info = re.sub("...\(.*\)...", "...", result_dict[field_name])
                        diff_dict.update({field_name: field_rule_complies_parent([result_without_missing_bytes_info, field_name], rule)})
                        
                    else:
                        is_valid = False
                        diff_dict[field_name] = False
                        
                        after_overflow_offset = after_ellipsis_offset+length_to_insert*2 - (-number_of_missing_bytes*2)
                        middle_overflowing_msg = message[after_ellipsis_offset:after_ellipsis_offset+(-number_of_missing_bytes*2)]
                        correct_msg_part = message[after_ellipsis_offset+(-number_of_missing_bytes*2):]
                        
                        result_dict[field_name] += f"(+{middle_overflowing_msg}) {correct_msg_part}"
                        log_message = f"Message with ellipsis too long while checking field '{field_name}', overflowing {-number_of_missing_bytes} bytes: '{message[after_ellipsis_offset:after_ellipsis_offset+(-number_of_missing_bytes*2)]}'  after the ellipsis"
                                                                                                                                                                            
                        try:
                            log_dict[field_name].append(log_message)
                        except KeyError:
                            log_dict[field_name] = [log_message]
                
            
                    # We should now have sth like this in the result_dict[field_name]:
                    # 0461...(10 bytes)...7305000000021a8a3a58
                
                    current_offset = ellipsis_offset + 3
                    current_offset += length_to_insert*2
                
            else:
                message_field_subtring = message[current_offset:current_offset+current_length * 2]
                
                if current_length > 0:
                    aux_rule = [message[current_offset:current_offset+current_length * 2], field_name]
                    diff_dict.update({field_name: field_rule_complies_parent(aux_rule, rule)})
                    
                    result_dict.update({field_name: message[current_offset:current_offset+current_length * 2]})
                    
                    if field_rule_is_encoded(rule):
                        decoded_result_dict[field_name] = f"{field_decode(rule, message_field_subtring)}"
                else:
                    current_length = 0
                    
                    diff_dict.update({field_name: False})
                    result_dict.update({field_name: "--"})
                    
                    log_message = f"expected invalid length of {current_length} for field in rule {rule}"
                    #print(log_message)
                                                                                                                                                                            
                    try:
                        log_dict[field_name].append(log_message)
                    except KeyError:
                        log_dict[field_name] = [log_message]
            
            
                current_offset += current_length * 2
        
        i=i+1
    
    if current_offset < len(message):
        is_valid = False
        log_message = f"Overflowing bytes '{message[current_offset:]}' for message. Message too long, expected {current_offset//2} bytes, got {len(message)//2}"
        #print(log_message)
        try:
            log_dict[None].append(log_message)
        except KeyError:
            log_dict[None] = [log_message]
        diff_dict.update({None: False})
        result_dict.update({None: message[current_offset:]})
        
    #pprint(diff_dict)
    #pprint(result_dict)
    #print(is_valid)
    
    if is_valid == True:
        for k, v in diff_dict.items():
            if v == False:
                is_valid = False
                break
      
    return is_valid, result_dict, diff_dict, log_dict, decoded_result_dict


def split_multimessage_rules(multimessage_rules_string):
    multimessage_rules_string_without_empty_lines = os.linesep.join([s.strip() for s in multimessage_rules_string.splitlines() if s]) 
    list_of_message_rules = re.split("(\[[^\[]*)", multimessage_rules_string_without_empty_lines)
    list_of_message_rules = list(filter(lambda x: x!= "", list_of_message_rules))
    
    return list_of_message_rules

class AnsiColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def get_message_explanation_string_oneline(validation_result, filter_fields = None, decode=False):
    
    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result
    
    result_string = ""
    for k, v in validation_result_dict.items():
        if filter_fields is not None and k not in filter_fields:
            continue
        
        field_complies = validation_diff_dict[k]
        
        k_adj, v_adj = k, v
        
        if decode == True and k in validation_decoded_dict.keys():
            v_adj = validation_decoded_dict[k]
        
        if not field_complies:
            v_adj = AnsiColors.BOLD + AnsiColors.FAIL + v_adj + AnsiColors.ENDC
        else:
            v_adj = AnsiColors.BOLD + AnsiColors.OKGREEN + v_adj + AnsiColors.ENDC
            
        if decode == True and k in validation_decoded_dict.keys():
            v_adj = f"({v_adj})"
            
        if k_adj is not None:
            k_adj = AnsiColors.BOLD + k_adj + AnsiColors.ENDC
            result_string += f"|{k_adj}: {v_adj}"
        else:   # Overflowing bytes field
            result_string += f"|+{v_adj}"
    
    if len(result_string) > 0:
        result_string += "|"
    
    return result_string


def get_message_explanation_string_multiline(validation_result, filter_fields = None, decode=False):
    
    _, validation_result_dict, validation_diff_dict, __, validation_decoded_dict = validation_result
    
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
        
        if not field_complies:
            v_adj = AnsiColors.BOLD + AnsiColors.FAIL + v_adj + AnsiColors.ENDC
        else:
            v_adj = AnsiColors.BOLD + AnsiColors.OKGREEN + v_adj + AnsiColors.ENDC
        k_adj = AnsiColors.BOLD + k_adj + AnsiColors.ENDC
            
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


def get_message_explanation_string(validation_result, validation_log_dict = None, oneline = False, filter_fields = None, decode = False):
    
    _, validation_result_dict, validation_diff_dict, __, ___ = validation_result
    
    if oneline == True:
        result_string = get_message_explanation_string_oneline(validation_result, filter_fields, decode=decode)
    else:
        result_string = get_message_explanation_string_multiline(validation_result, filter_fields, decode=decode)

    logs_string = ""
    if validation_log_dict is not None and len(validation_log_dict) > 0:
        for field_name, log_message_list in validation_log_dict.items():
            logs_string += f"- {field_name}:\n"
                        
            #print([f"    - {log_message}" for log_message in log message_list])
            logs_string += "\n".join([f"    - {log_message}" for log_message in log_message_list])
            logs_string += "\n"
    
    return logs_string + result_string

def find_message_rules(message_name, all_messages_rules_tokenized):
    for message_rules in all_messages_rules_tokenized:
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
    

def create_message(message_name, all_messages_rules_tokenized, input_dict = None):

    message_rules = find_message_rules(message_name, all_messages_rules_tokenized)
    message_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules
    message_rules = perform_subtypeof_overrides(message_rules, all_messages_rules_tokenized)
    
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
    validate_result = validate_message_by_name(message_name, message, all_messages_rules_tokenized)
    
    if validate_result[0] == False:
        raise RuntimeError(f"Invalid message generated. Call protococo.py check {message_name} {message} to see dissection")

    return message


def get_input_schema(message_name, all_messages_rules_tokenized):    
    message_rules = find_message_rules(message_name, all_messages_rules_tokenized)
    message_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules
    message_rules = perform_subtypeof_overrides(message_rules, all_messages_rules_tokenized)
    
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
        
    all_messages_rules_tokenized = [tokenize_rules(r) for r in split_multimessage_rules(all_messages_string)]
    
    
    if args["check"] == True:
        messages_input = [sys.stdin.read()] if not args["<message_hex_string>"] else args["<message_hex_string>"]
        
        for message_hex_string in messages_input:
            validate_result = validate_message_by_name(args["<message_name>"], message_hex_string, all_messages_rules_tokenized)
            
            explanation_logs = None
            if args["--verbose"] == True:
                explanation_logs = validate_result[3]
                
            print(get_message_explanation_string(validate_result, explanation_logs, args["--format"] == "oneline", decode=args["--decode"]))
            
            if validate_result[0] == False:
                ret = 1
        
    elif args["find"] == True:
        messages_input = sys.stdin.read().split() if not args["<message_hex_string>"] else args["<message_hex_string>"]
        
        oneline_enabled = args["--format"] == "oneline"
        
        for message_hex_string in messages_input:
            ordered_message_names, validate_results_by_message_name = identify_message(message_hex_string, all_messages_rules_tokenized)
            for i, match in enumerate(ordered_message_names):
                color = AnsiColors.BOLD + AnsiColors.OKGREEN if validate_results_by_message_name[match][0] == True else AnsiColors.BOLD + AnsiColors.FAIL
                
                filter_fields = [i.strip() for i in args["--dissect-fields"].split(",")] if args["--dissect-fields"] is not None else None
                                
                explanation = ""
                if args["--dissect"] == True or filter_fields is not None:
                    validate_result = validate_message_by_name(match, message_hex_string, all_messages_rules_tokenized)
                    
                    if args["--verbose"] == True:
                        explanation = "\n" + get_message_explanation_string(validate_result, validate_result[3], oneline_enabled, filter_fields=filter_fields, decode=args["--decode"])
                    else:
                        explanation = get_message_explanation_string(validate_result, None, oneline_enabled, filter_fields=filter_fields, decode=args["--decode"])
                        
                    if validate_result[0] == False:
                        ret = 1
                
                if args["--list"] == False:
                    if oneline_enabled:
                        print(color  + f"[{match}]" + AnsiColors.ENDC + "\t" + explanation)
                    else:
                        print(color  + f"[{match}]" + AnsiColors.ENDC)
                        print(explanation)
                        print()
                    break
                else:
                    if oneline_enabled:
                        print(color  + f"- {i}: [{match}]" + AnsiColors.ENDC + "\t" + explanation)
                    else:
                        print(color  + f"- {i}: [{match}]" + AnsiColors.ENDC)
                        print(explanation)
                        print()
    elif args["create"] == True:
        
        if args["<message_name>"] is not None and args["<message_name>"] != []:
            try:
                message = create_message(args["<message_name>"], all_messages_rules_tokenized)
                print(message)
            except ValueError as e:
                print(e)
        elif args["--from-json"] is not None:
            json_file_path = args["--from-json"]
            
            with open(json_file_path) as f:
                full_recipe = json.load(f)
            
            for message_recipe in full_recipe:
                try:
                    message = create_message(message_recipe["message_name"], all_messages_rules_tokenized, input_dict=message_recipe)
                    print(message)
                except ValueError as e:
                    print(e)
            
            
            
        #else:
            
    elif args["json-recipe"] == True:
        message_names = args["<message_names>"]
        
        schema = []
        
        for message_name in message_names:
            schema += get_input_schema(message_name, all_messages_rules_tokenized)
        
        print(json.dumps(schema, indent = 2))
        #print(yaml.dump(schema))
                
        
        
    sys.stdout.flush()
    os._exit(ret)
    

    
    
    
    



#TODO warnings: 2 equivalent messages in rules
#TODO error: 2 fields with same name in rules
#TODO refactor: organizar rules en clases
#TODO feature: complete tree in multiline check/dissect
#TODO ?: identificación certera del mensaje en función del message_type???
#TODO fix: falla cuando un lengthof cae dentro de una ellipsis o más allá del fin del mensaje en mensajes incompletos
#TODO improvement: cambiar el --dissect-fields por un arg adicional opcional filter-fields que tb funcione con el check
#TODO feature: #include message, #includepart message
#TODO feature: variation of message (1byte,2 byte) -> double subtypeof?
#TODO feature: X16
#TODO improvement: N field of missing length could be OK sometimes
#TODO feature: endswith instead of length
#TODO feature: --input-format=bin, --input-format=hex-string
#TODO feature: create message
#TODO feature: regex matcher for ascii rule
#TODO doc: Foo Protocol
#TODO tests: Bash diff tests
#TODO fix: Logger for --verbose fix
#TODO fix: collision between parent and child names. store multifield stack in length_params
#TODO feature: --input-format=json
#TODO feature: output-format==ptable
#TODO optimization: don't tokenize rules for each validation

            
if __name__ == "__main__":
    cli_main()
