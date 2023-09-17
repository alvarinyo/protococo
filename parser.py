import os
import re
import copy
from collections import OrderedDict
from pprint import pprint

TOKEN_DELIMITER = '$'
COMMENT_DELIMITER = '#'

def remove_comments(line):
    if line.count(COMMENT_DELIMITER) == 0:
        return line
    
    result = line.strip()
    
    if line.count(TOKEN_DELIMITER) == 0:
        result = line[:line.index(COMMENT_DELIMITER)]
    else:
        lhs = line[:line.index(TOKEN_DELIMITER)].strip()
        if COMMENT_DELIMITER in lhs:
            open_parenthesis_count = 0
            for i, c in enumerate(lhs):
                if c=="(":
                    open_parenthesis_count+=1
                elif c==")":
                    open_parenthesis_count-=1
                if open_parenthesis_count < 0:
                    raise RuntimeError("Unexpected ')'")
                if c == COMMENT_DELIMITER and open_parenthesis_count == 0:
                    result = line[:i]
        else:
            result = line[:line.index(COMMENT_DELIMITER)]
    
    return result.strip()

def tokenize_line(line):
    tokenized_rule = []
        
    if line.count(TOKEN_DELIMITER) == 0:
        if (rule_is_title([line])):
            tokenized_rule += [line]
        else:
            raise RuntimeError(f"Non-title rule without '{TOKEN_DELIMITER}' character")
    else:
    
        #left hand side
        lhs = line[:line.index(TOKEN_DELIMITER)].strip()
        tokenized_rule.append(lhs)
        #right hand side
        rhs = line[line.strip().index(TOKEN_DELIMITER)+1:]
        tokenized_rhs = [token.strip() for token in rhs.split(',')]
        tokenized_rule += tokenized_rhs
    
    return tokenized_rule

def tokenize_rules(rules_string):
    lines = [line.strip() for line in rules_string.splitlines() if len(line.strip()) > 0]

    tokenized_rules = []
    for line in lines:
        line = remove_comments(line)
        if line == "":
            continue
        rule = tokenize_line(line)
        tokenized_rules.append(rule)
    
    return tokenized_rules

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
    elif tokenized_rule.count(TOKEN_DELIMITER) > 0 or tokenized_rule.count(',') > 0:
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
        found_override = False
        for i, parent_rule in enumerate(tokenized_overriden_rules):
            #print(f"{parent_rule=}")
            if rule_is_field(parent_rule) and overriden_field_name == field_rule_get_field_name(parent_rule):
                tokenized_overriden_rules = tokenized_overriden_rules[:i] + subfields + tokenized_overriden_rules[i+1:]
                found_override = True
                break
        if not found_override:
            raise RuntimeError(f"Overriding spec '{title_rule_get_name(child_rules[0])}', couldn't find overriden field '{overriden_field_name}' in parent spec '{parent_name}'")
    
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
                
                #pprint(f"before override:")
                #pprint(expanded_child_rules)
                # pprint(f"{expanded_child_rules[i]=}")
                expanded_child_rules = override_rules(parent_rules, expanded_child_rules)
                #pprint(f"after override")
                #pprint(expanded_child_rules)
                #pprint(f"{expanded_child_rules[i]=}")

            i = 0
        i = i+1
    return expanded_child_rules

def preprocess_encode_fields(all_messages_rules_tokenized):
    for message_rules in all_messages_rules_tokenized:
        for rule in message_rules:
            if rule_is_field(rule):
                byte_symbol = rule[0].strip()
                if byte_symbol[0] == "(" and byte_symbol[-1] == ")":
                    #Override field rule byte symbol with the encoded value (hex string)
                    rule[0] = field_encode(rule, byte_symbol[1:-1])

def preprocess_multiple_subtypeof(all_messages_rules_tokenized):
    j = 0
    while j < len(all_messages_rules_tokenized):
        message_rules = all_messages_rules_tokenized[j]
        for i, rule in enumerate(message_rules):
            if rule_is_subtypeof(rule):
                subtypeof_rule_args_string = subtypeof_rule_get_parent(rule)
                parents = subtypeof_rule_args_string.split()
                if len(parents) > 1:
                    assert rule_is_title(message_rules[0])

                    new_message_mangled_names = []
                    #then calculate rest of variations (for rest of parents) and append to the cocodocument:
                    for parent in parents:
                        new_message_spec = copy.deepcopy(message_rules)
                        new_message_spec[i] = ["", f"subtypeof {parent}"] #replace subtypeof rule with a subtypeof rule - with each parent
                        assert rule_is_title(new_message_spec[0])
                        new_message_spec[0][0] = f"[{parent}.{new_message_spec[0][0][1:]}" #replace title of spec with mangled name #TODO can I delete this line?
                        new_message_mangled_names.append(title_rule_get_name(new_message_spec[0]))

                        all_messages_rules_tokenized = all_messages_rules_tokenized[:j] + [new_message_spec] + all_messages_rules_tokenized[j:]
                        j+=1
                    
                    del all_messages_rules_tokenized[j]
                    j-=1
                        
                    #now, make variations for all children
                    for k, mr in enumerate(all_messages_rules_tokenized):
                        for m, r in enumerate(mr):
                            if rule_is_subtypeof(r):
                                r_parents = subtypeof_rule_get_parent(r).split()
                                common_parent = title_rule_get_name(message_rules[0])
                                if common_parent in r_parents:
                                    r_parents.remove(common_parent)
                                    r = ["", f"subtypeof {' '.join(r_parents + new_message_mangled_names)}"]
                                    all_messages_rules_tokenized[k][m] = r
        j+=1
    
    return all_messages_rules_tokenized

def full_field_names_refer_to_same(a, b):
    return re.sub(":[^\.]*", "", a) == re.sub(":[^\.]*", "", b)

def rule_is_multifieldstart(rule):
    return len(rule) == 2 and rule[1][:15] == "startmultifield"

def rule_is_multifieldend(rule):
    return len(rule) == 2 and rule[1][:13] == "endmultifield"

def get_multifieldstart_full_name(multifieldstart_param):
    return multifieldstart_param[16:].strip()

def get_multifieldend_full_name(multifieldend_param):
    return multifieldend_param[14:].strip()

def _get_subtype_parents(subtypename, all_messages_rules_tokenized, parents_list, limit = None):
    found_parent = False
    parent_name = None
    
    for message_rules in all_messages_rules_tokenized:
        assert(rule_is_title(message_rules[0]))
        if title_rule_get_name(message_rules[0]) == subtypename:
            for rule in message_rules[1:]:
                if rule_is_subtypeof(rule):
                    parent_name = subtypeof_rule_get_parent(rule)
                    found_parent = True
                    if limit is not None:
                        limit -= 1
                    break
                
        if found_parent:
            break
    
    if found_parent:
        parents_list.append(parent_name)
        if limit is None or limit > 0:
            _get_subtype_parents(parent_name, all_messages_rules_tokenized, parents_list)

def get_subtype_parents(subtypename, all_messages_rules_tokenized, include_subtypename, limit = None):
    parents = []
    if include_subtypename == True:
        parents.append(subtypename)
    _get_subtype_parents(subtypename, all_messages_rules_tokenized, parents, limit)
    return parents

def byte_symbol_is_valid_hex(byte_symbol):
    try:
        int(byte_symbol, 16)
    except ValueError:
        return False
    return True

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
            
            if field_name == get_field_name_from_length_param(param) and unmatched_multifieldstart_params_to_stack(active_multifields) == param["multifields_stack"]:
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

def unmatched_multifieldstart_params_to_stack(unmatched_multifieldstart_params):
    return [get_multifieldstart_full_name(i["param"]) for i in unmatched_multifieldstart_params]

def get_conflicting_field_names(tokenized_message_rules):
    conflicting_names = []
    names = []
    for rule in tokenized_message_rules:
        if rule_is_field(rule):
            field_name = rule[1]
            if field_name in names:
                if not field_name in conflicting_names:
                    conflicting_names.append(field_name)
            else:
                names.append(field_name)

    return conflicting_names

def split_multimessage_rules(multimessage_rules_string):
    lines = [clean_line for line in multimessage_rules_string.splitlines() if (clean_line := remove_comments(line)) != '']
    multimessage_rules_string_without_empty_lines = os.linesep.join(lines)
    list_of_message_rules = re.split("(\[[^\[]*)", multimessage_rules_string_without_empty_lines)
    list_of_message_rules = list(filter(lambda x: x!= "", list_of_message_rules))
    
    return list_of_message_rules

def get_short_message_name(long_message_name):
    return re.sub(r'.*?([^\.]*)$', r'\1', long_message_name)

def get_max_message_name_length(all_messages_rules_tokenized, long_names = False):
    max_length = 0
    if long_names:
        for message_rules in all_messages_rules_tokenized:
            max_length = max(max_length, len(title_rule_get_name(message_rules[0])))
    else:
        for message_rules in all_messages_rules_tokenized:
            max_length = max(max_length, len(get_short_message_name(title_rule_get_name(message_rules[0]))))
    return max_length

from treelib import Node, Tree

class CocoMessageSpec(object):
    def __init__(self, full_message_name, preprocessed_rules):
        self.full_message_name = full_message_name
        self.preprocessed_rules = preprocessed_rules
        self.conflicting_field_names = get_conflicting_field_names(self.preprocessed_rules)

    # def get_direct_parent_name(self):

class CocoDocument(object):
    def __init__(self, all_messages_string):
        self.all_messages_rules_tokenized = [tokenize_rules(r) for r in split_multimessage_rules(all_messages_string)]
        preprocess_encode_fields(self.all_messages_rules_tokenized)
        self.all_messages_rules_tokenized = preprocess_multiple_subtypeof(self.all_messages_rules_tokenized)

        self.message_specs = []
        for message_rules in self.all_messages_rules_tokenized:
            self.message_specs.append(CocoMessageSpec(title_rule_get_name(message_rules[0]), perform_subtypeof_overrides(message_rules, self.all_messages_rules_tokenized)))


            p = get_subtype_parents(self.message_specs[-1].full_message_name, self.all_messages_rules_tokenized, False, limit = 1)


        self.tree = Tree()
        self.tree.create_node("_", 0)
        for message_spec in self.message_specs:
            parent = get_subtype_parents(message_spec.full_message_name, 
                                         self.all_messages_rules_tokenized, 
                                         False, 
                                         limit = 1)
            parent = 0 if parent == [] else parent[0]
            self.tree.create_node(message_spec.full_message_name[message_spec.full_message_name.rfind('.')+1:],
                                  message_spec.full_message_name,
                                  parent = parent)


    def get_message_spec(self, full_message_name):
        for ms in self.message_specs:
            if ms.full_message_name == full_message_name:
                return ms
        return None

    def print_tree(self):
        print(self.tree.show(stdout = False))

