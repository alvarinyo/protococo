from collections import OrderedDict
import re
from pprint import pprint

from parser import is_valid_message_input


from parser import byte_symbol_is_valid_hex, \
                   byte_symbol_is_XX_rule_type
                   

from parser import tokenize_rules, \
                   perform_subtypeof_overrides, \
                   get_conflicting_field_names, \
                   field_get_expected_bytes_length, \
                   unmatched_multifieldstart_params_to_stack, \
                   title_rule_get_name, rule_is_title, rule_is_field, \
                   rule_is_multifieldstart, get_multifieldstart_full_name, \
                   rule_is_multifieldend, get_multifieldend_full_name, \
                   field_rule_complies_parent, field_rule_is_encoded, \
                   field_rule_get_field_name, \
                   field_decode, \
                   get_subtype_parents


def process_length_params(tokenized_rules, message):
    length_params = []
    expected_lengths_dict = OrderedDict()
    
    current_offset = 0
    current_length = None
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
            
            
            expected_lengths_dict[(tuple(unmatched_multifieldstart_params_to_stack(unmatched_multifieldstart_params)), field_name)] = current_length
            

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
                            "parent_message_name" : title,
                            "multifields_stack" : unmatched_multifieldstart_params_to_stack(unmatched_multifieldstart_params),
                        })
                        #print(length_params)
            elif byte_symbol == "N":
                pass
            else:
                raise RuntimeError(f"Unexpected byte symbol for rule: {rule}")
        
            current_offset+=current_length * 2
            
        i=i+1

    return length_params, expected_lengths_dict, unknown_length_fields


def validate_message(message_rules, message, cocodoc):
    assert is_valid_message_input(message), "Malformed message, invalid hex string"
    
    tokenized_rules = tokenize_rules(message_rules) if isinstance(message_rules, str) else message_rules

    message_spec = cocodoc.get_message_spec(title_rule_get_name(message_rules[0]))
    tokenized_rules = message_spec.preprocessed_rules
    conflicting_field_names = message_spec.conflicting_field_names
    
    title_rule = None
    title = None
    
    is_valid = True
    result_dict = OrderedDict()
    decoded_result_dict = OrderedDict()
    diff_dict = OrderedDict()
    log_dict = OrderedDict()
    
    length_params, expected_lengths_dict, unknown_length_fields = process_length_params(tokenized_rules, message)
            
    i = 0
    current_offset = 0
    current_length = 0

    multifield_names_stack = []
    while i < len(tokenized_rules):
            
        rule = tokenized_rules[i]

        if rule_is_field(rule):
            
            byte_symbol = rule[0]
            field_name = rule[1]
            params = rule[2:]

            field_name_mangled = field_name if not field_name in conflicting_field_names else ".".join([i.split(".", 1)[1] for i in multifield_names_stack] + [field_name])

            if field_name_mangled in result_dict.keys():
                raise RuntimeError(f"Duplicated field {field_name} in {rule=} of {title_rule_get_name(title_rule)}")

            if field_name in unknown_length_fields:
                result_dict[field_name_mangled] = "(?)"
                diff_dict[field_name_mangled]  = False
                log_message = "Can't deduce this field length"
                try:
                    log_dict[field_name_mangled].append(log_message)
                except KeyError:
                    log_dict[field_name_mangled] = [log_message]
                i+=1
                continue
            
            current_length = expected_lengths_dict[(tuple(multifield_names_stack), field_name)]
            
            #print(f"{current_offset=},{current_length=}, '{message[current_offset:current_offset + current_length * 2]}'")
            
            if not "." in message[current_offset:current_offset + current_length * 2] and current_offset + current_length * 2 > len(message):
                result_dict[field_name_mangled] = message[current_offset:]
                
                number_of_missing_bytes = current_length - len(result_dict[field_name_mangled])//2
                if number_of_missing_bytes <= 16:
                    result_dict[field_name_mangled] += "--" * number_of_missing_bytes
                else:
                    result_dict[field_name_mangled] += f"---({number_of_missing_bytes} bytes missing)---"
                
                diff_dict[field_name_mangled] = False
                current_offset = len(message)
            
            elif "." in message[current_offset:current_offset + current_length * 2]: # and not message[current_offset:current_offset+3] == "...":
                
                ellipsis_offset = message.find("...")
                assert ellipsis_offset%2 == 0, "Malformed message: Invalid hex string before ellipsis"
                after_ellipsis_offset = ellipsis_offset + len("...")
                
                this_field_expected_length = 0
                total_expected_length = 0
                expected_length_after_this_field = 0
                
                mfns_stack = []
                for j, r in enumerate(tokenized_rules):
                    if (rule_is_field(r)):
                        r_length = expected_lengths_dict[(tuple(mfns_stack),field_rule_get_field_name(r))]
                        total_expected_length += r_length
                        if j==i:
                            this_field_expected_length = r_length
                        elif j>i:
                            expected_length_after_this_field += r_length
                    elif rule_is_multifieldstart(r):
                        multifield_name = get_multifieldstart_full_name(r[1])
                        mfns_stack.append(multifield_name)
                    elif rule_is_multifieldend(r):
                        mfs_name = mfns_stack[-1]
                        mfe_name = get_multifieldend_full_name(r[1])
                        assert mfs_name == mfe_name, f"Unexpected multifield end, {r=}, {mfns_stack[-1]=}"
                        mfns_stack.pop()
                #print(f"{total_expected_length=}")
                #print(f"{expected_length_after_this_field=}")

                result_dict[field_name_mangled] = message[current_offset:ellipsis_offset]
                diff_dict[field_name_mangled] = True
                
                inserted_length = len(message[current_offset:ellipsis_offset])//2
                                
                ## NOW WE PROCESS FROM THE ELLIPSIS
                if len(message[after_ellipsis_offset:]) > expected_length_after_this_field:
                    RuntimeError("Message too long from ellipsis")
                
                length_to_insert = len(message[after_ellipsis_offset:])//2 - expected_length_after_this_field
                #print(f"{length_to_insert=}")
                if length_to_insert < 0:
                    number_of_missing_bytes = this_field_expected_length - inserted_length
                    if number_of_missing_bytes > 0:
                        result_dict[field_name_mangled] += f"...({number_of_missing_bytes} bytes)..."
                    
                    result_without_missing_bytes_info = re.sub("...\(.*\)...", "...", result_dict[field_name_mangled])
                    diff_dict.update({field_name_mangled: field_rule_complies_parent([result_without_missing_bytes_info, field_name], rule)})
                    
                    current_offset = ellipsis_offset
                    
                else:
                    number_of_missing_bytes = this_field_expected_length - (inserted_length + length_to_insert)
                    if number_of_missing_bytes >= 0:
                        if number_of_missing_bytes > 0:
                            result_dict[field_name_mangled] += f"...({number_of_missing_bytes} bytes)..."
                        result_dict[field_name_mangled] += message[after_ellipsis_offset:after_ellipsis_offset+length_to_insert*2]
                        
                        result_without_missing_bytes_info = re.sub("...\(.*\)...", "...", result_dict[field_name_mangled])
                        diff_dict.update({field_name_mangled: field_rule_complies_parent([result_without_missing_bytes_info, field_name_mangled], rule)})
                        
                    else:
                        is_valid = False
                        diff_dict[field_name_mangled] = False
                        
                        after_overflow_offset = after_ellipsis_offset+length_to_insert*2 - (-number_of_missing_bytes*2)
                        middle_overflowing_msg = message[after_ellipsis_offset:after_ellipsis_offset+(-number_of_missing_bytes*2)]
                        correct_msg_part = message[after_ellipsis_offset+(-number_of_missing_bytes*2):]
                        
                        result_dict[field_name_mangled] += f"(+{middle_overflowing_msg}) {correct_msg_part}"
                        log_message = f"Message with ellipsis too long while checking field '{field_name_mangled}', overflowing {-number_of_missing_bytes} bytes: '{message[after_ellipsis_offset:after_ellipsis_offset+(-number_of_missing_bytes*2)]}'  after the ellipsis"
                                                                                                                                                                            
                        try:
                            log_dict[field_name_mangled].append(log_message)
                        except KeyError:
                            log_dict[field_name_mangled] = [log_message]
                
            
                    # We should now have sth like this in the result_dict[field_name]:
                    # 0461...(10 bytes)...7305000000021a8a3a58
                
                    current_offset = ellipsis_offset + 3
                    current_offset += length_to_insert*2
                
            else:
                message_field_subtring = message[current_offset:current_offset+current_length * 2]
                
                if current_length > 0:
                    aux_rule = [message[current_offset:current_offset+current_length * 2], field_name]
                    diff_dict.update({field_name_mangled: field_rule_complies_parent(aux_rule, rule)})
                    
                    result_dict.update({field_name_mangled: message[current_offset:current_offset+current_length * 2]})
                    
                    if field_rule_is_encoded(rule):
                        decoded_result_dict[field_name_mangled] = f"{field_decode(rule, message_field_subtring)}"
                elif current_length == 0:
                    diff_dict.update({field_name_mangled: True})
                    result_dict.update({field_name_mangled: ""})

                else:
                    current_length = 0
                    
                    diff_dict.update({field_name_mangled: False})
                    result_dict.update({field_name_mangled: "--"})
                    
                    log_message = f"expected invalid length of {current_length} for field in rule {rule}"
                    #print(log_message)
                                                                                                                                                                            
                    try:
                        log_dict[field_name_mangled].append(log_message)
                    except KeyError:
                        log_dict[field_name_mangled] = [log_message]
            
            
                current_offset += current_length * 2
            
        elif rule_is_multifieldstart(rule):
            multifield_name = get_multifieldstart_full_name(rule[1])
            multifield_names_stack.append(multifield_name)
        elif rule_is_multifieldend(rule):
            mfs_name = multifield_names_stack[-1]
            mfe_name = get_multifieldend_full_name(rule[1])
            assert mfs_name == mfe_name, f"Unexpected multifield end, {rule=}, {multifield_names_stack[-1]=}"
            multifield_names_stack.pop()
            
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
    # pprint(result_dict)
    #print(is_valid)
    
    if is_valid == True:
        for k, v in diff_dict.items():
            if v == False:
                is_valid = False
                break
      
    return is_valid, result_dict, diff_dict, log_dict, decoded_result_dict

def validate_message_by_name(message_name, message, cocodoc):
    for message_rules in cocodoc.all_messages_rules_tokenized:
        assert(rule_is_title([message_rules[0][0]]))
        if message_name == title_rule_get_name(message_rules[0]):
            return validate_message(message_rules, message, cocodoc)
    
    raise RuntimeError(f"Message with {message_name=} not found")

def _validate_bfs(cocodoc, message, validate_results, node):
    if node.identifier != 0: # 0 is reserved for root
        validate_results.update({node.identifier : validate_message_by_name(node.identifier, message, cocodoc)})
        
    if node.identifier == 0 or validate_results[node.identifier][0] == True:
        for child in cocodoc.tree.children(node.identifier):
            _validate_bfs(cocodoc, message, validate_results, child)

def validate_bfs(cocodoc, message, validate_results):
    _validate_bfs(cocodoc, message, validate_results, cocodoc.tree.get_node(cocodoc.tree.root))

def identify_message(message, cocodoc, include_all_bad = False):
    assert is_valid_message_input(message), "Malformed message, invalid hex string"
    
    validate_results = OrderedDict()

    if include_all_bad:
        for message_rules in cocodoc.all_messages_rules_tokenized:
            assert(rule_is_title(message_rules[0]))
            validate_results.update({title_rule_get_name(message_rules[0]) : validate_message(message_rules, message, cocodoc)})
    else:
        validate_bfs(cocodoc, message, validate_results)
        pass
    
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
    
    def number_of_parents(message_name):
        return len(get_subtype_parents(message_name, cocodoc.all_messages_rules_tokenized, False))

    ordered_message_names = sorted(message_names, key=lambda x: (total_bytes_matching(validate_results[x]), total_fields_matching(validate_results[x]), number_of_parents(x)), reverse=True)

    #return True, ordered_message_names
    return ordered_message_names, validate_results
