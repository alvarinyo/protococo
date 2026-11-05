
def wrap_payload(message_payload, message_name, message_field_name):
    pass

def split_message(message, max_chunk_size):
    result = []

    message_str_len = len(message)
    chunk_str_offset = 0
    max_chunk_str_len = 2 * max_chunk_size
    if max_chunk_str_len > message_str_len:
        max_chunk_str_len = message_str_len

    while True:
        if chunk_str_offset + max_chunk_str_len < message_str_len:
            result.append(message[chunk_str_offset : chunk_str_offset + max_chunk_str_len])
            chunk_str_offset += max_chunk_str_len
        else:
            if len(message[chunk_str_offset:]) > 0:
                result.append(message[chunk_str_offset:])
            break
    
    return result

if __name__ == '__main__':
    from pprint import pprint
    
    for chunk_size in range(30, 0, -1):
        chunks = split_message("aaaabbbbccaaaabbbbccaaaabbbbccaaaabbbbccaaaabbbbcc", chunk_size); pprint(chunks); print("-----")
