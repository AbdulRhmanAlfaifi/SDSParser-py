from ntfs_sds_parser import PySDSParser
import os

try:
    parser = PySDSParser(f"{os.path.dirname(__file__)}/../samples/sds_sample_record")

    for entry in parser:
        if not entry.is_error:
            print("="*50)
            print(f"Hash        : {entry.get_hash()}")
            print(f"ID          : {entry.get_security_id()}")
            print(f"Owner SID   : {entry.get_owner_sid()}")
            print(f"group SID   : {entry.get_group_sid()}")
            
            dacl = entry.get_dacl()
            if dacl:
                print("==== DACL ====")
                print(f"revision    : {dacl.revision}")
                print(f"count       : {dacl.count}")
                print(f"entries     :")
                for ace in dacl.entries:
                    print(f"    type    : {ace.ace_type}")
                    print(f"    flags   : {ace.ace_flags}")
                    print(f"    data    : {ace.ace_data}")
                    print(f"")
            
            sacl = entry.get_sacl()
            if sacl:
                print("==== SACL ====")
                print(f"revision    : {sacl.revision}")
                print(f"count       : {sacl.count}")
                print(f"entries     :")
                for ace in sacl.entries:
                    print(f"    type    : {ace.ace_type}")
                    print(f"    flags   : {ace.ace_flags}")
                    print(f"    data    : {ace.ace_data}")
                    print(f"")

except Exception as e:
    print(f"ERROR: {e}")