from sds_parser import PySDSParser
import os
try:
    parser = PySDSParser(f"{os.path.dirname(__file__)}/../samples/sds_sample_record")

    for entry in parser:
        if not entry.is_error:
            print(entry.to_json())

except Exception as e:
    print(f"ERROR: {e}")