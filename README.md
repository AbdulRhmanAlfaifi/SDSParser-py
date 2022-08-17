# SDSParser-py
This project is Python3 bindings for [Rust](https://github.com/AbdulRhmanAlfaifi/SDSParser-rs) version. SDSParser is NTFS Security Descriptor Stream ($Secure:$SDS) parser.
# Download and Compilation
## Download from PyPi
```bash
python3 -m pip install sds_parser
```

## Download wheels
You can also download wheels files from release section and install it using `python3 -m pip install <WHEEL_FILE>`

## Compile from Source
1. Install [Rustlang](https://www.rust-lang.org/tools/install)
2. Install [Python (>=3.7)](https://www.python.org/)
3. Install `maturin`: ```python3 -m pip install maturin```
4. Compile and Install this library:
```bash
git clone https://github.com/AbdulRhmanAlfaifi/SDSParser-py
cd SDSParser-py
python3 -m pip install .
``` 
## Usage
This is a simple script to parse `samples/sds_sample_record`:
```python
from sds_parser import PySDSParser
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

except Exception as e:
    print(f"ERROR: {e}")
```

Refer to the `examples` directory in this repository for more examples.