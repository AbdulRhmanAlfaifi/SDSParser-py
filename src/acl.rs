use pyo3::prelude::*;
use serde_json;
use winstructs::security::Acl;

/// Access Control Entry (ACE) data
#[pyclass]
#[derive(Clone)]
pub struct PyACE {
    #[pyo3(get)]
    ace_type: String,
    #[pyo3(get)]
    ace_flags: String,
    #[pyo3(get)]
    ace_data: String,
}

impl PyACE {
    pub fn new(ace_type: String, ace_flags: String, ace_data: String) -> Self {
        Self {
            ace_type,
            ace_flags,
            ace_data,
        }
    }
}

/// Represent Access Control List (ACL)
#[pyclass]
pub struct PyACL {
    #[pyo3(get)]
    revision: u8,
    #[pyo3(get)]
    count: u16,
    #[pyo3(get)]
    entries: Vec<PyACE>,
}

impl PyACL {
    pub fn new(acl: &Acl) -> Option<Self> {
        let mut aces = vec![];

        for ace in acl.entries.clone() {
            let pyace = PyACE::new(
                format!("{:?}", ace.ace_type),
                format!("{:?}", ace.ace_flags),
                serde_json::to_string(&ace.data).unwrap(),
            );
            aces.push(pyace);
        }

        Some(Self {
            revision: acl.revision,
            count: acl.count,
            entries: aces,
        })
    }
}
