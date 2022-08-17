use acl::PyACL;
use pyo3::pyclass::IterNextOutput;
use pyo3::{
    exceptions::{PyFileNotFoundError, PyValueError},
    prelude::*,
    types::PyString,
};
use sds_parser::{SDSEntry, SDSParser};
use serde_json;
use std::{
    fs::File,
    io::{Error, ErrorKind},
};

mod acl;
/// This struct is used to iterate through $Secure:$SDS stream and return `PySDSEntry` struct
#[pyclass]
pub struct PySDSParser {
    parser: SDSParser<File>,
}

#[pymethods]
impl PySDSParser {
    #[new]
    fn new(path: PyObject) -> PyResult<Self> {
        let gil = Python::acquire_gil();
        let py = gil.python();

        match path.cast_as::<PyString>(py) {
            Ok(file_path) => {
                let full_path = file_path.to_string_lossy().to_string();
                let file = match File::open(&full_path) {
                    Ok(file) => file,
                    Err(e) => {
                        return Err(PyFileNotFoundError::new_err(format!(
                            "Unable to find the file '{}', Error: {}",
                            full_path, e
                        )))
                    }
                };
                Ok(Self {
                    parser: SDSParser::from_reader(file),
                })
            }
            Err(e) => Err(PyValueError::new_err(format!(
                "Please specifiy path argument as string, ERROR: {}",
                e
            ))),
        }
    }

    fn __iter__(slf: PyRefMut<Self>) -> PyResult<Py<PySDSParser>> {
        Ok(slf.into())
    }

    fn __next__(mut slf: PyRefMut<Self>) -> IterNextOutput<PySDSEntry, &'static str> {
        match slf.next() {
            Some(value) => match value {
                Ok(record) => IterNextOutput::Yield(PySDSEntry::new(false, Some(record))),
                Err(_) => IterNextOutput::Yield(PySDSEntry::new(true, None)),
            },
            None => IterNextOutput::Return("Ended"),
        }
    }

    fn dump(&mut self) -> PyResult<String> {
        let mut results = vec![];
        for record in &mut self.parser {
            results.push(record.unwrap());
        }

        Ok(serde_json::to_string(&results).unwrap())
    }
}

impl Iterator for PySDSParser {
    type Item = Result<SDSEntry, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.parser.next() {
            Some(record) => {
                Some(record.map_err(|_| {
                    Error::new(ErrorKind::InvalidData, format!("Error parsing record"))
                }))
            }
            None => None,
        }
    }
}

/// Security Descriptor Stream (SDS) entry struct.
#[pyclass]
pub struct PySDSEntry {
    #[pyo3(get)]
    is_error: bool,
    inner: Option<SDSEntry>,
}

impl PySDSEntry {
    fn new(is_error: bool, inner: Option<SDSEntry>) -> Self {
        Self { is_error, inner }
    }
}

#[pymethods]
impl PySDSEntry {
    pub fn get_hash(&self) -> PyResult<u32> {
        match &self.inner {
            Some(record) => Ok(record.hash),
            None => Err(PyValueError::new_err(
                "Unable to parser the record to retrive the hash",
            )),
        }
    }
    pub fn get_security_id(&self) -> PyResult<u32> {
        match &self.inner {
            Some(record) => Ok(record.id),
            None => Err(PyValueError::new_err(
                "Unable to parser the record to retrive the security_id",
            )),
        }
    }

    pub fn get_owner_sid(&self) -> PyResult<String> {
        match &self.inner {
            Some(record) => Ok(record.security_descriptor.owner_sid.to_string()),
            None => Err(PyValueError::new_err(
                "Unable to parser the record to retrive the owner_sid",
            )),
        }
    }

    pub fn get_group_sid(&self) -> PyResult<String> {
        match &self.inner {
            Some(record) => Ok(record.security_descriptor.group_sid.to_string()),
            None => Err(PyValueError::new_err(
                "Unable to parser the record to retrive the group_sid",
            )),
        }
    }

    pub fn get_dacl(&self) -> PyResult<Option<PyACL>> {
        match &self.inner {
            Some(record) => match &record.security_descriptor.dacl {
                Some(dacl) => Ok(PyACL::new(&dacl)),
                None => Ok(None),
            },
            None => Err(PyValueError::new_err(
                "Unable to parser the record to retrive the DACL",
            )),
        }
    }

    pub fn get_sacl(&self) -> PyResult<Option<PyACL>> {
        match &self.inner {
            Some(record) => match &record.security_descriptor.sacl {
                Some(sacl) => Ok(PyACL::new(&sacl)),
                None => Ok(None),
            },
            None => Err(PyValueError::new_err(
                "Unable to parser the record to retrive the SACL",
            )),
        }
    }

    pub fn to_json(&self) -> PyResult<String> {
        match &self.inner {
            Some(record) => match serde_json::to_string(&record) {
                Ok(json_data) => Ok(json_data),
                Err(e) => Err(PyValueError::new_err(format!(
                    "Unable to generate JSON data from record, ERROR: {}",
                    e
                ))),
            },
            None => Err(PyValueError::new_err(
                "Unable to generate JSON data from record",
            )),
        }
    }
}

#[pymodule]
fn ntfs_sds_parser(_: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PySDSParser>()?;
    Ok(())
}
