use std::error::Error;

use crate::{Process, ProcessModule, Syringe};

// TODO:
pub struct InjectedModule<'a> {
    pub(crate) module: ProcessModule<'a>,
    pub(crate) process: &'a Process,
    pub(crate) syringe: &'a Syringe,
}

impl<'a> InjectedModule<'a> {
    pub fn eject(self) -> Result<(), Box<dyn Error>> {
        self.syringe.eject(self.process, self.module)
    }
}
