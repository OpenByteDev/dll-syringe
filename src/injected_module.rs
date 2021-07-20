use std::error::Error;

use crate::{Module, Process, Syringe};

pub struct InjectedModule<'a> {
    pub(crate) module: Module,
    pub(crate) process: &'a Process,
    pub(crate) syringe: &'a Syringe,
}

impl<'a> InjectedModule<'a> {
    pub fn eject(self) -> Result<(), (Box<dyn Error>, Self)> {
        match self.syringe.eject(self.process, self.module) {
            Ok(_) => Ok(()),
            Err(err) => Err((err, self)),
        }
    }
}

impl From<InjectedModule<'_>> for Module {
    fn from(injected: InjectedModule) -> Self {
        injected.module
    }
}
