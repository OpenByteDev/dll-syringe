use std::fmt::{Debug, Display};

use crate::{error::InjectError, Process, ProcessModule, Syringe};

pub struct InjectedModule<'a> {
    pub(crate) module: ProcessModule<'a>,
    pub(crate) syringe: &'a Syringe,
}

impl<'a> InjectedModule<'a> {
    pub fn target_process(&self) -> &'a Process {
        self.module.process().unwrap()
    }

    pub fn payload(&self) -> &ProcessModule<'a> {
        &self.module
    }

    pub fn eject(self) -> Result<(), InjectError> {
        self.syringe.eject(self)
    }
}

impl Display for InjectedModule<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.payload().fmt(f)
    }
}

impl PartialEq for InjectedModule<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.payload().eq(other.payload())
    }
}

impl<'a> From<InjectedModule<'a>> for ProcessModule<'a> {
    fn from(module: InjectedModule<'a>) -> Self {
        module.module
    }
}
