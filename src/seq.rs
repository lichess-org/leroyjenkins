use std::num::{NonZeroU32, Wrapping};

pub struct SeqGenerator {
    state: Wrapping<u32>,
}

impl SeqGenerator {
    pub fn new() -> Self {
        SeqGenerator { state: Wrapping(0) }
    }

    #[must_use]
    pub fn inc(&mut self) -> Seq {
        self.state += 1;
        if let Some(seq) = NonZeroU32::new(self.state.0) {
            Seq(seq)
        } else {
            self.state += 1;
            Seq(NonZeroU32::new(self.state.0).expect("non-zero sequence number"))
        }
    }
}

#[derive(Copy, Clone)]
pub struct Seq(pub NonZeroU32);

impl From<Seq> for u32 {
    fn from(seq: Seq) -> Self {
        seq.0.get()
    }
}
