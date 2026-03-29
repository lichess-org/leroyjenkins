use std::num::{NonZeroU32, Wrapping};

#[derive(Default)]
pub struct SeqGenerator {
    state: Wrapping<u32>,
}

impl SeqGenerator {
    pub fn new() -> Self {
        SeqGenerator { state: Wrapping(1) }
    }

    #[must_use]
    pub fn inc(&mut self) -> Seq {
        let seq = self.state;
        self.state += 1;
        Seq(NonZeroU32::new(seq.0)
            .or_else(|| NonZeroU32::new(0x1234_5678))
            .expect("non-zero sequence number"))
    }
}

#[derive(Copy, Clone)]
pub struct Seq(pub NonZeroU32);

impl From<Seq> for u32 {
    fn from(seq: Seq) -> Self {
        seq.0.get()
    }
}
