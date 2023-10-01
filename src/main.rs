use std::{error::Error, io, io::BufRead};

use clap::Parser;
use leroyjenkins::{Args, Leroy};
use log::info;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();

    let args = Args::parse();
    info!(
        "🔨🪓🪖🥚LEEEEEEEERRRRRROOOOOYYYYYYYYYY JJEEEEEENNNNNNNKKKKKKKIIIIIIINNNNNSSSSSSS🥚🪖🪓🔨"
    );
    info!("{:?}", args);

    let mut leroy = Leroy::new(args)?;
    for line in io::stdin().lock().split(b'\n') {
        leroy.handle_line(line?);
    }
    Ok(())
}
