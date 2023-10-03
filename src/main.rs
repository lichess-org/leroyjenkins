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

    let mut stdin = io::stdin().lock();
    let mut line = Vec::with_capacity(40);
    while stdin.read_until(b'\n', &mut line)? != 0 {
        if line[line.len() - 1] == b'\n' {
            line.pop();
        }
        leroy.handle_line(&line);
        line.clear();
    }

    Ok(())
}
