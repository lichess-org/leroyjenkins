use std::{error::Error, io};

use clap::Parser;
use leroyjenkins::{Args, Leroy};
use log::info;

fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();

    let args = Args::parse();
    info!(
        "🔨🪓🪖🥚LEEEEEEEERRRRRROOOOOYYYYYYYYYY JJEEEEEENNNNNNNKKKKKKKIIIIIIINNNNNSSSSSSS🥚🪖🪓🔨"
    );
    info!("{:?}", args);

    Leroy::new(args)?.handle_lines(io::stdin().lock())?;
    Ok(())
}
