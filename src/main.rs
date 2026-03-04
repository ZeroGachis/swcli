mod aws;
mod cli;

fn main() {
    env_logger::init();
    let _ = cli::execute().inspect_err(|e| {
        log::error!("{e:?}");
        std::process::exit(1);
    });
}
