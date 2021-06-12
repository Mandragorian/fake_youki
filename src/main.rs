use clap::{App, Arg};

use fake_youki::{ChildConfig, run};

fn main() {
    let matches = App::new("My Super Program")
        .version("1.0")
        .author("Kevin K. <kbknapp@gmail.com>")
        .about("Does awesome things")
        .arg(
            Arg::with_name("command")
                .short("-c")
                .value_name("COMMAND")
                .help("The command to run")
                .required(true)
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("user")
                .short("u")
                .value_name("UID")
                .help("The user id")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mount_dir")
                .short("m")
                .value_name("MOUNTDIR")
                .help("The directory to mount")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let mount_dir = matches.value_of("mount_dir").unwrap();
    let command: Vec<String> = matches.values_of("command").unwrap().map(|s| s.into()).collect();
    let user: u32 = matches.value_of("user").unwrap().parse().unwrap();

    let config = ChildConfig::new(user, command, mount_dir.into());

    run(config);
}
