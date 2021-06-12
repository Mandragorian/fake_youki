use std::ffi::{CStr, CString};
use std::os::unix::io::RawFd;
use nix::unistd::Pid;

use nix::sched::CloneFlags;
use nix::sys::utsname::uname;

const SUITS: [&'static str; 4] = ["swords", "wands", "pentacles", "cups"];
const MINOR: [&'static str; 14] = [
    "ace", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "page",
    "knight", "queen", "king",
];
const MAJOR: [&'static str; 22] = [
    "fool",
    "magician",
    "high-priestess",
    "empress",
    "emperor",
    "hierophant",
    "lovers",
    "chariot",
    "strength",
    "hermit",
    "wheel",
    "justice",
    "hanged-man",
    "death",
    "temperance",
    "devil",
    "tower",
    "star",
    "moon",
    "sun",
    "judgment",
    "world",
];

const STACK_SIZE: usize = 1024 * 1024;

#[derive(Debug, PartialEq)]
pub struct ChildConfig {
    uid: u32,
    fd: i32,
    hostname: String,
    args: Vec<String>,
    mount_dir: String,
}

impl ChildConfig {
    pub fn new(uid: u32, args: Vec<String>, mount_dir: String) -> Self {
        Self {
            uid,
            fd: 0,
            hostname: String::from("(none)"),
            args,
            mount_dir,
        }
    }

    pub fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
    }

    pub fn hostname(&self) -> &String {
        &self.hostname
    }

    pub fn set_fd(&mut self, fd: i32) {
        self.fd = fd;
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }
}

fn check_linux_version() -> Result<(), &'static str> {
    let uts_name = uname();

    if !uts_name.release().starts_with("5.12") {
        return Err("Linux version is not 5.12");
    }

    if !(uts_name.machine() == "x86_64") {
        return Err("Unsupported architecture, expected x86_64");
    }

    Ok(())
}

fn choose_hostname() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    let major: usize = rng.gen_range(0..MAJOR.len());
    let minor: usize = rng.gen_range(0..MINOR.len());
    let suit: usize = rng.gen_range(0..SUITS.len());

    format!("{}-{}-{}", MAJOR[major], MINOR[minor], SUITS[suit])
}

fn get_initial_socket_pair() -> nix::Result<(RawFd, RawFd)> {
    use nix::sys::socket::AddressFamily;
    use nix::sys::socket::SockType;

    nix::sys::socket::socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::SOCK_CLOEXEC,
    )
}

struct Stack {
    internal_vec: Vec<u8>,
    size: usize,
}

impl Stack {
    pub fn new(size: usize) -> Self {
        let mut internal_vec = Vec::new();
        internal_vec.resize(size, 0);
        Self { internal_vec, size }
    }

    pub fn get_start(&mut self) -> &mut [u8] {
        //let ptr: *mut u8 = self.internal_vec.as_mut_ptr();

        // We support only x86_64, which means that stack grows downwards.
        // Thus the start of the stack is the _end_ of the buffer
        //dbg!(self.internal_vec.len(), self.size);
        //let start = unsafe { ptr.add(self.internal_vec.len()) };
        //unsafe { std::slice::from_raw_parts_mut(start, self.size) }
        self.internal_vec.as_mut_slice()
    }
}

pub fn get_clone_flags() -> nix::sched::CloneFlags {
    // New mount namespace
    CloneFlags::CLONE_NEWNS
        // New cgroup namespace
        | CloneFlags::CLONE_NEWCGROUP
        // New pid namespace
        | CloneFlags::CLONE_NEWPID
        // New ipc namespace
        | CloneFlags::CLONE_NEWIPC
        // New netowrking namespace
        | CloneFlags::CLONE_NEWNET
        // New hostname namespace
        | CloneFlags::CLONE_NEWUTS
        // New user namespace
        | CloneFlags::CLONE_NEWUSER
}

fn userns(config: &ChildConfig) -> Result<(), &'static str> {
    use nix::unistd::{Gid, Uid};

    eprint!("=> trying a user namespace...");
    let mut result = [0];

    // Wait until parent has mapped the user/group
    let read = nix::unistd::read(config.fd, &mut result).map_err(|_| "could not read")?;

    if read != result.len() || result[0] != 0 {
        return Err("could not read");
    }

    //let gid = Gid::from_raw(config.uid);
    //let uid = Uid::from_raw(config.uid);
    //nix::unistd::setgroups(&[gid])
    //    .and_then(|_| nix::unistd::setresgid(gid, gid, gid))
    //    .and_then(|_| nix::unistd::setresuid(uid, uid, uid))
    //    .map_err(|_| "could not set user/group")?;

    eprintln!("done.");
    Ok(())
}

fn child(config: &mut ChildConfig) -> isize {
    let res = nix::unistd::sethostname(&config.hostname)
        .map_err(|_| "could not set the hostname")
        .and_then(|_| userns(config));

    if res.is_err() {
        let s = res.unwrap_err();
        eprintln!("{}", s);
        nix::unistd::close(config.fd).unwrap();
        return -1;
    }


    if nix::unistd::close(config.fd).is_err() {
        println!("close failed");
        return -2;
    }

    let args: Vec<CString> = config
        .args
        .iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    if nix::unistd::execve(
        args[0].as_c_str(),
        args.as_slice(),
        &[CStr::from_bytes_with_nul(&[0]).unwrap()],
    )
    .is_err()
    {
        println!("execve failed");
        return -3;
    }

    return 0;
}

const USERNS_OFFSET: u32 = 1000;
const USERNS_COUNT: u32 = 1;

fn deny_setgroups(pid: Pid) -> Result<(), &'static str> {
    use std::fs::OpenOptions;
    use std::io::prelude::*;

    let path = format!("/proc/{}/setgroups", pid);
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| "could not open mapping file")?;

    file.write_all("deny".as_bytes())
        .map_err(|_| "could not deny setgroups")?;
    Ok(())
}

pub fn handle_child_uid_map(pid: Pid, fd: i32) -> Result<(), &'static str> {
    use std::fs::OpenOptions;
    use std::io::prelude::*;

    // In order to remap the group id we first must deny setgroups
    deny_setgroups(pid)?;

    let files = ["uid_map", "gid_map"];
    for file in files {
        let path = format!("/proc/{}/{}", pid, file);
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|_| "could not open mapping file")?;

        //XXX the user/group inside the namespace will be hardcoded 0 (root)
        //and the user/group outside the namespace will be hardcoded 1000
        //(regular user) for now.
        let mapping = format!("0 {} {}", USERNS_OFFSET, USERNS_COUNT);
        file.write_all(mapping.as_bytes())
            .map_err(|_| "could not write mapping")?;
    }

    // notify the child that we have remaped the user/group
    nix::unistd::write(fd, &[0])
        .map_err(|_| "could not write to child")?;
    Ok(())
}

pub fn run(mut config: ChildConfig) {
    // We want to check the linux version so that no extra isolation method
    // is added, which we do not handle. If something new is added and we
    // dont isolate it, we might leave some door open.
    match check_linux_version() {
        Err(msg) => {
            println!("{}", msg);
            return;
        }
        Ok(_) => (),
    }

    // Generate a random hostname for the container.
    config.set_hostname(choose_hostname());

    // For the container to be setup correclty, the parent and the child will
    // need to coordinate. We use a socket pair to do that.
    let (parent_fd, child_fd) = get_initial_socket_pair().expect("could not get socket pair");
    config.set_fd(child_fd);

    // Get the flags that will be passed in the clone syscall
    let clone_flags = get_clone_flags();

    //The new process will need its own stack to run.
    let mut stack = Stack::new(STACK_SIZE);
    let stack_start = stack.get_start();

    //Now we clone the parent
    let pid = nix::sched::clone(
        // This is the closure that the child will start executing.
        Box::new(|| child(&mut config)),
        // Since in x86_64 the stack grows downwards, we would need to pass
        // something like stack_start + stack_len. Howerver the nix wrapper
        // around the system call takes care of this for us. So we just pass
        // the reference to the buffer.
        stack_start,
        clone_flags,
        // We allow sending SIGCHILD to the newly created process
        Some(nix::sys::signal::SIGCHLD as i32),
    )
    .expect("could not spawn child");

    // If we don't close the child_fd in the parent, we might create a deadlock
    // Specifically, if there is some bug that causes the parent to hang, and
    // the child tries to read from the socket, the child will also hang.
    nix::unistd::close(child_fd).expect("couldn't close child fd");

    println!("before handle");
    handle_child_uid_map(pid, parent_fd).unwrap();

    println!("parent done");

    //let mut buffer = String::new();

    //use std::io::Read;
    //std::io::stdin().read_to_string(&mut buffer).unwrap();
}
