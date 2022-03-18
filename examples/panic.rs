use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, SIGPROF};
use rand::Rng;

extern "C" {
    fn setitimer(sig: libc::c_int, val: *const libc::itimerval, old: *mut libc::itimerval) -> libc::c_int;
}

fn main() {
    // Register perf signal handler.
    let h = SigHandler::SigAction(perf_signal_handler);
    let a = SigAction::new(h, SaFlags::SA_SIGINFO, SigSet::empty());
    unsafe {
        sigaction(SIGPROF, &a).unwrap();
    }

    // Register SIGPROF that will be triggered periodically.
    unsafe {
        setitimer(libc::ITIMER_PROF, &frequency(99), std::ptr::null_mut());
    }

    // Run some workloads.
    loop {
        let mut rng = rand::thread_rng();
        let mut vec: Vec<i32> = vec![];
        for _ in 0..1000000 {
            vec.push(rng.gen())
        }
        vec.sort();
    }
}

fn frequency(v: i64) -> libc::itimerval {
    let interval = 1e6 as i64 / v;
    let it_interval = libc::timeval {
        tv_sec: interval / 1e6 as i64,
        tv_usec: (interval % 1e6 as i64) as _,
    };
    let it_value = it_interval.clone();
    libc::itimerval { it_interval, it_value }
}

#[no_mangle]
pub extern "C" fn perf_signal_handler(_: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    unsafe {
        backtrace::trace_unsynchronized(|_| {
            //
            true
        });
    }
}