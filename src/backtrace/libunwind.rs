//! Backtrace support using libunwind/gcc_s/etc APIs.
//!
//! This module contains the ability to unwind the stack using libunwind-style
//! APIs. Note that there's a whole bunch of implementations of the
//! libunwind-like API, and this is just trying to be compatible with most of
//! them all at once instead of being picky.
//!
//! The libunwind API is powered by `_Unwind_Backtrace` and is in practice very
//! reliable at generating a backtrace. It's not entirely clear how it does it
//! (frame pointers? eh_frame info? both?) but it seems to work!
//!
//! Most of the complexity of this module is handling the various platform
//! differences across libunwind implementations. Otherwise this is a pretty
//! straightforward Rust binding to the libunwind APIs.
//!
//! This is the default unwinding API for all non-Windows platforms currently.
#![allow(unused)]
use super::super::Bomb;
use core::ffi::c_void;
use addr2line::gimli::UnwindContext;

pub enum Frame {
    Raw(*mut uw::_Unwind_Context),
    Cloned {
        ip: *mut c_void,
        sp: *mut c_void,
        symbol_address: *mut c_void,
    },
}

// With a raw libunwind pointer it should only ever be access in a readonly
// threadsafe fashion, so it's `Sync`. When sending to other threads via `Clone`
// we always switch to a version which doesn't retain interior pointers, so we
// should be `Send` as well.
unsafe impl Send for Frame {}

unsafe impl Sync for Frame {}

impl Frame {
    pub fn ip(&self) -> *mut c_void {
        let ctx = match *self {
            Frame::Raw(ctx) => ctx,
            Frame::Cloned { ip, .. } => return ip,
        };
        unsafe { uw::_Unwind_GetIP(ctx) as *mut c_void }
    }

    pub fn sp(&self) -> *mut c_void {
        match *self {
            Frame::Raw(ctx) => unsafe { uw::get_sp(ctx) as *mut c_void },
            Frame::Cloned { sp, .. } => sp,
        }
    }

    pub fn symbol_address(&self) -> *mut c_void {
        if let Frame::Cloned { symbol_address, .. } = *self {
            return symbol_address;
        }

        // The macOS linker emits a "compact" unwind table that only includes an
        // entry for a function if that function either has an LSDA or its
        // encoding differs from that of the previous entry.  Consequently, on
        // macOS, `_Unwind_FindEnclosingFunction` is unreliable (it can return a
        // pointer to some totally unrelated function).  Instead, we just always
        // return the ip.
        //
        // https://github.com/rust-lang/rust/issues/74771#issuecomment-664056788
        //
        // Note the `skip_inner_frames.rs` test is skipped on macOS due to this
        // clause, and if this is fixed that test in theory can be run on macOS!
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            self.ip()
        } else {
            unsafe { uw::_Unwind_FindEnclosingFunction(self.ip()) }
        }
    }

    pub fn module_base_address(&self) -> Option<*mut c_void> {
        None
    }
}

impl Clone for Frame {
    fn clone(&self) -> Frame {
        Frame::Cloned {
            ip: self.ip(),
            sp: self.sp(),
            symbol_address: self.symbol_address(),
        }
    }
}

#[inline(always)]
pub unsafe fn trace(mut cb: &mut dyn FnMut(&super::Frame) -> bool) {
    uw::_Unwind_Backtrace(trace_fn, &mut cb as *mut _ as *mut _);
    extern "C" fn trace_fn(
        ctx: *mut uw::_Unwind_Context,
        arg: *mut c_void,
    ) -> uw::_Unwind_Reason_Code {
        let cb = unsafe { &mut *(arg as *mut &mut dyn FnMut(&super::Frame) -> bool) };
        let cx = super::Frame {
            inner: Frame::Raw(ctx),
        };

        let mut bomb = Bomb { enabled: true };
        let keep_going = cb(&cx);
        bomb.enabled = false;

        if keep_going {
            uw::_URC_NO_REASON
        } else {
            uw::_URC_FAILURE
        }
    }
}

#[cfg(any(feature = "llvm-unwind", feature = "nongnu-unwind"))]
#[inline(always)]
pub unsafe fn trace_external_api<F: FnMut(&super::Frame) -> bool>(mut f: F, signal_frame: bool) {
    use external_unwind::*;
    match UnwContext::new()
        .and_then(|mut x| { x.cursor(signal_frame) })
        .and_then(|mut x| {
            while let Ok(frame) = x.get_frame() {
                let frame = super::Frame {
                    inner: frame,
                };
                let mut bomb = Bomb { enabled: true };
                let keep_going = f(&frame);
                bomb.enabled = false;
                if !keep_going {
                    break;
                }
                match x.step() {
                    StepResult::Success => continue,
                    _ => break
                }
            }
            Ok(())
        }) {
        _ => ()
    }
}

/// Unwind library interface used for backtraces
///
/// Note that dead code is allowed as here are just bindings
/// iOS doesn't use all of them it but adding more
/// platform-specific configs pollutes the code too much
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
mod uw {
    pub use self::_Unwind_Reason_Code::*;

    use core::ffi::c_void;

    #[repr(C)]
    pub enum _Unwind_Reason_Code {
        _URC_NO_REASON = 0,
        _URC_FOREIGN_EXCEPTION_CAUGHT = 1,
        _URC_FATAL_PHASE2_ERROR = 2,
        _URC_FATAL_PHASE1_ERROR = 3,
        _URC_NORMAL_STOP = 4,
        _URC_END_OF_STACK = 5,
        _URC_HANDLER_FOUND = 6,
        _URC_INSTALL_CONTEXT = 7,
        _URC_CONTINUE_UNWIND = 8,
        _URC_FAILURE = 9, // used only by ARM EABI
    }

    pub enum _Unwind_Context {}

    pub type _Unwind_Trace_Fn =
    extern "C" fn(ctx: *mut _Unwind_Context, arg: *mut c_void) -> _Unwind_Reason_Code;

    extern "C" {
        pub fn _Unwind_Backtrace(
            trace: _Unwind_Trace_Fn,
            trace_argument: *mut c_void,
        ) -> _Unwind_Reason_Code;
    }

    cfg_if::cfg_if! {
        // available since GCC 4.2.0, should be fine for our purpose
        if #[cfg(all(
            not(all(target_os = "android", target_arch = "arm")),
            not(all(target_os = "freebsd", target_arch = "arm")),
            not(all(target_os = "linux", target_arch = "arm")),
            not(all(target_os = "horizon", target_arch = "arm"))
        ))] {
            extern "C" {
                pub fn _Unwind_GetIP(ctx: *mut _Unwind_Context) -> libc::uintptr_t;
                pub fn _Unwind_FindEnclosingFunction(pc: *mut c_void) -> *mut c_void;

                #[cfg(not(all(target_os = "linux", target_arch = "s390x")))]
                // This function is a misnomer: rather than getting this frame's
                // Canonical Frame Address (aka the caller frame's SP) it
                // returns this frame's SP.
                //
                // https://github.com/libunwind/libunwind/blob/d32956507cf29d9b1a98a8bce53c78623908f4fe/src/unwind/GetCFA.c#L28-L35
                #[link_name = "_Unwind_GetCFA"]
                pub fn get_sp(ctx: *mut _Unwind_Context) -> libc::uintptr_t;

            }

            // s390x uses a biased CFA value, therefore we need to use
            // _Unwind_GetGR to get the stack pointer register (%r15)
            // instead of relying on _Unwind_GetCFA.
            #[cfg(all(target_os = "linux", target_arch = "s390x"))]
            pub unsafe fn get_sp(ctx: *mut _Unwind_Context) -> libc::uintptr_t {
                extern "C" {
                    pub fn _Unwind_GetGR(ctx: *mut _Unwind_Context, index: libc::c_int) -> libc::uintptr_t;
                }
                _Unwind_GetGR(ctx, 15)
            }
        } else {
            // On android and arm, the function `_Unwind_GetIP` and a bunch of
            // others are macros, so we define functions containing the
            // expansion of the macros.
            //
            // TODO: link to the header file that defines these macros, if you
            // can find it. (I, fitzgen, cannot find the header file that some
            // of these macro expansions were originally borrowed from.)
            #[repr(C)]
            enum _Unwind_VRS_Result {
                _UVRSR_OK = 0,
                _UVRSR_NOT_IMPLEMENTED = 1,
                _UVRSR_FAILED = 2,
            }
            #[repr(C)]
            enum _Unwind_VRS_RegClass {
                _UVRSC_CORE = 0,
                _UVRSC_VFP = 1,
                _UVRSC_FPA = 2,
                _UVRSC_WMMXD = 3,
                _UVRSC_WMMXC = 4,
            }
            #[repr(C)]
            enum _Unwind_VRS_DataRepresentation {
                _UVRSD_UINT32 = 0,
                _UVRSD_VFPX = 1,
                _UVRSD_FPAX = 2,
                _UVRSD_UINT64 = 3,
                _UVRSD_FLOAT = 4,
                _UVRSD_DOUBLE = 5,
            }

            type _Unwind_Word = libc::c_uint;
            extern "C" {
                fn _Unwind_VRS_Get(
                    ctx: *mut _Unwind_Context,
                    klass: _Unwind_VRS_RegClass,
                    word: _Unwind_Word,
                    repr: _Unwind_VRS_DataRepresentation,
                    data: *mut c_void,
                ) -> _Unwind_VRS_Result;
            }

            pub unsafe fn _Unwind_GetIP(ctx: *mut _Unwind_Context) -> libc::uintptr_t {
                let mut val: _Unwind_Word = 0;
                let ptr = &mut val as *mut _Unwind_Word;
                let _ = _Unwind_VRS_Get(
                    ctx,
                    _Unwind_VRS_RegClass::_UVRSC_CORE,
                    15,
                    _Unwind_VRS_DataRepresentation::_UVRSD_UINT32,
                    ptr as *mut c_void,
                );
                (val & !1) as libc::uintptr_t
            }

            // R13 is the stack pointer on arm.
            const SP: _Unwind_Word = 13;

            pub unsafe fn get_sp(ctx: *mut _Unwind_Context) -> libc::uintptr_t {
                let mut val: _Unwind_Word = 0;
                let ptr = &mut val as *mut _Unwind_Word;
                let _ = _Unwind_VRS_Get(
                    ctx,
                    _Unwind_VRS_RegClass::_UVRSC_CORE,
                    SP,
                    _Unwind_VRS_DataRepresentation::_UVRSD_UINT32,
                    ptr as *mut c_void,
                );
                val as libc::uintptr_t
            }

            // This function also doesn't exist on Android or ARM/Linux, so make it
            // a no-op.
            pub unsafe fn _Unwind_FindEnclosingFunction(pc: *mut c_void) -> *mut c_void {
                pc
            }
        }
    }
}

#[cfg(any(feature = "llvm-unwind", feature = "nongnu-unwind"))]
mod external_unwind {
    use core::fmt::{Display, Formatter};
    use libc::{backtrace, c_void};

    #[derive(Debug)]
    pub struct UnwindError(libc::c_int);

    impl Display for UnwindError {
        fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
            write!(f, "unwind failed with code: {}", self.0)
        }
    }

    // the following length are defined enough for aarch64 and x86_64
    const UNW_TDEP_CURSOR_LEN: usize = 256;
    const LLVM_UNW_CONTEXT_SIZE: usize = 167;
    const LLVM_UNW_CURSOR_SIZE: usize = 179;
    #[allow(dead_code)]
    const UNW_INIT_SIGNAL_FRAME: libc::c_int = 1;

    // these two things can be quite large, but we need enough area to make sure the compatibility.
    #[repr(C)]
    pub union UnwContext {
        __ucontext: libc::ucontext_t,
        __mem_block: [usize; LLVM_UNW_CONTEXT_SIZE],
    }

    #[repr(C)]
    pub union UnwCursor {
        __llvm: [usize; LLVM_UNW_CURSOR_SIZE],
        __nongnu: [usize; UNW_TDEP_CURSOR_LEN],
    }

    #[repr(C)]
    pub struct UnwProcInfo {
        start_ip: *mut libc::c_void,
        // this is what we need
        __padding: [usize; 16], // enough space for padding
    }

    impl UnwProcInfo {
        fn new() -> Self {
            UnwProcInfo {
                start_ip: core::ptr::null_mut(),
                __padding: [0; 16],
            }
        }
    }

    #[derive(Debug)]
    pub enum StepResult {
        Error(libc::c_int),
        End,
        Success,
    }

    mod llvm {
        pub const UNW_REG_IP: libc::c_int = -1;
        pub const UNW_REG_SP: libc::c_int = -2;
    }

    mod nongnu_x86_64 {
        // RIP is the 17th register
        pub const UNW_REG_IP: libc::c_int = 16;
        // RSP is the 8th register
        pub const UNW_REG_SP: libc::c_int = 7;
    }

    mod nongnu_aarch64 {
        // aarch64 link register X30
        pub const UNW_REG_IP: libc::c_int = 30;
        // aarch64 stack pointer X31
        pub const UNW_REG_SP: libc::c_int = 31;
    }

    #[cfg(all(feature = "nongnu-unwind", target_arch = "aarch64"))]
    use nongnu_aarch64::*;

    #[cfg(all(feature = "nongnu-unwind", target_arch = "x86_64"))]
    use nongnu_x86_64::*;

    #[cfg(all(feature = "llvm-unwind"))]
    use llvm::*;

    #[cfg(target_arch = "x86_64")]
    extern "C" {
        #[cfg_attr(feature = "nongnu-unwind", link_name = "_Ux86_64_getcontext")]
        fn unw_getcontext(context: *mut UnwContext) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULx86_64_init_local")]
        fn unw_init_local(cursor: *mut UnwCursor, context: *mut UnwContext) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULx86_64_step")]
        fn unw_step(cursor: *mut UnwCursor) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULx86_64_get_reg")]
        fn unw_get_reg(cursor: *mut UnwCursor, num: libc::c_int, storage: *mut *mut c_void) -> libc::c_int;

        #[cfg(feature = "nongnu-unwind")]
        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULx86_64_init_local2")]
        fn unw_init_local2(cursor: *mut UnwCursor, context: *mut UnwContext, flag: libc::c_int) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULx86_64_get_proc_info")]
        fn unw_get_proc_info(cursor: *mut UnwCursor, context: *mut UnwProcInfo) -> libc::c_int;
    }

    #[cfg(target_arch = "aarch64")]
    extern "C" {
        #[cfg_attr(feature = "nongnu-unwind", link_name = "_Uaarch64_getcontext")]
        fn unw_getcontext(context: *mut UnwContext) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULaarch64_init_local")]
        fn unw_init_local(cursor: *mut UnwCursor, context: *mut UnwContext) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULaarch64_step")]
        fn unw_step(cursor: *mut UnwCursor) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULaarch64_get_reg")]
        fn unw_get_reg(cursor: *mut UnwCursor, num: libc::c_int, storage: *mut *mut c_void) -> libc::c_int;

        #[cfg(feature = "nongnu-unwind")]
        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULaarch64_init_local2")]
        fn unw_init_local2(cursor: *mut UnwCursor, context: *mut UnwContext, flag: libc::c_int) -> libc::c_int;

        #[cfg_attr(feature = "nongnu-unwind", link_name = "_ULaarch64_get_proc_info")]
        fn unw_get_proc_info(cursor: *mut UnwCursor, context: *mut UnwProcInfo) -> libc::c_int;
    }

    impl UnwContext {
        pub(crate) fn new() -> Result<Self, UnwindError> {
            let mut context = UnwContext { __mem_block: [0; LLVM_UNW_CONTEXT_SIZE] };
            unsafe {
                if unw_getcontext(&mut context as *mut _) == 0 {
                    Ok(context)
                } else {
                    Err(UnwindError(-1))
                }
            }
        }

        #[allow(unused_variables)]
        pub(crate) fn cursor(&mut self, signal_frame: bool) -> Result<UnwCursor, UnwindError> {
            let mut cursor = UnwCursor { __nongnu: [0; UNW_TDEP_CURSOR_LEN] };
            unsafe {
                #[cfg(feature = "nongnu-unwind")]
                    let res = unw_init_local2(&mut cursor as _, self as _,
                                              if signal_frame { UNW_INIT_SIGNAL_FRAME } else { 0 });

                #[cfg(feature = "llvm-unwind")]
                    let res = unw_init_local(&mut cursor as _, self as _);

                if res == 0 {
                    Ok(cursor)
                } else {
                    Err(UnwindError(res))
                }
            }
        }
    }

    impl UnwCursor {
        pub(crate) fn step(&mut self) -> StepResult {
            unsafe {
                let res = unw_step(self as _);
                if res > 0 {
                    StepResult::Success
                } else if res == 0 {
                    StepResult::End
                } else {
                    StepResult::Error(res)
                }
            }
        }
        pub(crate) fn get_frame(&mut self) -> Result<super::Frame, UnwindError> {
            let mut proc_info = UnwProcInfo::new();
            let mut ip: *mut c_void = core::ptr::null_mut();
            let mut sp: *mut c_void = core::ptr::null_mut();
            unsafe {
                let mut res = unw_get_proc_info(self as _, &mut proc_info as _);
                if res != 0 {
                    return Err(UnwindError(res));
                }
                res = unw_get_reg(self as _, UNW_REG_IP, &mut ip as _);
                if res != 0 {
                    return Err(UnwindError(res));
                }
                res = unw_get_reg(self as _, UNW_REG_SP, &mut sp as _);
                if res != 0 {
                    return Err(UnwindError(res));
                }
            }
            Ok(super::Frame::Cloned {
                ip,
                sp,
                symbol_address: proc_info.start_ip,
            })
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn unw_context_initialization() {
            assert!(UnwContext::new().is_ok())
        }

        #[test]
        fn unw_get_cursor() {
            assert!(UnwContext::new().and_then(|mut x| x.cursor(false)).is_ok())
        }

        #[test]
        fn unw_get_frame() {
            let frame =
                UnwContext::new()
                    .and_then(|mut x| x.cursor(false))
                    .and_then(|mut x| x.get_frame());
            assert!(frame.is_ok());
        }
    }
}
