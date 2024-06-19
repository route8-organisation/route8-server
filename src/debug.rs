
pub static mut STREAM_OUTPUT: Option<std::fs::File> = None;
pub static mut STREAM_ACCESS: Option<std::fs::File> = None;

const LOG_OUTPUT_FILENAME: &str = "debug.log";
const LOG_ACCESS_FILENAME: &str = "access.log";

#[macro_export]
macro_rules! outputln {
    ($module:expr, $fmt:expr $(, $args:expr)*) => {
        {
            use std::io::Write;
            use crate::debug::STREAM_OUTPUT;

            let mut stream = unsafe {
                STREAM_OUTPUT.as_ref().expect("debug is not initialiazed")
            };

            let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
            let time_friendly = now.format("%Y-%m-%d %H:%M:%S").to_string();
            let milliseconds = now.timestamp_subsec_millis();
        
            let _ = write!(stream, "[{}.{:03}][*][{}] ", time_friendly, milliseconds, $module);
            let _ = write!(stream, $fmt $(, $args)*);
            let _ = write!(stream, "\n");
        
            let mut stdout = std::io::stdout();
            let _ = write!(stdout, "[{}.{:03}][*][{}] ", time_friendly, milliseconds, $module);
            let _ = write!(stdout, $fmt $(, $args)*);
            let _ = write!(stdout, "\n");
        }
    };
}

#[macro_export]
macro_rules! errorln {
    ($module:expr, $fmt:expr $(, $args:expr)*) => {
        {
            use std::io::Write;
            use crate::debug::STREAM_OUTPUT;

            let mut stream = unsafe {
                STREAM_OUTPUT.as_ref().expect("debug is not initialiazed")
            };

            let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
            let time_friendly = now.format("%Y-%m-%d %H:%M:%S").to_string();
            let milliseconds = now.timestamp_subsec_millis();
        
            let _ = write!(stream, "[{}.{:03}][-][{}] ", time_friendly, milliseconds, $module);
            let _ = write!(stream, $fmt $(, $args)*);
            let _ = write!(stream, "\n");
        
            let mut stdout = std::io::stdout();
            let _ = write!(stdout, "[{}.{:03}][-][{}] ", time_friendly, milliseconds, $module);
            let _ = write!(stdout, $fmt $(, $args)*);
            let _ = write!(stdout, "\n");
        }
    };
}

#[macro_export]
macro_rules! accessln {
    ($module:expr, $fmt:expr $(, $args:expr)*) => {
        {
            use std::io::Write;
            use crate::debug::STREAM_ACCESS;

            let mut stream = unsafe {
                STREAM_ACCESS.as_ref().expect("debug is not initialiazed")
            };

            let now: chrono::DateTime<chrono::Local> = chrono::Local::now();
            let time_friendly = now.format("%Y-%m-%d %H:%M:%S").to_string();
            let milliseconds = now.timestamp_subsec_millis();
        
            let _ = write!(stream, "[{}.{:03}][{}] ", time_friendly, milliseconds, $module);
            let _ = write!(stream, $fmt $(, $args)*);
            let _ = write!(stream, "\n");
        
            let mut stdout = std::io::stdout();
            let _ = write!(stdout, "[{}.{:03}][{}] ", time_friendly, milliseconds, $module);
            let _ = write!(stdout, $fmt $(, $args)*);
            let _ = write!(stdout, "\n");
        }
    };
}

pub fn initialize() -> anyhow::Result<()> {
    let stream = std::fs::OpenOptions::new()
        .read(false)
        .append(true)
        .create(true)
        .open(LOG_OUTPUT_FILENAME)?;

    unsafe {
        STREAM_OUTPUT = Some(stream);
    }

    let stream = std::fs::OpenOptions::new()
        .read(false)
        .append(true)
        .create(true)
        .open(LOG_ACCESS_FILENAME)?;

    unsafe {
        STREAM_ACCESS = Some(stream);
    }

    Ok(())
}
