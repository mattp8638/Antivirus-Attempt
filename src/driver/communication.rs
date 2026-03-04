//! User-Kernel Communication
//!
//! IOCTL-based communication channel between user-mode agent and kernel driver
//! Uses DeviceIoControl for bidirectional messaging

use super::*;
use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::*;

/// Device name for kernel driver
const DEVICE_NAME: &str = "\\\\.\\TamsilCMSDriver";

/// IOCTL control codes
pub struct IOCTLCodes;

impl IOCTLCodes {
    pub const GET_EVENT: u32 = 0x80002000;
    pub const SET_POLICY: u32 = 0x80002004;
    pub const GET_STATISTICS: u32 = 0x80002008;
    pub const BLOCK_PROCESS: u32 = 0x8000200C;
    pub const UNBLOCK_PROCESS: u32 = 0x80002010;
}

/// User-kernel communication channel
pub struct DriverCommunication {
    device_handle: Option<HANDLE>,
}

impl DriverCommunication {
    pub fn new() -> Self {
        Self {
            device_handle: None,
        }
    }

    /// Connect to kernel driver
    pub fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        unsafe {
            let wide_name: Vec<u16> = DEVICE_NAME
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let handle = CreateFileW(
                windows::core::PCWSTR(wide_name.as_ptr()),
                FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )?;

            if handle == INVALID_HANDLE_VALUE {
                return Err("Failed to open driver device".into());
            }

            self.device_handle = Some(handle);
            tracing::info!("Connected to kernel driver: {}", DEVICE_NAME);
            Ok(())
        }
    }

    /// Send IOCTL to driver
    pub fn send_ioctl(
        &self,
        control_code: u32,
        input_buffer: &[u8],
        output_buffer: &mut [u8],
    ) -> Result<u32, Box<dyn std::error::Error>> {
        unsafe {
            let handle = self.device_handle
                .ok_or("Not connected to driver")?;

            let mut bytes_returned = 0u32;

            if let Err(err) = DeviceIoControl(
                handle,
                control_code,
                Some(input_buffer.as_ptr() as *const _),
                input_buffer.len() as u32,
                Some(output_buffer.as_mut_ptr() as *mut _),
                output_buffer.len() as u32,
                Some(&mut bytes_returned),
                None,
            ) {
                return Err(format!("DeviceIoControl failed: 0x{:X}", err.code().0 as u32).into());
            }

            Ok(bytes_returned)
        }
    }

    /// Get event from driver queue
    pub fn get_event(&self) -> Result<Option<DriverEvent>, Box<dyn std::error::Error>> {
        let mut output_buffer = vec![0u8; 4096];
        let bytes = self.send_ioctl(IOCTLCodes::GET_EVENT, &[], &mut output_buffer)?;

        if bytes == 0 {
            return Ok(None);
        }

        // Deserialize event (simplified)
        Ok(None)
    }

    /// Block process by PID
    pub fn block_process(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let input = pid.to_le_bytes();
        let mut output = [0u8; 4];
        self.send_ioctl(IOCTLCodes::BLOCK_PROCESS, &input, &mut output)?;
        
        tracing::info!("Blocked process: PID {}", pid);
        Ok(())
    }

    /// Disconnect from driver
    pub fn disconnect(&mut self) {
        if let Some(handle) = self.device_handle.take() {
            unsafe {
                let _ = CloseHandle(handle);
            }
            tracing::info!("Disconnected from kernel driver");
        }
    }
}

impl Drop for DriverCommunication {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Event pump for continuous driver monitoring
pub struct DriverEventPump {
    communication: DriverCommunication,
}

impl DriverEventPump {
    pub fn new() -> Self {
        Self {
            communication: DriverCommunication::new(),
        }
    }

    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.communication.connect()?;
        Ok(())
    }

    /// Poll driver for events
    pub async fn poll_events<F>(&self, mut callback: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: FnMut(DriverEvent),
    {
        loop {
            if let Some(event) = self.communication.get_event()? {
                callback(event);
            }
            
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }
}
