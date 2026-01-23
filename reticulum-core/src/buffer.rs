use core::cmp::min;
use core::fmt;

use crate::error::RnsError;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct StaticBuffer<const N: usize> {
    buffer: [u8; N],
    len: usize,
}

impl<const N: usize> StaticBuffer<N> {
    pub const fn new() -> Self {
        Self {
            buffer: [0u8; N],
            len: 0,
        }
    }

    pub fn new_from_slice(data: &[u8]) -> Self {
        let mut buffer = Self::new();

        buffer.safe_write(data);

        buffer
    }

    pub fn reset(&mut self) {
        self.len = 0;
    }

    pub fn resize(&mut self, len: usize) {
        self.len = min(len, self.buffer.len());
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn chain_write(&mut self, data: &[u8]) -> Result<&mut Self, RnsError> {
        self.write(data)?;
        Ok(self)
    }

    pub fn finalize(self) -> Self {
        self
    }

    pub fn safe_write(&mut self, data: &[u8]) -> usize {
        let data_size = data.len();

        let max_size = core::cmp::min(data_size, N - self.len);

        self.write(&data[..max_size]).unwrap_or(0)
    }

    pub fn chain_safe_write(&mut self, data: &[u8]) -> &mut Self {
        self.safe_write(data);
        self
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, RnsError> {
        let data_size = data.len();

        // Nothing to write
        if data_size == 0 {
            return Ok(0);
        }

        if (self.len + data_size) > N {
            return Err(RnsError::OutOfMemory);
        }

        self.buffer[self.len..(self.len + data_size)].copy_from_slice(data);
        self.len += data_size;

        Ok(data_size)
    }

    pub fn rotate_left(&mut self, mid: usize) -> Result<usize, RnsError> {
        if mid > self.len {
            return Err(RnsError::InvalidArgument);
        }

        self.len = self.len - mid;

        self.buffer.rotate_left(mid);

        Ok(self.len)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.len]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.len]
    }

    pub fn accuire_buf(&mut self, len: usize) -> &mut [u8] {
        self.len = len;
        &mut self.buffer[..self.len]
    }

    pub fn accuire_buf_max(&mut self) -> &mut [u8] {
        self.len = self.buffer.len();
        &mut self.buffer[..self.len]
    }
}

impl<const N: usize> Default for StaticBuffer<N> {
    fn default() -> Self {
        Self {
            buffer: [0u8; N],
            len: 0,
        }
    }
}

pub struct OutputBuffer<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> OutputBuffer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, RnsError> {
        let data_size = data.len();

        // Nothing to write
        if data_size == 0 {
            return Ok(0);
        }

        if (self.offset + data_size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        self.buffer[self.offset..(self.offset + data_size)].copy_from_slice(data);
        self.offset += data_size;

        Ok(data_size)
    }

    pub fn write_byte(&mut self, byte: u8) -> Result<usize, RnsError> {
        self.write(&[byte])
    }

    pub fn reset(&mut self) {
        self.offset = 0;
    }

    pub fn is_full(&self) -> bool {
        self.offset == self.buffer.len()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[..self.offset]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.offset]
    }
}

impl<'a> fmt::Display for OutputBuffer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ 0x")?;

        for i in 0..self.offset {
            write!(f, "{:0>2x}", self.buffer[i])?;
        }

        write!(f, " ]",)
    }
}

impl<const N: usize> fmt::Display for StaticBuffer<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ 0x")?;

        for i in 0..self.len {
            write!(f, "{:0>2x}", self.buffer[i])?;
        }

        write!(f, " ]",)
    }
}

pub struct InputBuffer<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> InputBuffer<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { offset: 0, buffer }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, RnsError> {
        let size = buf.len();
        if (self.offset + size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        buf.copy_from_slice(&self.buffer[self.offset..(self.offset + size)]);
        self.offset += size;

        Ok(size)
    }

    pub fn read_size(&mut self, buf: &mut [u8], size: usize) -> Result<usize, RnsError> {
        if (self.offset + size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        if buf.len() < size {
            return Err(RnsError::OutOfMemory);
        }

        buf[..size].copy_from_slice(&self.buffer[self.offset..(self.offset + size)]);
        self.offset += size;

        Ok(size)
    }

    pub fn read_byte(&mut self) -> Result<u8, RnsError> {
        let mut buf = [0u8; 1];
        self.read(&mut buf)?;

        Ok(buf[0])
    }

    pub fn read_slice(&mut self, size: usize) -> Result<&[u8], RnsError> {
        if (self.offset + size) > self.buffer.len() {
            return Err(RnsError::OutOfMemory);
        }

        let slice = &self.buffer[self.offset..self.offset + size];

        self.offset += size;

        Ok(slice)
    }

    pub fn bytes_left(&self) -> usize {
        self.buffer.len() - self.offset
    }
}
