use core::{mem::size_of, slice};

pub(crate) struct UnsafeRefIter {
    ptr: usize,
    end: usize
}

#[allow(dead_code)]
impl UnsafeRefIter {
    pub fn new(data: &[u8]) -> Self {
        Self { 
            ptr: data.as_ptr() as usize, 
            end: data.as_ptr() as usize + data.len()
        }
    }

    /// get a ref from the current ptr position
    pub unsafe fn next<T>(&mut self) -> Option<&'static T> {
        if self.ptr + size_of::<T>() <= self.end {
            let v = self.ptr as *const T;
            self.ptr += size_of::<T>();
            v.as_ref()
        } else {
            None
        }
    }

    /// get a mutable ref from the current ptr position
    pub unsafe fn next_mut<T>(&mut self) -> Option<&'static mut T> {
        if self.ptr + size_of::<T>() <= self.end {
            let v = self.ptr as *mut T;
            self.ptr += size_of::<T>();
            v.as_mut()
        } else {
            None
        }
    }

    /// get the ref array the current pointer point to.
    pub unsafe fn get_curr_arr(&self) -> &'static [u8]{
        slice::from_raw_parts(self.ptr as _, self.end - self.ptr)
    }

    /// get the mut ref array the current pointer point to.
    pub unsafe fn get_curr_arr_mut(&self) -> &'static mut [u8]{
        slice::from_raw_parts_mut(self.ptr as _, self.end - self.ptr)
    }
}

// copy from xv6-rust
pub fn check_sum(addr:*mut u8, len:u32) -> u16 {
    let mut sum:u32 = 0;
    let mut nleft = len;
    let mut w = addr as *const u16;
    
     // Our algorithm is simple, using a 32 bit accmulator (sum), we add
     // sequential 16 bit words to it, and at the end, fold back all the 
     // carry bits from the top 16 bits into the lower 16 bits. 
     while nleft > 0 {
        sum += unsafe{ *w as u32 };
        w = (w as usize + 2) as *mut u16;
        nleft -= 2;
     }

     // mop up an odd byte, if necessary
     // emmm, I think it is unnecessary

     // add back carry outs from top 16 bits to low bits
     sum = (sum & 0xFFFF) + (sum >> 16);
     sum = sum + (sum >> 16);
     // guaranted now that lower 16 bits of sum are correct

     let answer:u16 = !sum as u16;

     answer
}