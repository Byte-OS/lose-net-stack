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

