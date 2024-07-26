#[derive(Debug, Clone)]
pub struct OwnedSlice<T>(pub(super) T, pub(super) std::ops::Range<usize>);

impl<Inner: 'static + ?Sized + AsRef<[u8]>, T: Deref<Target = Inner>> Deref for OwnedSlice<T> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0.as_ref()[self.1.clone()]
    }
}

impl<Inner: 'static + ?Sized + AsRef<[u8]>, T: Deref<Target = Inner>> AsRef<[u8]>
    for OwnedSlice<T>
{
    fn as_ref(&self) -> &[u8] {
        self
    }
}

// this function feels strange, but it is completely safe Rust
// requirement for not panicking: "y" is a slice from "x"
pub fn to_range(x: std::ops::Range<*const u8>, y: &[u8]) -> std::ops::Range<usize> {
    let (x_begin, x_end) = (x.start as usize, x.end as usize);
    let y_begin = y.as_ptr() as usize;
    if y_begin < x_begin || y_begin + y.len() > x_end {
        panic!("attempt to obtain the range of an improper subslice")
    }
    let offset = y_begin - x_begin;

    offset..offset + y.len()
}

use std::ops::Deref;

// allow for two layers of dereferencing
impl<Inner: 'static + ?Sized + AsRef<[u8]>, T: Deref<Target = Inner>, B: AsRef<[u8]>> PartialEq<B>
    for OwnedSlice<T>
{
    fn eq(&self, other: &B) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl<Inner: 'static + ?Sized + AsRef<[u8]>, T: Deref<Target = Inner>> PartialEq<OwnedSlice<T>>
    for &[u8]
{
    fn eq(&self, other: &OwnedSlice<T>) -> bool {
        self == &other.as_ref()
    }
}
