/// A little trait to support a limited form of 'mut polymorphism'

pub trait FromMut<'a, T: ?Sized> {
    fn from_mut(x: &'a mut T) -> Self;
}

impl<'a, T: ?Sized> FromMut<'a, T> for &'a T {
    fn from_mut(x: &'a mut T) -> Self {
        x
    }
}

impl<'a, T: ?Sized> FromMut<'a, T> for &'a mut T {
    fn from_mut(x: &'a mut T) -> Self {
        x
    }
}
